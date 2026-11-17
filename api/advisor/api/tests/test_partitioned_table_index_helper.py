"""PostgreSQL integration tests for committed index drops and lock failures."""

from contextlib import contextmanager
from unittest.mock import patch
import uuid

from django.db import DatabaseError, OperationalError, ProgrammingError, connection, transaction
from django.test import TransactionTestCase
from psycopg2 import sql

from api.scripts import partitioned_table_index_helper as helper


class PartitionedTableIndexHelperTestCase(TransactionTestCase):
    available_apps = []

    def setUp(self):
        super().setUp()
        self.schema = f'index_helper_{uuid.uuid4().hex[:12]}'
        self.table = 'hosts'
        self.index = 'idx_staleness'
        self._execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(self.schema)))
        self._execute(sql.SQL('''
            CREATE TABLE {} (
                org_id integer NOT NULL, inventory_id integer NOT NULL,
                data jsonb NOT NULL, PRIMARY KEY (org_id, inventory_id)
            ) PARTITION BY HASH (org_id)
        ''').format(self._relation(self.table)))
        for part in range(2):
            self._execute(sql.SQL('''
                CREATE TABLE {} PARTITION OF {}
                FOR VALUES WITH (MODULUS 2, REMAINDER {})
            ''').format(
                self._relation(f'{self.table}_p{part}'),
                self._relation(self.table), sql.Literal(part),
            ))
        self._execute(sql.SQL('''
            INSERT INTO {} SELECT n % 2, n, jsonb_build_object('reporter', n)
            FROM generate_series(1, 10) n
        ''').format(self._relation(self.table)))

    def tearDown(self):
        self._execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(self.schema)))
        super().tearDown()

    def _relation(self, name):
        return sql.Identifier(self.schema, name)

    def _execute(self, statement, params=None):
        connection.ensure_connection()
        if isinstance(statement, sql.Composable):
            statement = statement.as_string(connection.connection)
        with connection.cursor() as cursor:
            cursor.execute(statement, params)
            return cursor.fetchall() if cursor.description else None

    def _exists(self, name):
        return self._execute(
            'SELECT to_regclass(%s) IS NOT NULL',
            [self._relation(name).as_string(connection.connection)],
        )[0][0]

    def _timeouts(self):
        return self._execute(
            "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')"
        )[0]

    def _create(self):
        helper.create_partitioned_table_index(
            self.table, self.index, 'USING GIN (data jsonb_path_ops)',
            num_partitions=2, schema=self.schema, migration_mode='automated',
        )

    def _drop(self, **kwargs):
        options = dict(num_partitions=2, schema=self.schema, max_attempts=1)
        options.update(kwargs)
        helper.drop_partitioned_table_index(self.table, self.index, **options)

    def _orphan(self, part=0):
        name = f'{self.table}_p{part}_{self.index}'
        self._execute(sql.SQL('CREATE INDEX {} ON {} USING GIN (data jsonb_path_ops)').format(
            sql.Identifier(name), self._relation(f'{self.table}_p{part}'),
        ))
        return name

    @contextmanager
    def _hold(self, table):
        blocker = connection.Database.connect(**connection.get_connection_params())
        try:
            with blocker.cursor() as cursor:
                cursor.execute('SET LOCAL lock_timeout = %s', ['100ms'])
                cursor.execute(sql.SQL('LOCK TABLE ONLY {} IN ACCESS SHARE MODE').format(
                    self._relation(table),
                ))
            yield blocker
        finally:
            blocker.rollback()
            blocker.close()

    def test_drop_preserves_rows_and_other_indexes_and_restores_timeouts(self):
        self._create()
        original = self._timeouts()
        self._drop()
        self.assertFalse(self._exists(self.index))
        self.assertTrue(self._exists(f'{self.table}_p0_pkey'))
        self.assertEqual(self._execute(sql.SQL('SELECT count(*) FROM {}').format(
            self._relation(self.table),
        ))[0][0], 10)
        self.assertEqual(self._timeouts(), original)

    def test_missing_index_does_not_lock_busy_table(self):
        with self._hold(self.table):
            self._drop()

    def test_if_exists_false_succeeds_then_raises_when_parent_is_missing(self):
        self._create()
        self._drop(if_exists=False)
        with self.assertRaises(ProgrammingError) as raised:
            self._drop(if_exists=False)
        self.assertEqual(raised.exception.__cause__.pgcode, '42704')

    def test_busy_parent_and_leaf_fail_and_restore_timeouts(self):
        self._create()
        original = self._timeouts()
        for table in [self.table, f'{self.table}_p1']:
            with self.subTest(table=table), self._hold(table):
                with self.assertRaises(OperationalError) as raised:
                    self._drop()
                self.assertEqual(raised.exception.__cause__.pgcode, '55P03')
                self.assertTrue(self._exists(self.index))
                self.assertEqual(self._timeouts(), original)

    def test_retry_sleeps_without_transaction_or_exclusive_locks(self):
        self._create()
        with self._hold(f'{self.table}_p1') as blocker:
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_backend_pid()')
                drop_pid = cursor.fetchone()[0]

            def release_blocker(delay):
                self.assertEqual(connection.connection.get_transaction_status(), 0)
                with blocker.cursor() as cursor:
                    cursor.execute(
                        "SELECT count(*) FROM pg_locks WHERE pid=%s AND mode='AccessExclusiveLock'",
                        [drop_pid],
                    )
                    self.assertEqual(cursor.fetchone()[0], 0)
                blocker.rollback()

            with patch.object(helper.time, 'sleep', side_effect=release_blocker) as sleep:
                self._drop(max_attempts=2)
            sleep.assert_called_once()
        self.assertFalse(self._exists(self.index))

    def test_atomic_context_is_refused(self):
        self._create()
        with transaction.atomic(), self.assertRaises(RuntimeError):
            self._drop()
        self.assertTrue(self._exists(self.index))

    def test_orphan_cleanup_when_parent_is_already_missing(self):
        orphans = [self._orphan(part) for part in range(2)]
        self._drop()
        for orphan in orphans:
            self.assertFalse(self._exists(orphan))

    def test_parent_commits_before_orphan_cleanup_and_failed_cleanup_is_resumable(self):
        self._create()
        orphan = self._orphan()
        observer = connection.Database.connect(**connection.get_connection_params())
        observer.autocommit = True
        parent_name = self._relation(self.index).as_string(connection.connection)
        blocked_cleanup = False

        def block_after_parent_commit(execute, statement, params, many, context):
            nonlocal blocked_cleanup
            result = execute(statement, params, many)
            if not blocked_cleanup:
                with observer.cursor() as cursor:
                    cursor.execute('SELECT to_regclass(%s)', [parent_name])
                    if cursor.fetchone()[0] is None:
                        observer.autocommit = False
                        cursor.execute("SET LOCAL lock_timeout = '100ms'")
                        cursor.execute(sql.SQL('LOCK TABLE ONLY {} IN ACCESS SHARE MODE').format(
                            self._relation(f'{self.table}_p0'),
                        ))
                        blocked_cleanup = True
            return result

        try:
            with connection.execute_wrapper(block_after_parent_commit):
                with self.assertRaises(OperationalError):
                    self._drop()
            self.assertTrue(blocked_cleanup)
            self.assertFalse(self._exists(self.index))
            self.assertTrue(self._exists(orphan))
        finally:
            observer.rollback()
            observer.close()
        self._drop()
        self.assertFalse(self._exists(orphan))

    def test_statement_timeout_rolls_back_without_retry_and_restores_timeouts(self):
        if not self._execute('SELECT rolsuper FROM pg_roles WHERE rolname=current_user')[0][0]:
            self.skipTest('Installing the DDL delay trigger requires a PostgreSQL superuser.')
        self._create()
        original = self._timeouts()
        trigger = f'drop_delay_{uuid.uuid4().hex[:12]}'
        self._execute(sql.SQL('''
            CREATE FUNCTION {}() RETURNS event_trigger LANGUAGE plpgsql
            AS 'BEGIN PERFORM pg_sleep(1); END';
            CREATE EVENT TRIGGER {} ON ddl_command_start
            WHEN TAG IN ('DROP INDEX') EXECUTE FUNCTION {}()
        ''').format(self._relation('delay_drop'), sql.Identifier(trigger), self._relation('delay_drop')))
        try:
            with patch.object(helper.time, 'sleep') as sleep:
                with self.assertRaises(OperationalError) as raised:
                    self._drop(statement_timeout='50ms', max_attempts=2)
            self.assertEqual(raised.exception.__cause__.pgcode, '57014')
            sleep.assert_not_called()
            self.assertTrue(self._exists(self.index))
            self.assertEqual(self._timeouts(), original)
        finally:
            self._execute(sql.SQL('DROP EVENT TRIGGER {}').format(sql.Identifier(trigger)))

    def test_index_on_another_table_is_refused(self):
        self._execute(sql.SQL('CREATE TABLE {} (data jsonb)').format(self._relation('other')))
        self._execute(sql.SQL('CREATE INDEX {} ON {} USING GIN (data)').format(
            sql.Identifier(self.index), self._relation('other'),
        ))
        with self.assertRaises(DatabaseError) as raised:
            self._drop()
        self.assertEqual(raised.exception.__cause__.pgcode, 'P0001')
        self.assertTrue(self._exists(self.index))

    def test_quoted_index_names_and_dollar_delimiters(self):
        self.index = 'index"$drop_index$% odd'
        self._execute(sql.SQL('CREATE INDEX {} ON {} USING GIN (data)').format(
            sql.Identifier(self.index), self._relation(self.table),
        ))
        self._drop()
        self.assertFalse(self._exists(self.index))

    def test_legacy_positional_arguments_and_search_path(self):
        self._create()
        original = self._execute("SELECT current_setting('search_path')")[0][0]
        try:
            self._execute("SELECT set_config('search_path', %s, false)", [
                sql.Identifier(self.schema).as_string(connection.connection),
            ])
            helper.drop_partitioned_table_index(self.table, self.index, 2, '', True, max_attempts=1)
        finally:
            self._execute("SELECT set_config('search_path', %s, false)", [original])
        self.assertFalse(self._exists(self.index))

    def test_unique_btree_indexes_are_supported(self):
        helper.create_partitioned_table_index(
            self.table, self.index, '(org_id, inventory_id)',
            num_partitions=2, schema=self.schema,
            unique=True, migration_mode='automated',
        )
        self._drop()
        self.assertFalse(self._exists(self.index))
