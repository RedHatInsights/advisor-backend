"""PostgreSQL integration tests for committed index drops and lock failures."""

from contextlib import contextmanager
from unittest.mock import patch
import threading
import time
import uuid

from django.db import DatabaseError, OperationalError, ProgrammingError, connection, connections, transaction
from django.test import TransactionTestCase
from psycopg2 import sql

from api.scripts import partitioned_table_index_helper as helper


class PartitionedTableIndexHelperTestCase(TransactionTestCase):
    available_apps = []

    def setUp(self):
        super().setUp()
        # Keep contention tests prompt; the retention test exercises all probes.
        upgrades = patch.object(helper, 'EXCLUSIVE_UPGRADE_ATTEMPTS', 1)
        upgrades.start()
        self.addCleanup(upgrades.stop)
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
    def _hold(self, table, mode='ACCESS SHARE'):
        blocker = connection.Database.connect(**connection.get_connection_params())
        try:
            with blocker.cursor() as cursor:
                cursor.execute('SET LOCAL lock_timeout = %s', ['100ms'])
                cursor.execute(sql.SQL('LOCK TABLE ONLY {} IN {} MODE').format(
                    self._relation(table), sql.SQL(mode),
                ))
            yield blocker
        finally:
            blocker.rollback()
            blocker.close()

    def _start_worker(self, operation):
        ready = threading.Event()
        state = {'errors': []}

        def run():
            try:
                worker_connection = connections['default']
                worker_connection.ensure_connection()
                state['pid'] = worker_connection.connection.get_backend_pid()
                ready.set()
                operation()
            except Exception as exc:
                state['errors'].append(exc)
            finally:
                ready.set()
                connections['default'].close()

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(ready.wait(timeout=5))
        self.assertIn('pid', state, state['errors'])
        return worker, state

    def _wait_for_lock(self, pid, table):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            locks = self._execute(
                'SELECT mode FROM pg_locks WHERE pid=%s AND relation=to_regclass(%s) AND NOT granted',
                [pid, self._relation(table).as_string(connection.connection)],
            )
            if locks:
                return [row[0] for row in locks]
            time.sleep(0.01)
        self.fail(f'Worker {pid} did not wait for a lock on {table}.')

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

    def test_create_and_drop_quote_identifiers_consistently(self):
        for old, new in [(self.table, 'MixedHosts'), ('hosts_p0', 'MixedHosts_p0'), ('hosts_p1', 'MixedHosts_p1')]:
            self._execute(sql.SQL('ALTER TABLE {} RENAME TO {}').format(
                self._relation(old), sql.Identifier(new),
            ))
        self.table = 'MixedHosts'
        self.index = 'MiXeD"$drop_index$% odd'
        for mode in ['automated', 'managed']:
            with self.subTest(mode=mode):
                helper.create_partitioned_table_index(
                    self.table, self.index, 'USING GIN (data jsonb_path_ops)',
                    num_partitions=2, schema=self.schema, migration_mode=mode,
                )
                self.assertTrue(self._exists(self.index))
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

    def test_index_replaced_between_validation_and_lock_is_preserved(self):
        self._create()
        self._execute(sql.SQL('CREATE TABLE {} (data jsonb)').format(self._relation('other')))
        gate = connection.Database.connect(**connection.get_connection_params())
        gate.autocommit = True
        gate_key = uuid.uuid4().int % (2 ** 31)
        with gate.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_lock(%s)', [gate_key])
        build_locks = helper._drop_index_locks
        errors = []

        def pause_before_table_lock(*args, **kwargs):
            # Test-only barrier makes concurrent replacement deterministic.
            barrier = sql.SQL('PERFORM pg_advisory_xact_lock({});').format(sql.Literal(gate_key))
            return barrier + build_locks(*args, **kwargs)

        def drop_in_another_session():
            try:
                self._drop(maintenance_lock_timeout='5s', statement_timeout='10s')
            except Exception as exc:
                errors.append(exc)
            finally:
                connections['default'].close()

        worker = threading.Thread(target=drop_in_another_session)
        try:
            with patch.object(helper, '_drop_index_locks', side_effect=pause_before_table_lock):
                worker.start()
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    if self._execute(
                        "SELECT EXISTS (SELECT FROM pg_locks WHERE locktype='advisory' "
                        'AND classid=0 AND objid=%s AND NOT granted)', [gate_key],
                    )[0][0]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail('Index drop did not reach the synchronization barrier.')
                self._execute(sql.SQL('DROP INDEX {}').format(self._relation(self.index)))
                self._execute(sql.SQL('CREATE INDEX {} ON {} (data)').format(
                    sql.Identifier(self.index), self._relation('other'),
                ))
                with gate.cursor() as cursor:
                    cursor.execute('SELECT pg_advisory_unlock(%s)', [gate_key])
                worker.join(timeout=10)
        finally:
            gate.close()
            if worker.is_alive():
                worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1, errors)
        self.assertEqual(errors[0].__cause__.pgcode, 'P0001')
        self.assertTrue(self._exists(self.index))

    def test_final_timed_attempt_can_acquire_a_previously_busy_lock(self):
        self._create()
        original = self._timeouts()
        release = None
        with self._hold(self.table) as blocker:
            def release_during_timed_wait(delay):
                nonlocal release
                release = threading.Timer(0.05, blocker.rollback)
                release.start()

            try:
                with patch.object(helper.time, 'sleep', side_effect=release_during_timed_wait) as sleep:
                    self._drop(max_attempts=2, lock_timeout='200ms')
                sleep.assert_called_once()
            finally:
                if release is not None:
                    release.join(timeout=2)
        self.assertFalse(self._exists(self.index))
        self.assertEqual(self._timeouts(), original)

    def test_final_timed_attempt_remains_bounded_and_restores_timeouts(self):
        self._create()
        original = self._timeouts()
        with self._hold(self.table):
            with patch.object(helper.time, 'sleep') as sleep:
                with self.assertRaises(OperationalError) as raised:
                    self._drop(max_attempts=2, lock_timeout='50ms')
            sleep.assert_called_once()
        self.assertEqual(raised.exception.__cause__.pgcode, '55P03')
        self.assertTrue(self._exists(self.index))
        self.assertEqual(self._timeouts(), original)

    def test_orphan_cleanup_uses_actual_partitions_when_legacy_count_is_low(self):
        orphans = [self._orphan(part) for part in range(2)]
        self._drop(num_partitions=1)
        for orphan in orphans:
            self.assertFalse(self._exists(orphan))

    def test_managed_creation_prepares_every_actual_partition_concurrently(self):
        # A nonstandard name also proves discovery is not just range(count).
        partition = 'actual_leaf'
        self._execute(sql.SQL('ALTER TABLE {} RENAME TO {}').format(
            self._relation(f'{self.table}_p1'), sql.Identifier(partition),
        ))
        with self._hold(partition, 'SHARE UPDATE EXCLUSIVE') as blocker:
            worker, state = self._start_worker(lambda: helper.create_partitioned_table_index(
                self.table, self.index, 'USING GIN (data jsonb_path_ops)',
                num_partitions=1, schema=self.schema, migration_mode='managed',
            ))
            try:
                self.assertEqual(self._wait_for_lock(state['pid'], partition), ['ShareUpdateExclusiveLock'])
            finally:
                blocker.rollback()
                worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(state['errors'], [])
        self.assertTrue(self._exists(self.index))
        self.assertTrue(self._exists(f'{partition}_{self.index}'))

    def test_missing_table_is_idempotent(self):
        self._execute(sql.SQL('DROP TABLE {} CASCADE').format(self._relation(self.table)))
        self._drop()

    def test_maintenance_timeout_is_separate_from_exclusive_lock_timeout(self):
        self._create()
        original = self._timeouts()
        with self._hold(f'{self.table}_p0', 'SHARE UPDATE EXCLUSIVE'):
            with self.assertRaises(OperationalError) as raised:
                self._drop(maintenance_lock_timeout='50ms', lock_timeout='5s', statement_timeout='300ms')
        self.assertEqual(raised.exception.__cause__.pgcode, '55P03')
        self.assertEqual(self._timeouts(), original)

    def test_exclusive_timed_fallback_can_be_disabled(self):
        self._create()
        with self._hold(self.table), patch.object(helper.time, 'sleep'):
            with self.assertRaises(OperationalError) as raised:
                self._drop(max_attempts=2, exclusive_wait_attempts=0,
                           lock_timeout='5s', statement_timeout='300ms')
        self.assertEqual(raised.exception.__cause__.pgcode, '55P03')

    def test_single_attempt_defaults_to_nowait(self):
        self._create()
        with self._hold(self.table):
            with self.assertRaises(OperationalError) as raised:
                self._drop(lock_timeout='5s', statement_timeout='300ms')
        self.assertEqual(raised.exception.__cause__.pgcode, '55P03')

    def test_exclusive_retries_keep_maintenance_locks_and_release_partial_exclusive_locks(self):
        self._create()
        original = self._timeouts()
        with self._hold(f'{self.table}_p1') as blocker:
            with patch.object(helper, 'EXCLUSIVE_UPGRADE_ATTEMPTS', 50):
                worker, state = self._start_worker(lambda: self._drop(statement_timeout='10s'))
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if self._execute(
                            "SELECT wait_event='PgSleep' FROM pg_stat_activity WHERE pid=%s",
                            [state['pid']],
                        ) == [(True,)]:
                            break
                        time.sleep(0.01)
                    else:
                        self.fail('Exclusive upgrade did not reach its retry sleep.')
                    locks = self._execute(
                        'SELECT mode, count(*) FROM pg_locks WHERE pid=%s AND granted '
                        "AND mode IN ('ShareUpdateExclusiveLock', 'AccessExclusiveLock') GROUP BY mode",
                        [state['pid']],
                    )
                    self.assertEqual(locks, [('ShareUpdateExclusiveLock', 3)])
                    self._execute("SELECT set_config('statement_timeout', '300ms', false)")
                    self.assertEqual(self._execute(sql.SQL('SELECT count(*) FROM {}').format(
                        self._relation(self.table),
                    ))[0][0], 10)
                    self._execute(sql.SQL("UPDATE {} SET data='{{}}'::jsonb WHERE inventory_id=1").format(
                        self._relation(self.table),
                    ))
                finally:
                    self._execute("SELECT set_config('statement_timeout', %s, false)", [original[1]])
                    blocker.rollback()
                    worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(state['errors'], [])
        self.assertFalse(self._exists(self.index))

    def test_partition_discovery_obeys_maintenance_timeout_and_restores_settings(self):
        self._create()
        original = self._timeouts()
        with self._hold(f'{self.table}_p1', 'ACCESS EXCLUSIVE') as blocker:
            # Avoid an indefinite hang if discovery regresses outside the timeout scope.
            release = threading.Timer(1, blocker.rollback)
            release.start()
            try:
                with self.assertRaises(OperationalError) as raised:
                    self._drop(maintenance_lock_timeout='50ms')
            finally:
                release.cancel()
                release.join(timeout=2)
        self.assertEqual(raised.exception.__cause__.pgcode, '55P03')
        self.assertEqual(self._timeouts(), original)
        self.assertTrue(self._exists(self.index))

    def test_overall_budget_caps_a_blocked_statement(self):
        self._create()
        original = self._timeouts()
        with self._hold(f'{self.table}_p1', 'SHARE UPDATE EXCLUSIVE') as blocker:
            release = threading.Timer(1, blocker.rollback)
            release.start()
            try:
                with self.assertRaises(OperationalError) as raised:
                    self._drop(max_total_seconds=0.1, maintenance_lock_timeout='5s')
            finally:
                release.cancel()
                release.join(timeout=2)
        self.assertEqual(raised.exception.__cause__.pgcode, '57014')
        self.assertEqual(self._timeouts(), original)
        self.assertTrue(self._exists(self.index))

    def test_overall_budget_caps_retry_delays(self):
        self._create()
        original = self._timeouts()
        with self._hold(self.table):
            started = time.monotonic()
            with self.assertRaisesRegex(TimeoutError, 'max_total_seconds'):
                self._drop(max_attempts=2, retry_delay_seconds=5, max_total_seconds=0.1,
                           exclusive_wait_attempts=0)
            self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self._timeouts(), original)
        self.assertTrue(self._exists(self.index))

    def test_draining_multiple_maintenance_locks_allows_reads_and_writes(self):
        self._create()
        with self._hold(f'{self.table}_p0', 'SHARE UPDATE EXCLUSIVE') as first:
            with self._hold(f'{self.table}_p1', 'SHARE UPDATE EXCLUSIVE') as second:
                worker, state = self._start_worker(lambda: self._drop(
                    maintenance_lock_timeout='5s', statement_timeout='10s', exclusive_wait_attempts=0,
                ))
                original = self._timeouts()
                try:
                    for part, blocker in [(0, first), (1, second)]:
                        self.assertEqual(
                            self._wait_for_lock(state['pid'], f'{self.table}_p{part}'),
                            ['ShareUpdateExclusiveLock'],
                        )
                        self.assertEqual(self._execute(
                            "SELECT count(*) FROM pg_locks WHERE pid=%s AND mode='AccessExclusiveLock'",
                            [state['pid']],
                        )[0][0], 0)
                        self._execute("SELECT set_config('statement_timeout', '300ms', false)")
                        self.assertEqual(self._execute(sql.SQL('SELECT count(*) FROM {}').format(
                            self._relation(self.table),
                        ))[0][0], 10)
                        self._execute(sql.SQL("UPDATE {} SET data='{{}}'::jsonb WHERE inventory_id=1").format(
                            self._relation(self.table),
                        ))
                        blocker.rollback()
                finally:
                    self._execute("SELECT set_config('statement_timeout', %s, false)", [original[1]])
                    first.rollback()
                    second.rollback()
                    worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(state['errors'], [])
        self.assertFalse(self._exists(self.index))
