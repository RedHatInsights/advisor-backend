# Copyright 2016-2024 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

# Insights Advisor is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# Insights Advisor is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with Insights Advisor. If not, see <https://www.gnu.org/licenses/>.

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection
from django.test import TestCase, TransactionTestCase

from api.management.commands.vacuum_db import (
    Command, SESSION_SETTINGS, VACUUM_TABLES,
)


def leaf_partitions(table):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT relid::regclass::text FROM pg_partition_tree(%s::regclass) "
            "WHERE isleaf ORDER BY 1",
            [table]
        )
        return [row[0] for row in cursor.fetchall()]


class VacuumDbDryRunTestCase(TestCase):
    """
    Dry runs only plan statements, so they can run inside TestCase's
    transaction.
    """
    def run_command(self, *args):
        out = StringIO()
        call_command('vacuum_db', '--dry-run', *args, stdout=out)
        lines = out.getvalue().splitlines()
        return [line for line in lines if not line.startswith('-- settings: ')]

    def test_default_statements(self):
        lines = self.run_command()
        reindex = [line for line in lines if line.startswith('REINDEX')]
        vacuum = [line for line in lines if line.startswith('VACUUM')]
        self.assertEqual(len(lines), len(reindex) + len(vacuum))
        # Reindexes come before vacuums
        self.assertEqual(lines, reindex + vacuum)

        self.assertIn('REINDEX TABLE CONCURRENTLY "api_currentreport"', reindex)
        self.assertIn('REINDEX TABLE CONCURRENTLY "api_host"', reindex)
        # The partitioned parent is not reindexed directly; its leaves are
        self.assertNotIn('REINDEX TABLE CONCURRENTLY "advisor_inventory_host"', reindex)
        for leaf in leaf_partitions('advisor_inventory_host'):
            self.assertIn(f'REINDEX TABLE CONCURRENTLY "{leaf}"', reindex)

        self.assertEqual(
            vacuum, [f'VACUUM ANALYZE "{table}"' for table in VACUUM_TABLES]
        )

    def test_single_table(self):
        self.assertEqual(self.run_command('--table', 'api_upload'), [
            'REINDEX TABLE CONCURRENTLY "api_upload"',
            'VACUUM ANALYZE "api_upload"',
        ])

    def test_skip_options(self):
        lines = self.run_command('--skip-reindex')
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith('VACUUM') for line in lines))
        lines = self.run_command('--skip-vacuum')
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith('REINDEX') for line in lines))
        self.assertEqual(self.run_command('--skip-reindex', '--skip-vacuum'), [])

    def test_separate_reindex_and_vacuum_tables(self):
        self.assertEqual(self.run_command(
            '--reindex-table', 'api_host', '--vacuum-table', 'api_upload',
            '--vacuum-table', 'api_ack',
        ), [
            'REINDEX TABLE CONCURRENTLY "api_host"',
            'VACUUM ANALYZE "api_upload"',
            'VACUUM ANALYZE "api_ack"',
        ])
        # Giving only reindex tables leaves the default vacuum list
        lines = self.run_command('--reindex-table', 'api_host')
        self.assertEqual(lines[0], 'REINDEX TABLE CONCURRENTLY "api_host"')
        self.assertEqual(
            lines[1:], [f'VACUUM ANALYZE "{table}"' for table in VACUUM_TABLES]
        )

    def test_settings(self):
        out = StringIO()
        call_command('vacuum_db', '--dry-run', '--skip-vacuum', '--skip-reindex', stdout=out)
        self.assertEqual(out.getvalue().splitlines(), [
            '-- settings: lock_timeout=30s, statement_timeout=0, vacuum_cost_delay=2ms'
        ])
        out = StringIO()
        call_command(
            'vacuum_db', '--dry-run', '--skip-vacuum', '--skip-reindex',
            '--lock-timeout', '5s', '--statement-timeout', '1h',
            '--vacuum-cost-delay', '0', stdout=out
        )
        self.assertEqual(out.getvalue().splitlines(), [
            '-- settings: lock_timeout=5s, statement_timeout=1h, vacuum_cost_delay=0ms'
        ])

    def test_max_index_size(self):
        sizes = {'api_host': 9000 * 1024 * 1024, 'api_upload': 100 * 1024 * 1024}
        with patch.object(Command, 'index_size', lambda command, action, name: sizes[name]):
            out = StringIO()
            call_command(
                'vacuum_db', '--dry-run', '--skip-vacuum', '--reindex-table',
                'api_host', '--reindex-table', 'api_upload', stdout=out
            )
            lines = out.getvalue().splitlines()
            self.assertIn(
                'SKIPPED reindex of api_host: indexes are 9000 MB, over the 8192 MB limit',
                lines
            )
            self.assertIn('REINDEX TABLE CONCURRENTLY "api_upload"', lines)
            self.assertNotIn('REINDEX TABLE CONCURRENTLY "api_host"', lines)

            # A lower limit skips both; no limit skips neither
            lines = self.run_command(
                '--skip-vacuum', '--reindex-table', 'api_host',
                '--reindex-table', 'api_upload', '--max-index-size-mb', '50'
            )
            self.assertFalse([line for line in lines if line.startswith('REINDEX')])
            lines = self.run_command(
                '--skip-vacuum', '--reindex-table', 'api_host',
                '--reindex-table', 'api_upload', '--max-index-size-mb', '0'
            )
            self.assertEqual(len(lines), 2)

    def test_reindex_index(self):
        # Naming an index replaces the default list of tables to reindex
        self.assertEqual(
            self.run_command('--reindex-index', 'api_host_pkey', '--skip-vacuum'),
            ['REINDEX INDEX CONCURRENTLY "api_host_pkey"']
        )
        lines = self.run_command(
            '--reindex-index', 'api_host_pkey', '--reindex-table', 'api_upload'
        )
        self.assertEqual(lines[:2], [
            'REINDEX TABLE CONCURRENTLY "api_upload"',
            'REINDEX INDEX CONCURRENTLY "api_host_pkey"',
        ])
        self.assertEqual(
            lines[2:], [f'VACUUM ANALYZE "{table}"' for table in VACUUM_TABLES]
        )

    def test_reindex_partitioned_index(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT c.relname FROM pg_class c "
                "JOIN pg_index i ON i.indexrelid = c.oid "
                "WHERE i.indrelid = 'advisor_inventory_host'::regclass "
                "AND c.relkind = 'I' ORDER BY 1 LIMIT 1"
            )
            parent_index = cursor.fetchone()[0]
            cursor.execute(
                "SELECT relid::regclass::text FROM pg_partition_tree(%s::regclass) "
                "WHERE isleaf ORDER BY 1",
                [parent_index]
            )
            leaf_indexes = [row[0] for row in cursor.fetchall()]
        self.assertTrue(leaf_indexes)
        self.assertEqual(
            self.run_command('--reindex-index', parent_index, '--skip-vacuum'),
            [f'REINDEX INDEX CONCURRENTLY "{leaf}"' for leaf in leaf_indexes]
        )

    def test_reindex_index_max_size(self):
        with patch.object(Command, 'index_size', lambda command, action, name: 9000 * 1024 * 1024):
            out = StringIO()
            call_command(
                'vacuum_db', '--dry-run', '--skip-vacuum',
                '--reindex-index', 'api_host_pkey', stdout=out
            )
        self.assertEqual(out.getvalue().splitlines()[0], (
            'SKIPPED reindex of api_host_pkey: index is 9000 MB, over the 8192 MB limit'
        ))
        self.assertNotIn('REINDEX', out.getvalue())

    def test_missing_index(self):
        with self.assertRaisesRegex(CommandError, 'Index no_such_index does not exist'):
            self.run_command('--reindex-index', 'no_such_index')
        # A table is not an index
        with self.assertRaisesRegex(CommandError, 'Index api_host does not exist'):
            self.run_command('--reindex-index', 'api_host')

    def test_missing_table(self):
        with self.assertRaisesRegex(CommandError, 'does not exist'):
            self.run_command('--table', 'inventory.hosts_v1_1729168968095308833')

    def test_refuses_to_run_in_transaction(self):
        with self.assertRaisesRegex(CommandError, 'transaction'):
            call_command('vacuum_db', stdout=StringIO())


class VacuumDbTestCase(TransactionTestCase):
    """
    VACUUM and REINDEX CONCURRENTLY cannot run in a transaction, so these
    tests need TransactionTestCase.
    """

    def show(self, setting):
        with connection.cursor() as cursor:
            cursor.execute(f"SHOW {setting}")
            return cursor.fetchone()[0]

    def test_default_run(self):
        out = StringIO()
        call_command('vacuum_db', stdout=out)
        output = out.getvalue()
        self.assertIn('REINDEX TABLE CONCURRENTLY "api_currentreport"', output)
        self.assertIn('VACUUM ANALYZE "advisor_inventory_host"', output)
        self.assertIn('Completed', output)

        planned = StringIO()
        call_command('vacuum_db', '--dry-run', stdout=planned)
        count = len(planned.getvalue().splitlines()) - 1  # settings line
        self.assertIn(f'Completed {count} of {count} statements', output)

    def test_reindex_index_run(self):
        out = StringIO()
        call_command(
            'vacuum_db', '--reindex-index', 'api_host_pkey', '--skip-vacuum',
            stdout=out
        )
        lines = out.getvalue().splitlines()
        self.assertRegex(
            lines[0], r'^REINDEX INDEX CONCURRENTLY "api_host_pkey": [0-9.]+s, \d+ MB -> \d+ MB$'
        )
        self.assertIn('Completed 1 of 1 statements', lines[1])

    def test_failure_continues_then_raises(self):
        original = Command.execute_statement
        bad_statement = 'REINDEX TABLE CONCURRENTLY "api_upload"'

        def execute_statement(command, statement):
            if statement == bad_statement:
                raise DatabaseError('simulated failure')
            return original(command, statement)

        out, err = StringIO(), StringIO()
        with patch.object(Command, 'execute_statement', execute_statement):
            with self.assertRaisesRegex(CommandError, '1 statement\\(s\\) failed'):
                call_command(
                    'vacuum_db', '--table', 'api_upload', stdout=out, stderr=err
                )
        self.assertIn(f'FAILED: {bad_statement}: simulated failure', err.getvalue())
        # The VACUUM still ran after the REINDEX failed
        self.assertIn('VACUUM ANALYZE "api_upload"', out.getvalue())
        self.assertIn('Completed 1 of 2 statements', out.getvalue())

    def test_settings_applied_and_reset(self):
        before = {name: self.show(name) for name in SESSION_SETTINGS}
        seen = {}
        original = Command.execute_statement

        def execute_statement(command, statement):
            seen.update({name: self.show(name) for name in SESSION_SETTINGS})
            return original(command, statement)

        with patch.object(Command, 'execute_statement', execute_statement):
            call_command(
                'vacuum_db', '--table', 'api_upload', '--lock-timeout', '5s',
                '--statement-timeout', '10min', '--vacuum-cost-delay', '1',
                stdout=StringIO()
            )
        self.assertEqual(seen, {
            'lock_timeout': '5s', 'statement_timeout': '10min',
            'vacuum_cost_delay': '1ms',
        })
        self.assertEqual({name: self.show(name) for name in SESSION_SETTINGS}, before)

    def test_invalid_setting(self):
        with self.assertRaisesRegex(CommandError, 'Invalid lock_timeout'):
            call_command(
                'vacuum_db', '--table', 'api_upload', '--lock-timeout', 'soon',
                stdout=StringIO()
            )

    def test_pause_between_statements(self):
        with patch('api.management.commands.vacuum_db.sleep') as mock_sleep:
            call_command(
                'vacuum_db', '--table', 'api_upload', '--pause', '7',
                stdout=StringIO()
            )
        mock_sleep.assert_called_once_with(7)

    def test_drops_invalid_reindex_indexes(self):
        self.create_invalid_index()
        out = StringIO()
        call_command('vacuum_db', '--table', 'vacuum_db_test', stdout=out)
        self.assertIn(
            'Dropped invalid index left by REINDEX: vacuum_db_test_x_ccnew',
            out.getvalue()
        )
        self.assertEqual(self.indexes('vacuum_db_test'), [])

    def test_failed_invalid_index_drop_is_a_failure(self):
        self.create_invalid_index()
        original = Command.execute_statement

        def execute_statement(command, statement):
            if statement.startswith('DROP INDEX'):
                raise DatabaseError('simulated lock timeout')
            return original(command, statement)

        out, err = StringIO(), StringIO()
        with patch.object(Command, 'execute_statement', execute_statement):
            with self.assertRaisesRegex(
                CommandError, 'DROP INDEX CONCURRENTLY "vacuum_db_test_x_ccnew"'
            ):
                call_command(
                    'vacuum_db', '--table', 'vacuum_db_test', stdout=out, stderr=err
                )
        self.assertIn('simulated lock timeout', err.getvalue())
        # The REINDEX and VACUUM themselves still succeeded
        self.assertIn('Completed 2 of 2 statements', out.getvalue())
        self.assertEqual(self.indexes('vacuum_db_test'), ['vacuum_db_test_x_ccnew'])

    def test_invalid_index_drop_retried_after_reindex(self):
        self.create_invalid_index()
        original = Command.execute_statement
        drops = []

        def execute_statement(command, statement):
            if statement.startswith('DROP INDEX'):
                drops.append(statement)
                if len(drops) == 1:
                    raise DatabaseError('simulated lock timeout')
            return original(command, statement)

        out, err = StringIO(), StringIO()
        with patch.object(Command, 'execute_statement', execute_statement):
            call_command(
                'vacuum_db', '--table', 'vacuum_db_test', stdout=out, stderr=err
            )
        self.assertIn('simulated lock timeout', err.getvalue())
        self.assertIn(
            'Dropped invalid index left by REINDEX: vacuum_db_test_x_ccnew',
            out.getvalue()
        )
        self.assertEqual(len(drops), 2)
        self.assertEqual(self.indexes('vacuum_db_test'), [])

    def test_timeouts_apply_while_planning(self):
        original = Command.index_size
        seen = []

        def index_size(command, action, name):
            seen.append(self.show('lock_timeout'))
            return original(command, action, name)

        with patch.object(Command, 'index_size', index_size):
            call_command(
                'vacuum_db', '--dry-run', '--reindex-index', 'api_host_pkey',
                '--lock-timeout', '5s', stdout=StringIO()
            )
        self.assertEqual(seen, ['5s'])

    def create_invalid_index(self):
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE vacuum_db_test (x integer)")
            self.addCleanup(self.drop_test_table)
            cursor.execute("INSERT INTO vacuum_db_test VALUES (1), (1)")
            # A failed CREATE INDEX CONCURRENTLY leaves an invalid index, as an
            # interrupted REINDEX CONCURRENTLY does with its _ccnew index.
            with self.assertRaises(DatabaseError):
                cursor.execute(
                    "CREATE UNIQUE INDEX CONCURRENTLY vacuum_db_test_x_ccnew "
                    "ON vacuum_db_test (x)"
                )
        self.assertEqual(self.indexes('vacuum_db_test'), ['vacuum_db_test_x_ccnew'])

    def indexes(self, table):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT indexname FROM pg_indexes WHERE tablename = %s", [table]
            )
            return [row[0] for row in cursor.fetchall()]

    def drop_test_table(self):
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE IF EXISTS vacuum_db_test")
