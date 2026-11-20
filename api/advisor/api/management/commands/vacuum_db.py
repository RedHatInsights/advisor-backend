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

from time import monotonic, sleep

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from api.models import (
    Ack, AdvisorInventoryHost, CurrentReport, Host, HostAck, Playbook,
    RuleRating, Upload, WeeklyReportSubscription,
)

# Tables whose indexes bloat quickly enough to be worth rebuilding.
REINDEX_TABLES = [
    CurrentReport._meta.db_table,
    Host._meta.db_table,
    AdvisorInventoryHost._meta.db_table,
]

# Tables to VACUUM ANALYZE, in order.
VACUUM_TABLES = [
    CurrentReport._meta.db_table,
    RuleRating._meta.db_table,
    HostAck._meta.db_table,
    WeeklyReportSubscription._meta.db_table,
    Ack._meta.db_table,
    Playbook._meta.db_table,
    Host._meta.db_table,
    Upload._meta.db_table,
    AdvisorInventoryHost._meta.db_table,
]

# Session settings applied for the run, and reset afterwards.
SESSION_SETTINGS = ('lock_timeout', 'statement_timeout', 'vacuum_cost_delay')


def mb(size):
    return f"{size / 1024 / 1024:.0f} MB"


class Command(BaseCommand):
    help = (
        "Rebuild indexes (REINDEX TABLE CONCURRENTLY) and VACUUM ANALYZE the "
        "busiest Advisor tables.  Runs through Django's database connection, "
        "so it does not need the psql client.  Defaults are chosen to limit "
        "the load on the database: VACUUM is throttled like autovacuum, lock "
        "waits time out, and tables with very large indexes are not reindexed."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--table', '-t', action='append', dest='tables', default=[],
            help="Reindex and vacuum this table (may be given more than once)"
        )
        parser.add_argument(
            '--reindex-table', action='append', dest='reindex_tables', default=[],
            help="Reindex all indexes on this table (may be given more than "
                 "once).  If no --table, --reindex-table or --reindex-index is "
                 "given, the built-in list of tables is reindexed"
        )
        parser.add_argument(
            '--reindex-index', action='append', dest='reindex_indexes', default=[],
            help="Reindex just this index (may be given more than once)"
        )
        parser.add_argument(
            '--vacuum-table', action='append', dest='vacuum_tables', default=[],
            help="Vacuum this table (may be given more than once).  If no "
                 "--table or --vacuum-table is given, the built-in list is used"
        )
        parser.add_argument(
            '--skip-reindex', action='store_true',
            help="Do not rebuild indexes"
        )
        parser.add_argument(
            '--skip-vacuum', action='store_true',
            help="Do not VACUUM ANALYZE"
        )
        parser.add_argument(
            '--max-index-size-mb', type=int, default=8192,
            help="Do not reindex an index, or a table (or partition) whose "
                 "indexes total, more than this many MB; 0 for no limit "
                 "(default: %(default)s)"
        )
        parser.add_argument(
            '--vacuum-cost-delay', type=float, default=2,
            help="vacuum_cost_delay in milliseconds, to throttle VACUUM like "
                 "autovacuum does; 0 for unthrottled (default: %(default)s)"
        )
        parser.add_argument(
            '--lock-timeout', default='30s',
            help="Give up on a statement that waits this long for a lock, "
                 "rather than queueing behind (and in front of) other "
                 "sessions; 0 to wait forever (default: %(default)s)"
        )
        parser.add_argument(
            '--statement-timeout', default='0',
            help="Cancel any single statement that runs longer than this; 0 "
                 "for no limit (default: %(default)s)"
        )
        parser.add_argument(
            '--pause', type=float, default=0,
            help="Seconds to wait between statements, to let IO and "
                 "replication catch up (default: %(default)s)"
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help="Print the statements that would be run without running them"
        )

    def handle(self, *args, **options):
        self.dry_run = options['dry_run']
        self.verbosity = options['verbosity']

        # VACUUM and REINDEX CONCURRENTLY cannot run inside a transaction block.
        if connection.in_atomic_block and not self.dry_run:
            raise CommandError(
                "vacuum_db cannot run inside a transaction (atomic block)"
            )

        reindex_tables = options['tables'] + options['reindex_tables']
        reindex_indexes = options['reindex_indexes']
        if not (reindex_tables or reindex_indexes):
            reindex_tables = REINDEX_TABLES
        vacuum_tables = (
            options['tables'] + options['vacuum_tables'] or VACUUM_TABLES
        )
        max_index_bytes = options['max_index_size_mb'] * 1024 * 1024
        settings = {
            'lock_timeout': options['lock_timeout'],
            'statement_timeout': options['statement_timeout'],
            'vacuum_cost_delay': f"{options['vacuum_cost_delay']:g}ms",
        }

        failures = []
        completed = 0
        total_start = monotonic()
        try:
            # Apply the timeouts before planning too, so that the size queries
            # cannot wait indefinitely behind another session's lock.
            self.apply_settings(settings)

            # Plan everything first, so a missing table fails before any work.
            # Each step is (action, relation to process, table it belongs to).
            plan = []
            if not options['skip_reindex']:
                candidates = []
                for table in reindex_tables:
                    # Reindex partitioned tables one partition at a time, so
                    # only one partition's indexes are being rebuilt at once.
                    candidates.extend(
                        ('reindex_table', leaf, leaf) for leaf in self.leaf_tables(table)
                    )
                for index in reindex_indexes:
                    candidates.extend(
                        ('reindex_index', leaf, table)
                        for leaf, table in self.leaf_indexes(index)
                    )
                for action, name, table in candidates:
                    size = self.index_size(action, name)
                    if max_index_bytes and size > max_index_bytes:
                        what = 'indexes are' if action == 'reindex_table' else 'index is'
                        self.stdout.write(
                            f"SKIPPED reindex of {name}: {what} {mb(size)}, over "
                            f"the {options['max_index_size_mb']} MB limit"
                        )
                        continue
                    plan.append((action, name, table))
            if not options['skip_vacuum']:
                for table in vacuum_tables:
                    self.leaf_tables(table)  # existence check only
                    # VACUUM on a partitioned parent recurses into its
                    # partitions, and ANALYZE also collects the parent's
                    # inheritance statistics.
                    plan.append(('vacuum', table, table))

            if self.dry_run:
                self.stdout.write('-- settings: ' + ', '.join(
                    f'{name}={value}' for name, value in settings.items()
                ))
                for action, name, _ in plan:
                    self.stdout.write(self.statement(action, name))
                return

            for number, (action, name, table) in enumerate(plan):
                if number and options['pause']:
                    sleep(options['pause'])
                reindex = action != 'vacuum'
                if reindex:
                    # REINDEX CONCURRENTLY skips invalid indexes, and they
                    # still cost space and write time, so remove any left by
                    # an earlier failed run.  A failure here is retried below.
                    self.drop_invalid_reindex_indexes(table)
                    size_before = self.index_size(action, name)
                statement = self.statement(action, name)
                start = monotonic()
                try:
                    self.execute_statement(statement)
                    succeeded = True
                except Exception as exc:
                    failures.append(statement)
                    self.stderr.write(f"FAILED: {statement}: {exc}")
                    succeeded = False
                if succeeded:
                    completed += 1
                    if self.verbosity >= 1:
                        result = f"{statement}: {monotonic() - start:.1f}s"
                        if reindex:
                            # Record the effect, to judge how often to reindex
                            size_after = self.index_size(action, name)
                            result += f", {mb(size_before)} -> {mb(size_after)}"
                        self.stdout.write(result)
                if reindex:
                    # Drop anything still invalid: a leftover the first attempt
                    # could not drop, or one this REINDEX left if it failed.
                    failures.extend(self.drop_invalid_reindex_indexes(table))
        finally:
            self.reset_settings()

        if self.verbosity >= 1:
            self.stdout.write(
                f"Completed {completed} of {len(plan)} "
                f"statements in {monotonic() - total_start:.1f}s"
            )
        if failures:
            raise CommandError(
                f"{len(failures)} statement(s) failed: " + '; '.join(failures)
            )

    @staticmethod
    def statement(action, table):
        name = connection.ops.quote_name(table)
        if action == 'reindex_table':
            return f'REINDEX TABLE CONCURRENTLY {name}'
        if action == 'reindex_index':
            return f'REINDEX INDEX CONCURRENTLY {name}'
        return f'VACUUM ANALYZE {name}'

    def execute_statement(self, statement):
        with connection.cursor() as cursor:
            cursor.execute(statement)

    def apply_settings(self, settings):
        with connection.cursor() as cursor:
            for name, value in settings.items():
                try:
                    cursor.execute("SELECT set_config(%s, %s, false)", [name, value])
                except Exception as exc:
                    raise CommandError(f"Invalid {name} value {value!r}: {exc}")

    def reset_settings(self):
        with connection.cursor() as cursor:
            for name in SESSION_SETTINGS:
                cursor.execute(f"RESET {name}")

    def index_size(self, action, name):
        """
        The size in bytes of an index, or of all the indexes on a table.
        """
        function = 'pg_indexes_size' if action == 'reindex_table' else 'pg_relation_size'
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT {function}(to_regclass(%s))", [name])
            return cursor.fetchone()[0]

    def leaf_indexes(self, index):
        """
        Return (index, table) name pairs for the ordinary indexes that make up
        this index: the index itself, or the index on each leaf partition if
        it is a partitioned index.  Raises CommandError if there is no such
        index.
        """
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT c.relkind, t.relname
                FROM pg_class c
                JOIN pg_index i ON i.indexrelid = c.oid
                JOIN pg_class t ON t.oid = i.indrelid
                WHERE c.oid = to_regclass(%s)
                """,
                [index]
            )
            row = cursor.fetchone()
            if row is None:
                raise CommandError(f"Index {index} does not exist")
            if row[0] != 'I':
                return [(index, row[1])]
            cursor.execute(
                """
                SELECT c.relname, t.relname
                FROM pg_partition_tree(to_regclass(%s)) pt
                JOIN pg_class c ON c.oid = pt.relid
                JOIN pg_index i ON i.indexrelid = c.oid
                JOIN pg_class t ON t.oid = i.indrelid
                WHERE pt.isleaf
                ORDER BY c.relname
                """,
                [index]
            )
            return cursor.fetchall()

    def drop_invalid_reindex_indexes(self, table):
        """
        Drop the invalid '_ccnew' / '_ccold' indexes that an interrupted
        REINDEX CONCURRENTLY leaves behind on this table.  Returns the DROP
        statements that failed, since a leftover index still slows writes.
        """
        with connection.cursor() as cursor:
            cursor.execute(
                r"""
                SELECT ci.relname
                FROM pg_index i
                JOIN pg_class ci ON ci.oid = i.indexrelid
                WHERE i.indrelid = to_regclass(%s)
                  AND NOT i.indisvalid
                  AND ci.relname ~ '_cc(new|old)[0-9]*$'
                """,
                [table]
            )
            leftovers = [relname for (relname,) in cursor.fetchall()]
        failed = []
        for index in leftovers:
            statement = f'DROP INDEX CONCURRENTLY {connection.ops.quote_name(index)}'
            try:
                self.execute_statement(statement)
                self.stdout.write(f"Dropped invalid index left by REINDEX: {index}")
            except Exception as exc:
                failed.append(statement)
                self.stderr.write(f"FAILED: {statement}: {exc}")
        return failed

    def leaf_tables(self, table):
        """
        Return the names of the ordinary tables that hold this table's data:
        the table itself, or all leaf partitions if it is partitioned.  Raises
        CommandError if the table does not exist.
        """
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT relkind FROM pg_class WHERE oid = to_regclass(%s)",
                [table]
            )
            row = cursor.fetchone()
            if row is None:
                raise CommandError(f"Table {table} does not exist")
            if row[0] != 'p':
                return [table]
            cursor.execute(
                """
                SELECT c.relname
                FROM pg_partition_tree(to_regclass(%s)) pt
                JOIN pg_class c ON c.oid = pt.relid
                WHERE pt.isleaf
                ORDER BY c.relname
                """,
                [table]
            )
            return [relname for (relname,) in cursor.fetchall()]
