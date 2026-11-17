"""
Helpers for creating and dropping partitioned indexes in Django migrations.

In automated mode (local, CI, ephemeral), indexes are created on the parent table only.
PostgreSQL creates matching indexes on all partitions automatically.

In managed mode (stage, production), indexes are created on each partition with
CREATE INDEX CONCURRENTLY first, then on the parent table.

Drops use autocommit and recursive NOWAIT locks, followed by bounded timed waits
on the final attempts. Orphan indexes are cleaned up after the parent commit.
"""

import logging
import os
import random
import time
from typing import Literal

from django.db import OperationalError, connections
from psycopg2 import sql

logger = logging.getLogger(__name__)

TABLE_NUM_PARTITIONS = int(os.getenv('ADVISOR_INVENTORY_HOST_NUM_PARTITIONS', '1'))

MigrationMode = Literal['automated', 'managed']

# None never queues. Final attempts can interrupt a blocking, non-wraparound
# autovacuum when this wait exceeds deadlock_timeout (1s in production).
LOCK_SCHEDULE = (None,) * 100 + ('1500ms',) * 20


def validate_num_partitions(num_partitions: int) -> None:
    if not 1 <= num_partitions <= 16:
        raise ValueError(
            f'Invalid number of partitions: {num_partitions}. Must be between 1 and 16.'
        )


def _qualified_name(schema: str, name: str) -> str:
    return f'{schema}.{name}' if schema else name


def _quoted_name(db_connection, name: str, schema: str = '') -> str:
    identifier = sql.Identifier(schema, name) if schema else sql.Identifier(name)
    return identifier.as_string(db_connection.connection)


def _execute_sql(statement: str, using: str = 'default') -> None:
    with connections[using].cursor() as cursor:
        cursor.execute(statement)


def _wait_for_concurrent_indexes(using: str = 'default') -> None:
    _execute_sql("""
            DO $$
            DECLARE
                idx_builds INT;
            BEGIN
                RAISE NOTICE 'Waiting for all concurrent index builds to complete...';
                LOOP
                    SELECT COUNT(*) INTO idx_builds
                    FROM pg_stat_progress_create_index
                    WHERE command = 'CREATE INDEX' AND phase != 'done';

                    EXIT WHEN idx_builds = 0;

                    RAISE NOTICE 'Still % ongoing index builds... sleeping 10s', idx_builds;
                    PERFORM pg_sleep(10);
                END LOOP;
                RAISE NOTICE 'All concurrent index builds are complete.';
            END;
            $$;
        """, using=using)


def _create_partitioned_table_index_automated(
    qualified_table: str,
    index_name: str,
    index_definition: str,
    unique_clause: str,
    using: str,
) -> None:
    _execute_sql(
        f'CREATE {unique_clause}INDEX IF NOT EXISTS '
        f'{_quoted_name(connections[using], index_name)} '
        f'ON {qualified_table} {index_definition};', using=using,
    )
    return


def _create_partitioned_table_index_managed(
    table_name: str,
    qualified_table: str,
    index_name: str,
    index_definition: str,
    num_partitions: int,
    schema: str,
    unique_clause: str,
    using: str,
) -> None:

    db_connection = connections[using]
    db_connection.ensure_connection()
    original_autocommit = db_connection.get_autocommit()

    db_connection.set_autocommit(True)
    try:
        with db_connection.cursor() as cursor:
            for i in range(num_partitions):
                partition_name = f'{table_name}_p{i}'
                partition_index_name = _quoted_name(
                    db_connection, f'{table_name}_p{i}_{index_name}',
                )
                qualified_partition = _quoted_name(db_connection, partition_name, schema)
                cursor.execute(
                    f'CREATE {unique_clause}INDEX CONCURRENTLY IF NOT EXISTS {partition_index_name} '
                    f'ON {qualified_partition} {index_definition};'
                )

        _wait_for_concurrent_indexes(using=using)

        with db_connection.cursor() as cursor:
            cursor.execute(
                f'CREATE {unique_clause}INDEX IF NOT EXISTS '
                f'{_quoted_name(db_connection, index_name)} '
                f'ON {qualified_table} {index_definition};'
            )
    finally:
        db_connection.set_autocommit(original_autocommit)


def create_partitioned_table_index(
    table_name: str,
    index_name: str,
    index_definition: str,
    num_partitions: int | None = None,
    schema: str = '',
    unique: bool = False,
    migration_mode: MigrationMode = os.getenv('MIGRATION_MODE', 'automated'),
    *,
    using: str = 'default',
) -> None:
    """
    Create an index on a partitioned table and all its partitions.

    Args:
        table_name: Name of the parent table (without schema prefix)
        index_name: Name for the index (partition indexes are prefixed per partition)
        index_definition: Column definition for the index, e.g. "(org_id, last_check_in DESC)"
            or "USING GIN (tags jsonb_path_ops)"
        num_partitions: Number of hash partitions (0 .. num_partitions-1)
        schema: Optional schema name (empty string for the default public schema)
        unique: Create a UNIQUE index when True
        using: Django database alias used by both creation modes
    """
    if num_partitions is None:
        num_partitions = TABLE_NUM_PARTITIONS

    validate_num_partitions(num_partitions)

    db_connection = connections[using]
    db_connection.ensure_connection()
    qualified_table = _quoted_name(db_connection, table_name, schema)
    unique_clause = 'UNIQUE ' if unique else ''

    logger.info(
        "Creating index '%s' on partitioned table '%s' with %d partitions in '%s' mode",
        index_name,
        qualified_table,
        num_partitions,
        migration_mode,
    )

    if migration_mode == 'automated':
        _create_partitioned_table_index_automated(
            qualified_table=qualified_table,
            index_name=index_name,
            index_definition=index_definition,
            unique_clause=unique_clause,
            using=using,
        )
        return

    try:
        _create_partitioned_table_index_managed(
            table_name=table_name,
            qualified_table=qualified_table,
            index_name=index_name,
            index_definition=index_definition,
            num_partitions=num_partitions,
            schema=schema,
            unique_clause=unique_clause,
            using=using,
        )

    except Exception:
        logger.exception(
            "Error creating index '%s' on partitioned table '%s'",
            index_name,
            qualified_table,
        )
        raise


def _drop_index_statement(db_connection, table_name, index_name, schema, if_exists, *, nowait=True):
    """Quote both SQL identifiers and the outer PL/pgSQL source separately."""
    table = sql.Identifier(schema, table_name) if schema else sql.Identifier(table_name)
    index = sql.Identifier(schema, index_name) if schema else sql.Identifier(index_name)
    raw_connection = db_connection.connection
    drop = sql.SQL('DROP INDEX {if_exists} {index};').format(
        if_exists=sql.SQL('IF EXISTS' if if_exists else ''), index=index,
    )
    missing = sql.SQL('RETURN;') if if_exists else drop + sql.SQL(' RETURN;')
    # One autocommitted server round trip keeps lock acquisition and DROP
    # together, without a client round trip extending the exclusive lock.
    return sql.SQL("""
        DECLARE
            target_index oid := pg_catalog.to_regclass({index_name});
            target_table oid := pg_catalog.to_regclass({table_name});
        BEGIN
            IF target_index IS NULL THEN
                {missing}
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_index
                WHERE indexrelid = target_index
                  AND indrelid = target_table
            ) THEN
                RAISE EXCEPTION 'Index does not belong to the expected table';
            END IF;
            LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE {nowait};
            IF pg_catalog.to_regclass({index_name}) IS DISTINCT FROM target_index
                OR pg_catalog.to_regclass({table_name}) IS DISTINCT FROM target_table
                OR NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_index
                    WHERE indexrelid = target_index AND indrelid = target_table
                )
            THEN
                RAISE EXCEPTION 'Index identity or table changed while acquiring locks';
            END IF;
            {drop}
        END
    """).format(
        index_name=sql.Literal(index.as_string(raw_connection)),
        table_name=sql.Literal(table.as_string(raw_connection)),
        missing=missing, table=table, drop=drop,
        nowait=sql.SQL('NOWAIT' if nowait else ''),
    ).as_string(raw_connection)


def _drop_index_with_retry(
    cursor, nowait_statement, wait_statement, index_name,
    max_attempts, retry_delay_seconds, lock_timeout,
):
    for attempt in range(1, max_attempts + 1):
        wait_timeout = LOCK_SCHEDULE[min(attempt - 1, len(LOCK_SCHEDULE) - 1)]
        cursor.execute(
            "SELECT set_config('lock_timeout', %s, false)",
            [wait_timeout or lock_timeout],
        )
        statement = nowait_statement if wait_timeout is None else wait_statement
        try:
            # Bind the entire DO body as a string literal. This also handles
            # identifiers containing quotes or a PL/pgSQL dollar delimiter.
            cursor.execute('DO %s', [statement])
        except OperationalError as exc:
            if getattr(exc.__cause__, 'pgcode', None) != '55P03':
                raise
            if attempt == max_attempts:
                raise
            delay = retry_delay_seconds + random.uniform(0, 1)
            logger.warning(
                'Lock unavailable dropping %s (attempt %d/%d, wait=%s); retrying in %.2fs',
                index_name, attempt, max_attempts, wait_timeout or 'NOWAIT', delay,
            )
            # Autocommit has already rolled back the unsuccessful DO block.
            time.sleep(delay)
        else:
            return


def drop_partitioned_table_index(
    table_name: str,
    index_name: str,
    num_partitions: int | None = None,
    schema: str = '',
    if_exists: bool = True,
    *,
    using: str = 'default',
    lock_timeout: str = '100ms',
    statement_timeout: str = '2s',
    max_attempts: int = 120,
    retry_delay_seconds: float = 2,
) -> None:
    """
    Drop a parent index and orphaned indexes with staged, bounded lock attempts.

    Requires autocommit outside an atomic block. Each drop is one server-side
    transaction: recursively lock the table and drop the index. The first 100
    attempts use NOWAIT; remaining attempts wait up to 1500ms per lock. A wait
    longer than deadlock_timeout lets PostgreSQL interrupt ordinary autovacuum;
    wraparound-prevention vacuum is not interrupted. statement_timeout still
    bounds each DO block, including all its lock acquisitions. Retry only
    lock-unavailable errors, with no transaction held during the delay.

    Attached children disappear with the parent. Legacy orphan cleanup runs in
    separate transactions after the parent commit; a failed cleanup is resumable
    with if_exists=True. Timeout settings on the selected alias are restored.
    Timeouts and the retry budget apply independently to each index drop.
    """
    if num_partitions is None:
        num_partitions = TABLE_NUM_PARTITIONS

    validate_num_partitions(num_partitions)
    if max_attempts < 1 or retry_delay_seconds < 0:
        raise ValueError('max_attempts must be positive and retry_delay_seconds nonnegative.')

    db_connection = connections[using]
    if not db_connection.get_autocommit() or db_connection.in_atomic_block:
        raise RuntimeError('Dropping a partitioned index requires a non-atomic migration.')

    logger.info(
        "Dropping index '%s' from partitioned table '%s' with %d partitions",
        index_name,
        _qualified_name(schema, table_name),
        num_partitions,
    )

    with db_connection.cursor() as cursor:
        cursor.execute(
            "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')"
        )
        original_timeouts = cursor.fetchone()
        try:
            # Set statement_timeout before DO starts, rather than inside it.
            cursor.execute(
                "SELECT set_config('statement_timeout', %s, false)",
                [statement_timeout],
            )
            targets = [(table_name, index_name, if_exists)]
            targets.extend(
                (f'{table_name}_p{i}', f'{table_name}_p{i}_{index_name}', True)
                for i in range(num_partitions)
            )
            for target_table, target_index, target_if_exists in targets:
                nowait_statement = _drop_index_statement(
                    db_connection, target_table, target_index, schema, target_if_exists,
                )
                wait_statement = _drop_index_statement(
                    db_connection, target_table, target_index, schema, target_if_exists,
                    nowait=False,
                )
                _drop_index_with_retry(
                    cursor, nowait_statement, wait_statement, target_index,
                    max_attempts, retry_delay_seconds, lock_timeout,
                )
        finally:
            # Every DO has committed or rolled back before settings are restored.
            cursor.execute(
                "SELECT set_config('lock_timeout', %s, false), "
                "set_config('statement_timeout', %s, false)",
                original_timeouts,
            )
