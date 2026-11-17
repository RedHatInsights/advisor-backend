"""
Helpers for creating and dropping partitioned indexes in Django migrations.

In automated mode (local, CI, ephemeral), indexes are created on the parent table only.
PostgreSQL creates matching indexes on all partitions automatically.

In managed mode (stage, production), indexes are created on each partition with
CREATE INDEX CONCURRENTLY first, then on the parent table.

Drops drain maintenance locks without blocking normal reads or writes before
requesting exclusive locks. Orphans are cleaned up after the parent commit.
"""

import logging
import os
import random
import time
from typing import Literal

from django.db import OperationalError, connections
from psycopg2 import sql

logger = logging.getLogger(__name__)

MigrationMode = Literal['automated', 'managed']


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


def _table_partitions(db_connection, table_name: str, schema: str) -> list[tuple[str, str]]:
    """Discover existing leaves, including their actual names and schemas."""
    with db_connection.cursor() as cursor:
        cursor.execute("""
            SELECT p.level, c.relkind, n.nspname, c.relname
            FROM pg_catalog.pg_partition_tree(pg_catalog.to_regclass(%s)) p
            JOIN pg_catalog.pg_class c ON c.oid=p.relid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE p.level=0 OR p.isleaf
            ORDER BY p.level, c.oid
        """, [_quoted_name(db_connection, table_name, schema)])
        rows = cursor.fetchall()
    if rows and rows[0][1] != 'p':
        raise ValueError('Expected a partitioned table.')
    return [(namespace, name) for level, _, namespace, name in rows if level > 0]


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
            for partition_schema, partition_name in _table_partitions(db_connection, table_name, schema):
                partition_index_name = _quoted_name(
                    db_connection, f'{partition_name}_{index_name}',
                )
                qualified_partition = _quoted_name(db_connection, partition_name, partition_schema)
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
        num_partitions: Legacy count, validated if provided; managed creation
            discovers the existing partitions from PostgreSQL instead
        schema: Optional schema name (empty string for the default public schema)
        unique: Create a UNIQUE index when True
        using: Django database alias used by both creation modes
    """
    if num_partitions is not None:
        validate_num_partitions(num_partitions)

    db_connection = connections[using]
    db_connection.ensure_connection()
    qualified_table = _quoted_name(db_connection, table_name, schema)
    unique_clause = 'UNIQUE ' if unique else ''

    logger.info(
        "Creating index '%s' on partitioned table '%s' in '%s' mode",
        index_name,
        qualified_table,
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


def _drop_index_locks(table, nowait, lock_timeout):
    """Wait for maintenance compatibly with DML, then acquire exclusive locks."""
    return sql.SQL("""
        LOCK TABLE {table} IN SHARE UPDATE EXCLUSIVE MODE;
        PERFORM pg_catalog.set_config('lock_timeout', {lock_timeout}, true);
        LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE {nowait};
    """).format(
        table=table, lock_timeout=sql.Literal(lock_timeout),
        nowait=sql.SQL('NOWAIT' if nowait else ''),
    )


def _drop_index_statement(
    db_connection, table_name, index_name, schema, if_exists, *, nowait=True, lock_timeout='100ms',
):
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
            {locks}
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
        missing=missing, drop=drop,
        locks=_drop_index_locks(table, nowait, lock_timeout),
    ).as_string(raw_connection)


def _drop_index_with_retry(
    cursor, nowait_statement, wait_statement, index_name,
    max_attempts, retry_delay_seconds, exclusive_wait_attempts,
):
    for attempt in range(1, max_attempts + 1):
        nowait = attempt <= max_attempts - exclusive_wait_attempts
        statement = nowait_statement if nowait else wait_statement
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
                'Lock unavailable dropping %s (attempt %d/%d, exclusive=%s); retrying in %.2fs',
                index_name, attempt, max_attempts, 'NOWAIT' if nowait else 'timed', delay,
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
    maintenance_lock_timeout: str = '1500ms',
    statement_timeout: str = '10s',
    max_attempts: int = 120,
    retry_delay_seconds: float = 2,
    exclusive_wait_attempts: int | None = None,
) -> None:
    """
    Drop a parent index and orphaned indexes with staged, bounded lock attempts.

    Requires autocommit outside an atomic block. Each drop is one server-side
    transaction: drain recursive SHARE UPDATE EXCLUSIVE locks, acquire ACCESS
    EXCLUSIVE locks, and drop. Maintenance waits allow normal DML to continue;
    maintenance_lock_timeout must exceed deadlock_timeout to let PostgreSQL
    interrupt ordinary autovacuum. Wraparound-prevention vacuum is protected.

    Exclusive acquisition uses NOWAIT initially. By default, the final sixth of
    max_attempts (at least one) waits briefly; exclusive_wait_attempts=0 disables
    that fallback. lock_timeout bounds all lock waits after draining, including
    this final exclusive wait. statement_timeout bounds the entire DO block.
    Retry only lock-unavailable errors, with no transaction held during delays.

    Attached children disappear with the parent. Legacy orphan cleanup runs in
    separate transactions after the parent commit; a failed cleanup is resumable
    with if_exists=True. Timeout settings on the selected alias are restored.
    Timeouts and the retry budget apply independently to each index drop.
    num_partitions is accepted for compatibility; actual leaves determine cleanup.
    """
    if num_partitions is not None:
        validate_num_partitions(num_partitions)
    if max_attempts < 1 or retry_delay_seconds < 0:
        raise ValueError('max_attempts must be positive and retry_delay_seconds nonnegative.')
    if exclusive_wait_attempts is None:
        exclusive_wait_attempts = max(1, max_attempts // 6)
    if not 0 <= exclusive_wait_attempts <= max_attempts:
        raise ValueError('exclusive_wait_attempts must be between zero and max_attempts.')

    db_connection = connections[using]
    if not db_connection.get_autocommit() or db_connection.in_atomic_block:
        raise RuntimeError('Dropping a partitioned index requires a non-atomic migration.')

    partitions = _table_partitions(db_connection, table_name, schema)
    logger.info(
        "Dropping index '%s' from partitioned table '%s' with %d partitions",
        index_name,
        _qualified_name(schema, table_name),
        len(partitions),
    )

    with db_connection.cursor() as cursor:
        cursor.execute(
            "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')"
        )
        original_timeouts = cursor.fetchone()
        try:
            # Set statement_timeout before DO starts, rather than inside it.
            cursor.execute(
                "SELECT set_config('lock_timeout', %s, false), "
                "set_config('statement_timeout', %s, false)",
                [maintenance_lock_timeout, statement_timeout],
            )
            targets = [(schema, table_name, index_name, if_exists)]
            targets.extend(
                (partition_schema, partition_name, f'{partition_name}_{index_name}', True)
                for partition_schema, partition_name in partitions
            )
            for target_schema, target_table, target_index, target_if_exists in targets:
                nowait_statement = _drop_index_statement(
                    db_connection, target_table, target_index, target_schema, target_if_exists,
                    lock_timeout=lock_timeout,
                )
                wait_statement = _drop_index_statement(
                    db_connection, target_table, target_index, target_schema, target_if_exists,
                    nowait=False, lock_timeout=lock_timeout,
                )
                _drop_index_with_retry(
                    cursor, nowait_statement, wait_statement, target_index,
                    max_attempts, retry_delay_seconds, exclusive_wait_attempts,
                )
        finally:
            # Every DO has committed or rolled back before settings are restored.
            cursor.execute(
                "SELECT set_config('lock_timeout', %s, false), "
                "set_config('statement_timeout', %s, false)",
                original_timeouts,
            )
