"""
Helper functions for creating indexes on partitioned tables in Django migrations.

In automated mode (local, CI, ephemeral), indexes are created on the parent table only.
PostgreSQL creates matching indexes on all partitions automatically.

In managed mode (stage, production), indexes are created on each partition with
CREATE INDEX CONCURRENTLY first, then on the parent table.
"""

import logging
import os
from typing import Literal

from django.db import connection, connections

logger = logging.getLogger(__name__)

TABLE_NUM_PARTITIONS = int(os.getenv('ADVISOR_INVENTORY_HOST_NUM_PARTITIONS', '1'))

MigrationMode = Literal['automated', 'managed']

def validate_num_partitions(num_partitions: int) -> None:
    if not 1 <= num_partitions <= 16:
        raise ValueError(
            f'Invalid number of partitions: {num_partitions}. Must be between 1 and 16.'
        )


def _qualified_name(schema: str, name: str) -> str:
    return f'{schema}.{name}' if schema else name


def _execute_sql(sql: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(sql)

def _wait_for_concurrent_indexes() -> None:
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
        """)

def _create_partitioned_table_index_automated(
    qualified_table: str,
    index_name: str,
    index_definition: str,
    unique_clause: str,
) -> None:
    _execute_sql(
        f'CREATE {unique_clause}INDEX IF NOT EXISTS {index_name} '
        f'ON {qualified_table} {index_definition};'
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
) -> None:

    db_connection = connections['default']
    db_connection.ensure_connection()
    original_autocommit = db_connection.get_autocommit()

    db_connection.set_autocommit(True)
    try:
        with db_connection.cursor() as cursor:
            for i in range(num_partitions):
                partition_name = f'{table_name}_p{i}'
                partition_index_name = f'{table_name}_p{i}_{index_name}'
                qualified_partition = _qualified_name(schema, partition_name)
                cursor.execute(
                    f'CREATE {unique_clause}INDEX CONCURRENTLY IF NOT EXISTS {partition_index_name} '
                    f'ON {qualified_partition} {index_definition};'
                )

        _wait_for_concurrent_indexes()

        with db_connection.cursor() as cursor:
            cursor.execute(
                f'CREATE {unique_clause}INDEX IF NOT EXISTS {index_name} '
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
    """
    if num_partitions is None:
        num_partitions = TABLE_NUM_PARTITIONS

    validate_num_partitions(num_partitions)

    qualified_table = _qualified_name(schema, table_name)
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
        )

    except Exception:
        logger.exception(
            "Error creating index '%s' on partitioned table '%s'",
            index_name,
            qualified_table,
        )
        raise


def drop_partitioned_table_index(
    table_name: str,
    index_name: str,
    num_partitions: int | None = None,
    schema: str = '',
    if_exists: bool = True,
) -> None:
    """
    Drop an index from a partitioned table and any orphaned partition indexes.

    Dropping the parent index cascades to attached partition indexes. Partition-level
    indexes left over from a failed managed-mode creation are cleaned up explicitly.
    """
    if num_partitions is None:
        num_partitions = TABLE_NUM_PARTITIONS

    validate_num_partitions(num_partitions)

    qualified_table = _qualified_name(schema, table_name)
    if_exists_clause = 'IF EXISTS' if if_exists else ''

    logger.info(
        "Dropping index '%s' from partitioned table '%s' with %d partitions",
        index_name,
        qualified_table,
        num_partitions,
    )

    try:
        _execute_sql(f'DROP INDEX {if_exists_clause} {_qualified_name(schema, index_name)};')

        for i in range(num_partitions):
            partition_index_name = f'{table_name}_p{i}_{index_name}'
            _execute_sql(
                f'DROP INDEX {if_exists_clause} {_qualified_name(schema, partition_index_name)};'
            )
    except Exception:
        logger.exception(
            "Error dropping index '%s' from partitioned table '%s'",
            index_name,
            qualified_table,
        )
        raise
