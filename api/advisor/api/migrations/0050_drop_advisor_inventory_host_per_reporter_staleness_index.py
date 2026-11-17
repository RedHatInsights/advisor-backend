"""
Drop the unused GIN index on advisor_inventory_host.per_reporter_staleness.

The index (created in 0046) uses jsonb_path_ops, which only supports the
containment operators (@>, @?, @@). Advisor only filters on values extracted
from the JSON (e.g. per_reporter_staleness -> 'puptoo' ->> 'stale_timestamp'),
so the index is never used: prod showed 0 scans on all partitions. Every HBI
update rewrites the staleness timestamps, so the index kept growing (47 GB in
prod after 4.5 months). See RHINENG-30535.

PostgreSQL can't drop a partitioned index CONCURRENTLY, and dropping it takes
an ACCESS EXCLUSIVE lock on the parent table and every partition. To avoid
queueing behind long-running queries (which would block all other access to
the table while we wait), each attempt uses a short lock_timeout and is retried.
"""

import logging
import time

from django.db import OperationalError, migrations, transaction

from api.scripts.partitioned_table_index_helper import (
    create_partitioned_table_index,
    drop_partitioned_table_index,
)

logger = logging.getLogger(__name__)

PARENT_TABLE = 'advisor_inventory_host'
INDEX_NAME = 'idx_advisor_inventory_host_per_reporter_staleness'
INDEX_DEFINITION = 'USING GIN (per_reporter_staleness jsonb_path_ops)'

LOCK_TIMEOUT = '5s'
MAX_ATTEMPTS = 12
RETRY_DELAY_SECONDS = 10

LOCK_NOT_AVAILABLE = '55P03'


def drop_per_reporter_staleness_index(apps, schema_editor):
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with transaction.atomic(using=schema_editor.connection.alias):
                with schema_editor.connection.cursor() as cursor:
                    cursor.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}';")
                drop_partitioned_table_index(
                    table_name=PARENT_TABLE,
                    index_name=INDEX_NAME,
                )
            return
        except OperationalError as e:
            if getattr(e.__cause__, 'pgcode', None) != LOCK_NOT_AVAILABLE:
                raise
            if attempt == MAX_ATTEMPTS:
                logger.error(
                    "Could not lock %s to drop %s after %d attempts",
                    PARENT_TABLE, INDEX_NAME, MAX_ATTEMPTS,
                )
                raise
            logger.warning(
                "Timed out waiting for lock on %s (attempt %d/%d); retrying in %ds",
                PARENT_TABLE, attempt, MAX_ATTEMPTS, RETRY_DELAY_SECONDS,
            )
            time.sleep(RETRY_DELAY_SECONDS)


def recreate_per_reporter_staleness_index(apps, schema_editor):
    create_partitioned_table_index(
        table_name=PARENT_TABLE,
        index_name=INDEX_NAME,
        index_definition=INDEX_DEFINITION,
    )


class Migration(migrations.Migration):

    # Each drop attempt runs in its own short transaction so the retry delay
    # doesn't hold any locks; the reverse needs autocommit for CONCURRENTLY.
    atomic = False

    dependencies = [
        ('api', '0049_remove_inventoryhost'),
    ]

    operations = [
        migrations.RunPython(
            drop_per_reporter_staleness_index,
            recreate_per_reporter_staleness_index,
        ),
    ]
