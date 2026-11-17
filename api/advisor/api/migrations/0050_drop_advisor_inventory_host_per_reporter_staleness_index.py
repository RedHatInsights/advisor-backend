"""Drop the unused partitioned staleness GIN index using fail-fast locking."""

from django.db import migrations

from api.scripts.partitioned_table_index_helper import (
    create_partitioned_table_index,
    drop_partitioned_table_index,
)

PARENT_TABLE = 'advisor_inventory_host'
INDEX_NAME = 'idx_advisor_inventory_host_per_reporter_staleness'
INDEX_DEFINITION = 'USING GIN (per_reporter_staleness jsonb_path_ops)'


def drop_per_reporter_staleness_index(apps, schema_editor):
    drop_partitioned_table_index(
        table_name=PARENT_TABLE,
        index_name=INDEX_NAME,
        schema='public',
        using=schema_editor.connection.alias,
    )


def recreate_per_reporter_staleness_index(apps, schema_editor):
    create_partitioned_table_index(
        table_name=PARENT_TABLE,
        index_name=INDEX_NAME,
        index_definition=INDEX_DEFINITION,
        schema='public',
        using=schema_editor.connection.alias,
    )


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ('api', '0049_remove_inventoryhost'),
    ]

    operations = [
        migrations.RunPython(
            drop_per_reporter_staleness_index,
            recreate_per_reporter_staleness_index,
            atomic=False,
        ),
    ]
