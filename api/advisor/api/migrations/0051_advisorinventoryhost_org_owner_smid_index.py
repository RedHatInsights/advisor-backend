import os

from django.db import migrations

from api.scripts.partitioned_table_index_helper import (
    create_partitioned_table_index,
    drop_partitioned_table_index,
)

PARENT_TABLE = 'advisor_inventory_host'
INDEX_NAME = 'idx_aih_org_owner_smid'
INDEX_DEFINITION = '(org_id, owner_id, subscription_manager_id)'
PARTITION_COUNT = int(os.getenv('ADVISOR_INVENTORY_HOST_NUM_PARTITIONS', '1'))


def create_org_owner_smid_index(apps, schema_editor):
    create_partitioned_table_index(
        table_name=PARENT_TABLE,
        index_name=INDEX_NAME,
        index_definition=INDEX_DEFINITION,
        num_partitions=PARTITION_COUNT,
    )


def drop_org_owner_smid_index(apps, schema_editor):
    drop_partitioned_table_index(
        table_name=PARENT_TABLE,
        index_name=INDEX_NAME,
        num_partitions=PARTITION_COUNT,
    )


class Migration(migrations.Migration):
    """Index Satellite host scope: org_id, owner_id, subscription_manager_id."""

    atomic = False

    dependencies = [
        ('api', '0050_advisorinventoryhost_subscription_manager_id'),
    ]

    operations = [
        migrations.RunPython(create_org_owner_smid_index, drop_org_owner_smid_index),
    ]
