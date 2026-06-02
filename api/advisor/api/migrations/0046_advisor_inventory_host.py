import os
import django_prometheus.models
from django.db import migrations, models

from api.scripts.partitioned_table_index_helper import (
    create_partitioned_table_index,
    drop_partitioned_table_index,
)

PARTITION_COUNT = int(os.getenv('PARTITION_COUNT', '16'))
PARENT_TABLE = 'advisor_inventory_host'

CREATE_PARENT_SQL = f"""
    CREATE TABLE {PARENT_TABLE} (
        inventory_id UUID NOT NULL,
        account VARCHAR(10),
        org_id VARCHAR(50) NOT NULL,
        display_name VARCHAR(200) NOT NULL,
        tags JSONB NOT NULL,
        workspace_id UUID,
        workspace_name VARCHAR(200),
        updated TIMESTAMPTZ NOT NULL,
        created TIMESTAMPTZ NOT NULL,
        last_check_in TIMESTAMPTZ NOT NULL,
        stale_timestamp TIMESTAMPTZ NOT NULL,
        insights_id UUID NOT NULL,
        reporter VARCHAR(200) NOT NULL DEFAULT 'puptoo',
        per_reporter_staleness JSONB NOT NULL DEFAULT '{{}}'::jsonb,
        os_name VARCHAR(50),
        os_major INTEGER,
        os_minor INTEGER,
        host_type VARCHAR(50),
        bootc_booted_image VARCHAR(512),
        bootc_booted_image_digest VARCHAR(256),
        owner_id UUID,
        rhc_client_id UUID,
        workloads JSONB NOT NULL DEFAULT '{{}}'::jsonb,
        system_update_method VARCHAR(50),
        PRIMARY KEY (org_id, inventory_id)
    ) PARTITION BY HASH (org_id);
"""

partition_statements = []
for i in range(PARTITION_COUNT):
    partition_statements.append(
        f'CREATE TABLE {PARENT_TABLE}_p{i} '
        f'PARTITION OF {PARENT_TABLE} '
        f'FOR VALUES WITH (MODULUS {PARTITION_COUNT}, REMAINDER {i});'
    )
PARTITION_SQL = '\n'.join(partition_statements)

CREATE_TABLE_SQL = CREATE_PARENT_SQL + PARTITION_SQL

# Mirrors inventory.hosts indexes (Cyndi mock + current HBI hosts indexes), adapted
# for flattened advisor_inventory_host columns.
PARTITIONED_INDEXES = [
    ('idx_advisor_inventory_host_display_name', '(display_name)'),
    ('idx_advisor_inventory_host_tags', 'USING GIN (tags jsonb_path_ops)'),
    (
        'idx_advisor_inventory_host_per_reporter_staleness',
        'USING GIN (per_reporter_staleness jsonb_path_ops)',
    ),
    ('idx_advisor_inventory_host_insights_id', '(insights_id)'),
    ('idx_advisor_inventory_host_host_type', '(host_type)'),
]


def create_advisor_inventory_host_indexes(apps, schema_editor):
    for index_name, index_definition in PARTITIONED_INDEXES:
        create_partitioned_table_index(
            table_name=PARENT_TABLE,
            index_name=index_name,
            index_definition=index_definition,
            num_partitions=PARTITION_COUNT,
        )


def drop_advisor_inventory_host_indexes(apps, schema_editor):
    for index_name, _index_definition in reversed(PARTITIONED_INDEXES):
        drop_partitioned_table_index(
            table_name=PARENT_TABLE,
            index_name=index_name,
            num_partitions=PARTITION_COUNT,
        )


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ('api', '0001_squashed_0045_remove_dailyhitgroup'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql=CREATE_TABLE_SQL,
                    reverse_sql=f'DROP TABLE IF EXISTS {PARENT_TABLE} CASCADE;',
                ),
                migrations.RunPython(
                    create_advisor_inventory_host_indexes,
                    drop_advisor_inventory_host_indexes,
                ),
            ],
            state_operations=[
                migrations.CreateModel(
                    name='AdvisorInventoryHost',
                    fields=[
                        ('pk', models.CompositePrimaryKey('org_id', 'inventory_id', blank=True, editable=False, primary_key=True, serialize=False)),
                        ('inventory_id', models.UUIDField()),
                        ('account', models.CharField(blank=True, max_length=10, null=True)),
                        ('org_id', models.CharField(max_length=50)),
                        ('display_name', models.CharField(max_length=200)),
                        ('tags', models.JSONField()),
                        ('workspace_id', models.UUIDField(null=True)),
                        ('workspace_name', models.CharField(blank=True, max_length=200, null=True)),
                        ('updated', models.DateTimeField()),
                        ('created', models.DateTimeField()),
                        ('last_check_in', models.DateTimeField()),
                        ('stale_timestamp', models.DateTimeField()),
                        ('insights_id', models.UUIDField()),
                        ('reporter', models.CharField(default='puptoo', max_length=200)),
                        ('per_reporter_staleness', models.JSONField(default=dict)),
                        ('os_name', models.CharField(blank=True, max_length=50, null=True)),
                        ('os_major', models.IntegerField(null=True)),
                        ('os_minor', models.IntegerField(null=True)),
                        ('host_type', models.CharField(blank=True, max_length=50, null=True)),
                        ('bootc_booted_image', models.CharField(blank=True, max_length=512, null=True)),
                        ('bootc_booted_image_digest', models.CharField(blank=True, max_length=256, null=True)),
                        ('owner_id', models.UUIDField(null=True)),
                        ('rhc_client_id', models.UUIDField(null=True)),
                        ('workloads', models.JSONField(default=dict)),
                        ('system_update_method', models.CharField(blank=True, max_length=50, null=True)),
                    ],
                    options={
                        'db_table': PARENT_TABLE,
                    },
                    bases=(django_prometheus.models.ExportModelOperationsMixin('advisorinventoryhost'), models.Model),
                ),
            ],
        ),
    ]
