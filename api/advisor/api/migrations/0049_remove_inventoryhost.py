from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Remove InventoryHost from Django state and replace Host.inventory with a
    UUID primary key mapped to the existing system_uuid column.

    Database operations are empty so api_host.system_uuid is preserved.
    """

    dependencies = [
        ('api', '0048_advisorinventoryhost_sat_compat_fields'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(
                    model_name='host',
                    name='inventory',
                ),
                migrations.AddField(
                    model_name='host',
                    name='inventory_id',
                    field=models.UUIDField(
                        primary_key=True,
                        serialize=False,
                        db_column='system_uuid',
                    ),
                ),
                migrations.DeleteModel(
                    name='InventoryHost',
                ),
            ],
            database_operations=[],
        ),
    ]
