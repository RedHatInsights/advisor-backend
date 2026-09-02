from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Drop InventoryHost from Django state and replace Host.inventory (OneToOne
    PK to the Cyndi view) with a UUIDField on the same system_uuid column.

    Database operations are empty: InventoryHost is unmanaged, and altering
    Host.inventory must not emit DROP COLUMN system_uuid.
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
