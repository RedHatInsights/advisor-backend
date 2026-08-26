from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tasks', '0026_host_use_advisor_inventory_host'),
    ]

    operations = [
        migrations.AddField(
            model_name='host',
            name='workspace_ungrouped',
            field=models.BooleanField(null=True),
        ),
    ]
