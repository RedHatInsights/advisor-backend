from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0047_add_workspace_ungrouped_to_advisor_inventory_host'),
    ]

    operations = [
        migrations.AddField(
            model_name='advisorinventoryhost',
            name='infrastructure_type',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='advisorinventoryhost',
            name='bios_release_date',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='advisorinventoryhost',
            name='bios_vendor',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='advisorinventoryhost',
            name='bios_version',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='advisorinventoryhost',
            name='release',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
