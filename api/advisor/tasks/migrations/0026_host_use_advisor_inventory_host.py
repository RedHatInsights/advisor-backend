from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tasks', '0025_host_remove_stale_warning_culled_timestamps'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='host',
            table='advisor_inventory_host',
        ),
        migrations.RemoveField(
            model_name='host',
            name='system_profile',
        ),
        migrations.RemoveField(
            model_name='host',
            name='id',
        ),
        migrations.AddField(
            model_name='host',
            name='pk',
            field=models.CompositePrimaryKey('org_id', 'inventory_id'),
        ),
        migrations.AddField(
            model_name='host',
            name='inventory_id',
            field=models.UUIDField(default=None),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='host',
            name='os_name',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='os_major',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='os_minor',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='host_type',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='bootc_booted_image',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='bootc_booted_image_digest',
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='rhc_client_id',
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='workloads',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='host',
            name='system_update_method',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='workspace_id',
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(
            model_name='host',
            name='workspace_name',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
