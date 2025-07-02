# Copyright 2016-2024 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

# Insights Advisor is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# Insights Advisor is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with Insights Advisor. If not, see <https://www.gnu.org/licenses/>.

# Mabulated by hand from pure organic bits by Paul

from django.db import migrations, models


def bash_to_script(apps, schema_editor):
    Task = apps.get_model('tasks', 'Task')
    Task.objects.filter(type='B').update(type='S')


def script_to_bash(apps, schema_editor):
    Task = apps.get_model('tasks', 'Task')
    Task.objects.filter(type='S').update(type='B')


class Migration(migrations.Migration):

    dependencies = [
        ('tasks', '0014_job_add_stdout_field'),
    ]

    operations = [
        migrations.AlterField(
            model_name='task',
            name='type',
            field=models.CharField(choices=[('A', 'Ansible'), ('S', 'Script')], default='A', max_length=1),
        ),
        migrations.RunPython(bash_to_script, script_to_bash),
    ]
