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

from django.db import migrations, models

# Populate all existing executed tasks with their associated task name
populate_executed_tasks_names = """
UPDATE tasks_executedtask et
SET name = (
    SELECT t.title from tasks_task t
    WHERE t.id = et.task_id
)
"""


class Migration(migrations.Migration):

    dependencies = [
        ('tasks', '0008_executed_task_add_token'),
    ]

    operations = [
        # first create the new field
        # it has to be null otherwise we hit integrity issues
        migrations.AddField(
            model_name='executedtask',
            name='name',
            field=models.CharField(max_length=200, null=True),
        ),
        # populate any existing executed tasks with their associated task name
        migrations.RunSQL(populate_executed_tasks_names),
        # alter the name field to be required
        migrations.AlterField(
            model_name='executedtask',
            name='name',
            field=models.CharField(max_length=200),
        ),
    ]
