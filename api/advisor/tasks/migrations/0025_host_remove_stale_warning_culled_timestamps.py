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

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('tasks', '0024_taskparameter_default_blank'),
    ]
    operations = [
        # Because the table is (currently) not managed by Django, we don't
        # have to recreate the data in the fields when removing them.  Even
        # if we did, it'd simply be a default to the stale_timestamp plus
        # seven or fourteen days.
        migrations.RemoveField(
            model_name='Host',
            name='stale_warning_timestamp',
        ),
        migrations.RemoveField(
            model_name='Host',
            name='culled_timestamp',
        ),
    ]
