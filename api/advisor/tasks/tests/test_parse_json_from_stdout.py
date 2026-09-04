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

from django.test import TestCase

from tasks.management.commands.tasks_service import parse_json_from_stdout
from tasks.models import Job, JobStatusChoices, TaskTypeChoices


def make_playbook_stdout(separator):
    # Remember, '"task_results": {' is the start so last } absorbed.
    return '{"task_results": {\n    "foo": "bar"\n}\n}' + separator + 'PLAY RECAP *********'


class TaskJobUpdateTestCase(TestCase):
    fixtures = ['basic_task_test_data']

    def test_parse_playbook_different_line_endings(self):
        """
        We seem to get a variety of different line endings, particularly
        around the line endings between the final } and the PLAY RECAP.  Make
        sure we can successfully deal with all the different versions.
        """
        job = Job.objects.get(id=1)

        for separator in ('\n', '\r\n', '\r\r\n', '\n\r\n', '\r\n\n', '\r\n\r\n'):
            stdout = make_playbook_stdout(separator)
            parse_json_from_stdout(job, stdout, TaskTypeChoices.ANSIBLE)
            job.refresh_from_db()
            # Parsing adds alert status in if not found
            self.assertEqual(job.results, {'alert': False, 'foo': 'bar'})
            self.assertEqual(job.status, JobStatusChoices.SUCCESS)
