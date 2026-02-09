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

import responses

from django.test import TestCase, override_settings
from django.urls import reverse

from api.tests import update_stale_dates
from api.permissions import auth_header_for_testing
from tasks.models import Job, JobStatusChoices, TaskTypeChoices
from tasks.tests import constants
from tasks.management.commands.tasks_service import get_stdout_url


job_stdout = r"""
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [task for leapp pre-upgrade assessment] ***********************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Install Leapp from RHEL 7 Extras] ****************************************
skipping: [localhost]

TASK [Install Leapp on RHEL 8 or later] ****************************************
ok: [localhost]
"""


def json_playbook_dispatcher_partial_reply():
    return {"data": [{"stdout": job_stdout}]}


class JobViewTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    std_auth = auth_header_for_testing()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_job_list(self):
        # no auth, no access
        res = self.client.get(reverse('tasks-job-list'))
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-job-list'),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        # paginated list:
        self.assertIn('meta', data)
        self.assertIn('links', data)
        self.assertIn('data', data)
        page = data['data']
        self.assertIsInstance(page, list)
        # check fields ...
        self.assertEqual(page[0]['id'], constants.job_1_id)
        self.assertEqual(page[0]['executed_task'], constants.executed_task_id)
        self.assertEqual(page[0]['system'], constants.host_01_uuid)
        self.assertEqual(page[0]['display_name'], constants.host_01_name)
        self.assertEqual(page[0]['connection_type'], 'direct')
        self.assertEqual(page[0]['status'], constants.status_running)
        self.assertEqual(page[0]['results'], {})
        self.assertEqual(page[0]['updated_on'], "2022-04-11T04:01:26Z")
        self.assertEqual(page[0]['run_id'], constants.job_1_run_id)
        self.assertEqual(page[1]['id'], constants.job_2_id)
        self.assertEqual(page[1]['run_id'], constants.job_2_run_id)
        self.assertEqual(page[1]['executed_task'], constants.executed_task_id)
        self.assertEqual(page[2]['id'], constants.job_3_id)
        self.assertEqual(page[2]['run_id'], constants.job_3_run_id)
        self.assertEqual(page[2]['executed_task'], constants.completed_task_id)
        self.assertTrue(page[2]['has_stdout'])
        self.assertEqual(page[3]['id'], constants.job_4_id)
        self.assertEqual(page[3]['run_id'], constants.job_4_run_id)
        self.assertEqual(page[3]['executed_task'], constants.completed_task_id)
        self.assertEqual(page[4]['id'], constants.job_5_id)
        self.assertEqual(page[4]['run_id'], constants.job_5_run_id)
        self.assertEqual(page[4]['executed_task'], constants.completed_task_id)
        self.assertEqual(page[5]['id'], constants.job_7_id)
        self.assertEqual(page[5]['run_id'], constants.job_7_run_id)
        self.assertEqual(page[5]['executed_task'], constants.bash_executed_task_id)
        self.assertEqual(page[6]['id'], constants.job_8_id)
        self.assertEqual(page[6]['run_id'], constants.job_8_run_id)
        self.assertEqual(page[6]['executed_task'], constants.executed_task_parameters_id)
        self.assertEqual(page[7]['id'], constants.job_9_id)
        self.assertEqual(page[7]['run_id'], constants.job_9_run_id)
        self.assertEqual(page[7]['executed_task'], constants.executed_task_id)
        self.assertEqual(len(page), 8)

    def test_job_list_bad_param(self):
        res = self.client.get(
            reverse('tasks-job-list'),
            data={'status': '1'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        self.assertIn(
            "The value is required to be one of the following "
            "values: Running, Success, Failure, Timeout, Cancelled",
            res.content.decode()
        )

    def test_job_detail(self):
        res = self.client.get(
            reverse('tasks-job-detail', kwargs={'id': constants.job_1_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        # unpaginated job
        self.assertEqual(data['id'], constants.job_1_id)
        self.assertEqual(data['executed_task'], constants.executed_task_id)
        self.assertEqual(data['system'], constants.host_01_uuid)
        self.assertEqual(data['display_name'], constants.host_01_name)
        self.assertEqual(data['connection_type'], 'direct')
        self.assertEqual(data['status'], constants.status_running)
        self.assertEqual(data['run_id'], constants.job_1_run_id)
        self.assertEqual(data['results'], {})
        self.assertEqual(data['updated_on'], "2022-04-11T04:01:26Z")
        self.assertFalse(data['has_stdout'])
        self.assertTrue(data['log_link'].endswith('/api/tasks/v1/job/1/log'))

    def test_job_detail_check_rhc_client_id(self):
        res = self.client.get(
            reverse('tasks-job-detail', kwargs={'id': constants.job_1_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertEqual(data['rhc_client_id'], constants.job_1_rhc_client_id)

        # checking if rhc client id can returns null
        res = self.client.get(
            reverse('tasks-job-detail', kwargs={'id': constants.job_9_id}),
            **self.std_auth
        )
        data = res.json()
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(data['rhc_client_id'])

    def test_job_log(self):
        res = self.client.get(
            reverse('tasks-job-log', kwargs={'id': constants.job_8_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        # paginated list of log lines:
        self.assertIn('meta', data)
        self.assertIn('links', data)
        self.assertIn('data', data)
        page = data['data']
        self.assertIsInstance(page, list)
        # Test both log lines because why not
        self.assertEqual(page[0]['created_at'], "2023-12-19T22:42:17Z")
        self.assertEqual(page[0]['is_ok'], True)
        self.assertEqual(page[0]['line'], "Job dispatched to Cloud Connector")
        self.assertEqual(page[1]['created_at'], "2023-12-19T22:43:01Z")
        self.assertEqual(page[1]['is_ok'], False)
        self.assertEqual(page[1]['line'], "Job timed out after 3600 seconds")
        self.assertEqual(len(page), 2)

    def test_job_stdout(self):
        # Without Playbook Dispatcher enabled, getting the stdout from a
        # running job is an AttributeError
        with self.assertRaises(AttributeError):
            res = self.client.get(
                reverse('tasks-job-stdout', kwargs={'id': constants.job_1_id}),
                **self.std_auth
            )
        # But getting the stdout from a completed job is fine
        res = self.client.get(
            reverse('tasks-job-stdout', kwargs={'id': constants.job_3_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, 'text/plain')
        self.maxDiff = None
        self.assertEqual(res.content.decode(), r"""
TASK [detect problems]
Detected one error
TASK [print results] *
ok: "task_results": {
    "msg": "{\"message\": \"Vulnerable files found\", \"alert\": true, \"files\": [\"/home/dkuc/Videos/log4j-core-2.0-tests.jar\", \"/home/dkuc/Videos/log4j-core-2.0.jar\"]}"
}
PLAY RECAP *
        """.strip())

    @responses.activate
    @override_settings(PLAYBOOK_DISPATCHER_URL='http://localhost', PDAPI_PSK='test')
    def test_job_live_stdout(self):
        # Make sure this job is running and it normally has no stdout.
        job1 = Job.objects.get(id=1)
        self.assertEqual(job1.stdout, '')
        self.assertEqual(job1.status, JobStatusChoices.RUNNING)
        self.assertEqual(job1.executed_task.task.type, TaskTypeChoices.ANSIBLE)
        # Set up our partial response
        responses.get(
            get_stdout_url(constants.job_1_run_id),
            status=200,
            body=job_stdout
        )
        # Request it from PD
        res = self.client.get(
            reverse('tasks-job-stdout', kwargs={'id': constants.job_1_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        self.assertEqual(res.accepted_media_type, 'text/plain')
        self.assertEqual(res.content.decode(), job_stdout)
