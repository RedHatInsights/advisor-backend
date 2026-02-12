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

import json
import responses
from datetime import timedelta
import uuid

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from tasks.models import Task, ExecutedTask, Job, Host
from api.tests import update_stale_dates
from api.permissions import auth_header_for_testing
from tasks.tests import constants
from tasks.views.executed_task import extask_sort_fields


PLAYBOOK_DISPATCHER_URL = "http://localhost/internal/v2/dispatch"


class ExecutedTaskViewTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    std_auth = auth_header_for_testing(user_opts={'is_org_admin': True})

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()
        responses.add(
            responses.POST, 'http://localhost/splunk',
            status=200
        )

    def test_executed_task_list(self):
        # no auth, no access
        res = self.client.get(reverse('tasks-executedtask-list'))
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-executedtask-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        page = res.json()
        self.assertIsInstance(page, dict)
        self.assertIn('links', page)
        self.assertIsInstance(page['links'], dict)
        self.assertIn('meta', page)
        self.assertIsInstance(page['meta'], dict)
        self.assertIn('count', page['meta'])
        self.assertEqual(page['meta']['count'], 4)
        self.assertIn('data', page)
        data = page['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), page['meta']['count'])
        # Check one item's details
        self.assertIsInstance(data[0], dict)
        self.assertIn('id', data[0])
        self.assertEqual(data[0]['id'], constants.executed_task_id)
        self.assertIn('name', data[0])
        self.assertEqual(data[0]['name'], constants.executed_task_name)
        self.assertIn('task_slug', data[0])
        self.assertEqual(data[0]['task_slug'], constants.task_slug)
        self.assertIn('task_title', data[0])
        self.assertEqual(data[0]['task_title'], constants.task_title)
        self.assertIn('task_description', data[0])
        self.assertEqual(data[0]['task_description'], constants.task_description)
        self.assertIn('task_filter_message', data[0])
        self.assertEqual(data[0]['task_filter_message'], None)
        self.assertIn('initiated_by', data[0])
        self.assertEqual(data[0]['initiated_by'], constants.test_user)
        self.assertIn('start_time', data[0])
        self.assertEqual(data[0]['start_time'], constants.executed_task_start_time)
        self.assertIn('end_time', data[0])
        self.assertIsNone(data[0]['end_time'])
        self.assertIn('status', data[0])
        self.assertEqual(data[0]['status'], constants.status_running)
        self.assertIn('systems_count', data[0])
        self.assertEqual(data[0]['systems_count'], 3)
        self.assertIn('running_jobs_count', data[0])
        self.assertEqual(data[0]['running_jobs_count'], 1)
        self.assertIn('completed_jobs_count', data[0])
        self.assertEqual(data[0]['completed_jobs_count'], 1)
        self.assertIn('failure_jobs_count', data[0])
        self.assertEqual(data[0]['failure_jobs_count'], 1)
        self.assertIn('timeout_jobs_count', data[0])
        self.assertEqual(data[0]['timeout_jobs_count'], 0)
        # Check other fields for difference
        self.assertEqual(data[1]['id'], constants.completed_task_id)
        self.assertEqual(data[1]['task_slug'], constants.task_slug)
        self.assertEqual(data[1]['running_jobs_count'], 0)
        self.assertEqual(data[1]['completed_jobs_count'], 2)
        self.assertEqual(data[1]['failure_jobs_count'], 1)
        self.assertEqual(data[1]['timeout_jobs_count'], 0)
        self.assertEqual(data[2]['id'], constants.executed_task_parameters_id)
        self.assertEqual(data[2]['task_slug'], constants.parameters_task_slug)
        self.assertEqual(data[2]['task_filter_message'], constants.parameters_task_filter_message)
        self.assertEqual(data[3]['id'], constants.bash_executed_task_id)
        self.assertEqual(data[3]['task_slug'], constants.bash_task_slug)

    def test_executed_task_detail_parameters_ordered_by_index(self):
        # Parameters of executed tasks should be ordered by their index
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_parameters_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        for i, parameter in enumerate(res.json()['parameters']):
            self.assertEqual(parameter['index'], i + 1)

    def test_executed_task_list_filter(self):
        # Assume everything mainly works as above, just test the filtering
        # text filtering
        res = self.client.get(
            reverse('tasks-executedtask-list'),
            data={'text': 'leap'},  # no matches
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 0)
        res = self.client.get(
            reverse('tasks-executedtask-list'),
            data={'text': 'bash'},  # new script task match
            **self.std_auth
        )
        data = res.json()['data']
        self.assertEqual(res.status_code, 200, res.content.decode())
        self.assertEqual(data[0]['task_slug'], constants.bash_task_slug)
        self.assertEqual(len(data), 1)

        res = self.client.get(
            reverse('tasks-executedtask-list'),
            data={'text': 'My Named Task for Log4Shell vulnerability detection'},  # one match
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 1)

        # status filtering
        res = self.client.get(
            reverse('tasks-executedtask-list'),
            data={'status': constants.status_cancelled},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 0)

    def test_executed_task_list_sort(self):
        # Assume everything mainly works as above, just test the sorting
        res = self.client.get(
            reverse('tasks-executedtask-list'),
            data={'sort': 'status'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 4, data)
        self.assertEqual(data[0]['id'], constants.executed_task_id)
        self.assertEqual(data[0]['task_slug'], constants.task_slug)
        self.assertEqual(data[1]['id'], constants.bash_executed_task_id)
        self.assertEqual(data[1]['task_slug'], constants.bash_task_slug)
        self.assertEqual(data[2]['id'], constants.completed_task_id)
        self.assertEqual(data[2]['task_slug'], constants.task_slug)
        self.assertEqual(data[3]['id'], constants.executed_task_parameters_id)
        self.assertEqual(data[3]['task_slug'], constants.parameters_task_slug)

        res = self.client.get(
            reverse('tasks-executedtask-list'),
            data={'sort': '-start_time'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 4, data)
        self.assertEqual(data[0]['id'], constants.bash_executed_task_id)
        self.assertEqual(data[0]['task_slug'], constants.bash_task_slug)
        self.assertEqual(data[1]['id'], constants.executed_task_parameters_id)
        self.assertEqual(data[1]['task_slug'], constants.parameters_task_slug)
        self.assertEqual(data[2]['id'], constants.completed_task_id)
        self.assertEqual(data[2]['task_slug'], constants.task_slug)
        self.assertEqual(data[3]['id'], constants.executed_task_id)
        self.assertEqual(data[3]['task_slug'], constants.task_slug)

        # Test that all fields and directions are handled correctly
        for sort_field in extask_sort_fields:
            for direction in ('', '-'):
                res = self.client.get(
                    reverse('tasks-executedtask-list'),
                    data={'sort': direction + sort_field},
                    **self.std_auth
                )
                self.assertEqual(res.status_code, 200, res.content.decode())

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_cancel(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/cancel', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 204, 'run_id': '00112233-4455-6677-8899-52554E494401'},
                {'code': 204, 'run_id': '00112233-4455-6677-8899-52554E494404'},
            ]
        )
        # no auth, no access
        res = self.client.post(
            reverse('tasks-executedtask-cancel', kwargs={'id': constants.executed_task_id})
        )
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.post(
            reverse('tasks-executedtask-cancel', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertEqual(data['id'], constants.executed_task_id)
        self.assertIn('status', data)
        self.assertEqual(data['status'], constants.status_cancelled)
        # extask in wrong org?  not known
        res = self.client.post(
            reverse('tasks-executedtask-cancel', kwargs={'id': constants.executed_task_id_org_2}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

    def test_executed_task_detail(self):
        # no auth, no access
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id})
        )
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertEqual(data['id'], constants.executed_task_id)
        self.assertIn('name', data)
        self.assertEqual(data['name'], constants.executed_task_name)
        self.assertIn('task_slug', data)
        self.assertEqual(data['task_slug'], constants.task_slug)
        self.assertIn('task_title', data)
        self.assertEqual(data['task_title'], constants.task_title)
        self.assertIn('task_description', data)
        self.assertEqual(data['task_description'], constants.task_description)
        self.assertIn('task_filter_message', data)
        self.assertEqual(data['task_filter_message'], None)
        self.assertIn('initiated_by', data)
        self.assertEqual(data['initiated_by'], constants.test_user)
        self.assertIn('start_time', data)
        self.assertEqual(data['start_time'], constants.executed_task_start_time)
        self.assertIn('end_time', data)
        self.assertIsNone(data['end_time'])
        self.assertIn('status', data)
        self.assertEqual(data['status'], constants.status_running)
        self.assertEqual(data['systems_count'], 3)
        self.assertIn('jobs', data)
        self.assertIsInstance(data['jobs'], list)
        self.assertEqual(len(data['jobs']), 3)
        self.assertEqual(data['jobs'][0]['status'], constants.status_running)
        self.assertEqual(data['jobs'][1]['status'], constants.status_success)
        self.assertEqual(data['jobs'][2]['status'], constants.status_failure)
        # extask in wrong org?  not known
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id_org_2}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

        # Executed task with a filter message
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_parameters_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['task_slug'], constants.parameters_task_slug)
        self.assertEqual(data['task_filter_message'], constants.parameters_task_filter_message)

        const_parameters = getattr(constants, 'parameters')
        # Check that parameters contain all the needed attributes
        for attribute in const_parameters[1].keys():
            self.assertIn(attribute, data['parameters'][0])

        # Check that the parameters are in the correct order
        for i, parameter in enumerate(data['parameters']):
            constant_id = list(const_parameters.keys())[i]
            self.assertEqual(parameter['id'], constant_id)

            for attribute in const_parameters[1].keys():
                self.assertEqual(parameter[attribute], const_parameters[constant_id][attribute],
                                 f"On index {i + 1} the parameter's attribute {attribute} does not match")

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 201, 'id': constants.job_1_run_id},
                {'code': 201, 'id': constants.job_2_run_id},
                {'code': 201, 'id': constants.job_3_run_id},
            ]
        )
        # no auth, no access
        res = self.client.post(reverse('tasks-executedtask-list'))
        self.assertEqual(res.status_code, 403)
        # fail on no data
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        # Should we check what errors we get back here?
        # Fail on task not found
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': 'missing-task', 'hosts': [constants.host_01_uuid]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'task': ["Task with slug 'missing-task' not found"]}
        )
        # Fail on invalid host
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': ["Fee fie foe fom, Oh my god - FACOM!"]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'hosts': {'0': ["Must be a valid UUID."]}}
        )
        # Fail on host not found
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [constants.job_1_run_id]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'hosts': {'0': [f"Host with UUID '{constants.job_1_run_id}' not found"]}}
        )
        # Fail on host not in this org
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [constants.host_02_uuid]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'hosts': {'0': [f"Host with UUID '{constants.host_02_uuid}' not found"]}}
        )
        # Fail on no hosts
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': []},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'hosts': ['Task must be run on at least one host']}
        )
        # Task and hosts good, let's create something!
        # Host 1 = direct connected, Host 4 = Satellite (3) connected
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'name': constants.executed_task_name, 'task': constants.task_slug,
                  'hosts': [
                                constants.host_01_uuid,  # direct connect
                                constants.host_03_uuid,  # direct connect
                                constants.host_04_uuid   # satellite connect
                            ]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)  # Value not reliable, depends on test data...
        self.assertIn('name', data)
        self.assertEqual(data['name'], constants.executed_task_name)
        self.assertIn('task_slug', data)
        self.assertEqual(data['task_slug'], constants.task_slug)
        self.assertIn('task_title', data)
        self.assertEqual(data['task_title'], constants.task_title)
        self.assertIn('initiated_by', data)
        self.assertEqual(data['initiated_by'], constants.test_user)
        self.assertIn('start_time', data)
        # Hack for not quite knowing when this task was created
        self.assertGreater(data['start_time'], str(timezone.now() - timedelta(minutes=1)))
        self.assertIn('end_time', data)
        self.assertIsNone(data['end_time'])
        self.assertIn('status', data)
        self.assertEqual(data['status'], constants.status_running)
        self.assertIn('jobs', data)
        self.assertIsInstance(data['jobs'], list)
        self.assertIsInstance(data['jobs'][0], dict)
        self.assertIn('system_id', data['jobs'][0])
        self.assertEqual(data['jobs'][0]['system_id'], constants.host_01_uuid)
        self.assertEqual(data['jobs'][1]['system_id'], constants.host_03_uuid)
        self.assertEqual(data['jobs'][2]['system_id'], constants.host_04_uuid)
        self.assertEqual(len(data['jobs']), 3)
        # Check that the data passed in was for the 'right' recipients:
        self.assertEqual(len(responses.calls), 1)
        # Decode the raw list to as a dict based on recipient, for comparison
        recipients = {
            run_item['recipient']: run_item
            for run_item in json.loads(responses.calls[0].request.body)
        }
        self.assertEqual(
            recipients[constants.host_01_clid], {
                "recipient": constants.host_01_clid,
                "org_id": constants.standard_org,
                "url": "https://cert.console.stage.redhat.com/api/tasks/v1/task/log4shell/playbook",
                "principal": constants.test_user,
                "name": "Log4Shell vulnerability detection",
            }
        )
        self.assertEqual(
            recipients[constants.host_03_clid], {
                "recipient": constants.host_03_clid,
                "org_id": constants.standard_org,
                "url": "https://cert.console.stage.redhat.com/api/tasks/v1/task/log4shell/playbook",
                "principal": constants.test_user,
                "name": "Log4Shell vulnerability detection",
            }
        )
        self.assertEqual(
            recipients[constants.host_04_recip], {
                "recipient": constants.host_04_recip,
                "org_id": constants.standard_org,
                "url": "https://cert.console.stage.redhat.com/api/tasks/v1/task/log4shell/playbook",
                "principal": constants.test_user,
                "name": "Log4Shell vulnerability detection",
                "recipient_config": {
                    "sat_id": constants.host_04_satid,
                    "sat_org_id": "1"
                },
                "hosts": [
                    {"inventory_id": constants.host_04_uuid}
                ]
            }
        )
        self.assertEqual(len(recipients), 3)

        # Also check that the jobs were given the run IDs our fake playbook
        # dispatcher gave them
        job1 = Job.objects.get(executed_task_id=data['id'], system_id=constants.host_01_uuid)
        self.assertEqual(job1.run_id, uuid.UUID(constants.job_1_run_id))
        job2 = Job.objects.get(executed_task_id=data['id'], system_id=constants.host_03_uuid)
        self.assertEqual(job2.run_id, uuid.UUID(constants.job_2_run_id))
        self.assertTrue(job1.executed_task.is_org_admin)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL, SPLUNK_URL='http://localhost/splunk', ENABLE_SPLUNK_HEC=True)
    @responses.activate
    def test_executed_task_create_logs_to_splunk(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            json=[
                {'code': 201, 'id': constants.job_1_run_id},
            ]
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [
                constants.host_01_uuid,
            ]},
            content_type='application/json', **{'HTTP_X_FORWARDED_FOR': '127.0.0.1', **self.std_auth}
        )
        self.assertEqual(res.status_code, 201)
        request = responses.calls[0].request
        body = json.loads(request.body)
        event = json.loads(body['event'])
        self.assertEqual(event['message'], 'Insights Tasks Execution')
        self.assertEqual(event['org_id'], '9876543')
        self.assertEqual(event['user'], 'testing')
        self.assertEqual(event['ip_address'], '127.0.0.1')
        self.assertEqual(event['task'], 'Log4Shell vulnerability detection')
        self.assertEqual(event['hosts'], ['00112233-4455-6677-8899-012345678901'])
        self.assertEqual(event['script_hash'], '6985cd14d87fde4f4cc2389db56ece1f2034ddfeb1b37a3a03467cad72a82034')

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_error(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=400,
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [constants.host_01_uuid]},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 400)

    @override_settings(CLOUD_CONNECTOR_HOST='localhost', CLOUD_CONNECTOR_PORT='8080')
    @responses.activate
    def test_executed_task_create_bash(self):
        responses.post(
            'http://localhost:8080/api/cloud-connector/v2/connections/00112233-4455-6677-8899-cccccccccc01/message',
            status=201,
            json={'id': str(uuid.UUID(int=0))}  # This return id isn't used
        )

        responses.post(
            'http://localhost:8080/api/cloud-connector/v2/connections/00112233-4455-6677-8899-cccccccccc03/message',
            status=201,
            json={'id': str(uuid.UUID(int=0))}  # This return id isn't used
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'name': constants.executed_task_name, 'task': constants.bash_task_slug,
                  'hosts': [
                                constants.host_01_uuid,  # direct connect
                                constants.host_03_uuid,
                            ]},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)  # Value not reliable, depends on test data...
        self.assertIn('name', data)
        self.assertEqual(data['name'], constants.executed_task_name)
        self.assertIn('task_slug', data)
        self.assertEqual(data['task_slug'], constants.bash_task_slug)
        self.assertIn('task_title', data)
        self.assertEqual(data['task_title'], 'Bash Task Title')
        # Check that the data passed in was for the 'right' recipients:
        self.assertEqual(len(responses.calls), 2)
        for call in responses.calls:
            cloud_connector_payload = json.loads(call.request.body)
            self.assertIsInstance(cloud_connector_payload['metadata'], dict)
            run_id = cloud_connector_payload['metadata']['correlation_id']
            self.assertEqual(cloud_connector_payload['payload'], 'https://cert.console.stage.redhat.com/api/tasks/v1/task/bash-script/playbook')
            self.assertEqual(cloud_connector_payload['directive'], 'rhc-worker-script')
            self.assertIsNotNone(run_id)
            self.assertEqual(cloud_connector_payload['metadata']['return_url'], 'https://cert.console.stage.redhat.com/api/ingress/v1/upload')
            job = Job.objects.get(executed_task_id=data['id'], run_id=run_id)
            self.assertEqual(job.status, 1)  # Running status

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_with_parameters(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 201, 'id': constants.job_4_run_id},
            ]
        )
        # ... should we also do responses.get(the task's playbook URL) and
        # check that if we request that URL with the token that was generated
        # for this run, we got the correct parameters set in the playbook?

        # Just tests that parameter creation and validation happens correctly.
        # First part: bulk all-or-nothing parameter tests
        # For this, there are required parameters with no default, so if we
        # don't supply any we get an error...
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [
                "Parameter 'organisation_id' requires a value"
            ]}
        )
        # If we supply optional parameters but not required parameters, we
        # get an error...
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'extra_repositories', 'value': 'true'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [
                "Parameter 'organisation_id' requires a value"
            ]}
        )
        # If we supply optional parameters and some required parameters but
        # not the one for which there is no default, we get an error...
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'extra_repositories', 'value': 'true'},
                    {'key': 'has_internet_access', 'value': 'false'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [
                "Parameter 'organisation_id' requires a value"
            ]}
        )
        # Even if we supply the required parameter with no default, if we
        # supply an unrecognised parameter that's an error...
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'organisation_id', 'value': 'my organisation'},
                    {'key': 'spatulas', 'value': 'infest my wardrobe'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [
                "Parameter 'spatulas' is not a valid parameter for task convert2rhel_check"
            ]}
        )
        # If we supply a parameter twice, even if all the required parameters
        # with no default are supplied, we get an error...
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'organisation_id', 'value': 'my organisation'},
                    {'key': 'organisation_id', 'value': 'another organisation'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [
                "Parameter 'organisation_id' is duplicated"
            ]}
        )
        # Specific parameter structure tests - on the only required parameter
        # with no default.
        # Key and value not supplied
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'name': 'organisation_id', 'data': 'my organisation'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [{
                'key': ['This field is required.'],
                'value': ['This field is required.']
            }]}
        )
        # Value not supplied
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'organisation_id', 'data': 'my organisation'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [{
                'value': ['This field is required.']
            }]}
        )

        # Value not in list
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'organisation_id', 'value': 'my organisation'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(),
            {'parameters': [
                "Supplied value 'my organisation' for parameter 'organisation_id' "
                "needs to be one of ['1248', '1369', '1720']"
            ]}
        )

        # Finally, check that we can actually create a new executed task
        # with the one required parameter supplied
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'organisation_id', 'value': '1720'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertEqual(data['task_slug'], constants.parameters_task_slug)
        self.assertIn('task_title', data)
        self.assertEqual(data['task_title'], constants.parameters_task_title)
        self.assertIn('initiated_by', data)
        self.assertEqual(data['initiated_by'], constants.test_user)
        self.assertIn('start_time', data)
        # Hack for not quite knowing when this task was created
        self.assertGreater(data['start_time'], str(timezone.now() - timedelta(minutes=1)))
        self.assertIn('end_time', data)
        self.assertIsNone(data['end_time'])
        self.assertIn('status', data)
        self.assertEqual(data['status'], constants.status_running)
        self.assertIn('jobs', data)
        self.assertIsInstance(data['jobs'], list)
        self.assertIsInstance(data['jobs'][0], dict)
        self.assertIn('system_id', data['jobs'][0])
        self.assertEqual(data['jobs'][0]['system_id'], constants.host_01_uuid)
        self.assertEqual(len(data['jobs']), 1)
        executed_task_id = data['id']

        # Have to look up the executed task for the token and parameter values,
        # because we don't publish that information (yet) via the API
        new_extask = ExecutedTask.objects.get(id=executed_task_id)
        # Check that the parameters were actually set
        self.assertEqual(new_extask.parameters.count(), 2)
        # parameter required, has default
        self.assertEqual(new_extask.parameters.get(parameter__key=constants.param_3_key).value, constants.param_3_default)
        # parameter required, no default, supplied value
        self.assertEqual(new_extask.parameters.get(parameter__key=constants.param_4_key).value, '1720')

        # Check that the data passed in was for the 'right' recipients:
        self.assertEqual(len(responses.calls), 1)
        call = responses.calls[0]
        dispatcher_payload = json.loads(call.request.body)
        self.assertIsInstance(dispatcher_payload, list)
        self.assertEqual(len(dispatcher_payload), 1)
        dispatch = dispatcher_payload[0]
        self.assertEqual(dispatch['recipient'], constants.host_01_clid)
        self.assertEqual(dispatch['org_id'], constants.standard_org)
        self.assertEqual(dispatch['url'], f"https://cert.console.stage.redhat.com/api/tasks/v1/task/convert2rhel_check/playbook?token={new_extask.token}")
        self.assertEqual(dispatch['principal'], constants.test_user)
        self.assertEqual(dispatch['name'], constants.parameters_task_title)

        # The job should also have been created
        job = Job.objects.get(executed_task_id=executed_task_id, run_id=constants.job_4_run_id)
        self.assertEqual(job.status, 1)  # Running status

        # Checking the actual parameters got inserted into the vars section
        # is left to the task views playbook test, with existing test data...

        # Now check that this new task exists
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertEqual(data['id'], executed_task_id)
        self.assertIn('task_slug', data)
        self.assertEqual(data['task_slug'], constants.parameters_task_slug)
        self.assertIn('task_title', data)
        self.assertEqual(data['task_title'], constants.parameters_task_title)
        self.assertIn('initiated_by', data)
        self.assertEqual(data['initiated_by'], constants.test_user)
        self.assertIn('end_time', data)
        self.assertIsNone(data['end_time'])
        self.assertIn('status', data)
        self.assertEqual(data['status'], constants.status_running)
        self.assertEqual(data['systems_count'], 1)
        self.assertIn('jobs', data)
        self.assertIsInstance(data['jobs'], list)
        self.assertEqual(len(data['jobs']), 1)
        self.assertIsInstance(data['jobs'][0], dict)
        self.assertIn('system_id', data['jobs'][0])
        self.assertEqual(data['jobs'][0]['system_id'], constants.host_01_uuid)
        self.assertEqual(len(data['jobs']), 1)
        self.assertEqual(data['jobs'][0]['status'], constants.status_running)
        # And check its parameters
        self.assertIn('parameters', data)
        self.assertIsInstance(data['parameters'], list)
        self.assertEqual(len(data['parameters']), 2)
        # Current ordering is by index (param_4, param_3)
        self.assertIsInstance(data['parameters'][0], dict)
        self.assertIn('key', data['parameters'][0])
        self.assertEqual(data['parameters'][0]['key'], constants.param_4_key)
        self.assertIn('value', data['parameters'][0])
        self.assertEqual(data['parameters'][0]['value'], '1720')
        self.assertIn('description', data['parameters'][0])
        self.assertEqual(
            data['parameters'][0]['description'],
            new_extask.task.taskparameters.get(key=data['parameters'][0]['key']).description
        )
        self.assertIn('default', data['parameters'][0])
        self.assertEqual(data['parameters'][0]['default'], constants.param_4_default)
        self.assertIn('required', data['parameters'][0])
        self.assertEqual(data['parameters'][0]['required'], constants.param_4_required)
        self.assertIn('multi_valued', data['parameters'][0])
        self.assertEqual(data['parameters'][0]['multi_valued'], False)

        self.assertEqual(data['parameters'][1]['key'], constants.param_3_key)
        # No value set, required, has default, so parameter default
        self.assertEqual(data['parameters'][1]['value'], constants.param_3_default)
        # grovel around inside the extask object to get the task parameter
        self.assertEqual(
            data['parameters'][1]['description'],
            new_extask.task.taskparameters.get(key=data['parameters'][1]['key']).description
        )
        self.assertEqual(data['parameters'][1]['default'], constants.param_3_default)
        self.assertEqual(data['parameters'][1]['required'], constants.param_3_required)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_with_parameters_required_default_none_supplied(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 201, 'id': constants.job_4_run_id},
            ]
        )
        # Check that if we don't post anything, and we only have parameters
        # that are required _AND_ have defaults, then we get those filled in.
        # To do this we have to remove the parameters that are required but
        # _DO_NOT_ have a default.
        param_task = Task.objects.get(slug=constants.parameters_task_slug)
        param_task.taskparameters.filter(required=True, default=None).delete()
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': constants.parameters_task_slug, 'hosts': [constants.host_01_uuid],
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertEqual(data['task_slug'], constants.parameters_task_slug)
        # Parameter should be created from defaults
        self.assertEqual(len(data['parameters']), 1, data['parameters'])
        self.assertEqual(data['parameters'][0]['key'], 'has_internet_access')
        self.assertEqual(data['parameters'][0]['value'], 'true')  # default
        self.assertEqual(data['parameters'][0]['default'], 'true')
        self.assertEqual(data['parameters'][0]['values'], ['true', 'false'])

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': constants.parameters_task_slug, 'hosts': [constants.host_01_uuid],
                'parameters': [{'key': 'has_internet_access', 'value': 'false'}],
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertEqual(data['task_slug'], constants.parameters_task_slug)
        self.assertEqual(len(data['parameters']), 1, data['parameters'])
        self.assertEqual(data['parameters'][0]['key'], 'has_internet_access')
        self.assertEqual(data['parameters'][0]['value'], 'false')  # as supplied
        self.assertEqual(data['parameters'][0]['default'], 'true')
        self.assertEqual(data['parameters'][0]['values'], ['true', 'false'])

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_with_blank_parameter(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 201, 'id': constants.job_4_run_id},
            ]
        )
        # Check that a required parameter cannot be supplied with an empty
        # string
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'organisation_id', 'value': ''}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        self.assertEqual(res.json(),
            {'parameters': [
                "Supplied value '' for parameter 'organisation_id' "
                "needs to be one of ['1248', '1369', '1720']"
            ]}
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'repository_names', 'value': ''},
                    {'key': 'organisation_id', 'value': '1248'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())
        data = res.json()
        self.assertEqual(data['task_slug'], 'convert2rhel_check')
        self.assertEqual(data['parameters'][0]['key'], 'organisation_id')
        self.assertEqual(data['parameters'][0]['value'], '1248')  # supplied value
        self.assertEqual(data['parameters'][0]['multi_valued'], False)
        self.assertEqual(data['parameters'][1]['key'], 'has_internet_access')
        self.assertEqual(data['parameters'][1]['value'], 'true')  # default value
        self.assertEqual(data['parameters'][1]['multi_valued'], False)
        self.assertEqual(data['parameters'][2]['key'], 'repository_names')
        self.assertEqual(data['parameters'][2]['value'], '')  # supplied values
        self.assertEqual(data['parameters'][2]['multi_valued'], True)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_with_multiple_parameters(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            json=[{'code': 201, 'id': constants.job_4_run_id}]
        )
        # Pass multiple valid parameter values
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [
                    {'key': 'repository_names', 'value': 'els,extra'},
                    {'key': 'organisation_id', 'value': '1248'}
                ]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())
        data = res.json()
        self.assertEqual(data['task_slug'], 'convert2rhel_check')
        self.assertEqual(data['parameters'][0]['key'], 'organisation_id')
        self.assertEqual(data['parameters'][0]['value'], '1248')  # supplied value
        self.assertEqual(data['parameters'][0]['multi_valued'], False)
        self.assertEqual(data['parameters'][1]['key'], 'has_internet_access')
        self.assertEqual(data['parameters'][1]['value'], 'true')  # default value
        self.assertEqual(data['parameters'][1]['multi_valued'], False)
        self.assertEqual(data['parameters'][2]['key'], 'repository_names')
        self.assertEqual(data['parameters'][2]['value'], 'els,extra')  # supplied values
        self.assertEqual(data['parameters'][2]['multi_valued'], True)

        # Pass an invalid value for one of the parameter values
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [{'key': 'repository_names', 'value': 'els,extra,invalid'}]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(), {
            'parameters': [
                "Supplied value 'invalid' for parameter 'repository_names' needs "
                "to be one of ['els', 'epel', 'extra', '']"
            ]}
        )
        # Pass multiple invalid values
        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={
                'task': 'convert2rhel_check', 'hosts': [constants.host_01_uuid],
                'parameters': [{'key': 'repository_names', 'value': 'these,are,mostly,wrong,epel'}]
            },
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(), {
            'parameters': [
                "Supplied value 'these' for parameter 'repository_names' needs to be one of ['els', 'epel', 'extra', '']",
                "Supplied value 'are' for parameter 'repository_names' needs to be one of ['els', 'epel', 'extra', '']",
                "Supplied value 'mostly' for parameter 'repository_names' needs to be one of ['els', 'epel', 'extra', '']",
                "Supplied value 'wrong' for parameter 'repository_names' needs to be one of ['els', 'epel', 'extra', '']"
            ]}
        )

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_fifty_systems(self):
        system_count = 50
        original_host = Host.objects.get(id=constants.host_01_uuid)
        # clone the original system 50 times
        for i in range(system_count):
            original_host.pk = uuid.UUID(int=i)
            original_host.save()

        def dispatcher_call_back(request):
            system_batch_count = len(json.loads(request.body))
            if system_batch_count == 0:
                return 500, {}, "Need at least one system"
            return_data = [{'code': 201, 'id': str(uuid.uuid4())} for _ in range(system_batch_count)]
            return 207, {}, json.dumps(return_data)

        responses.add_callback(
            responses.POST,
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch',
            callback=dispatcher_call_back,
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [
                uuid.UUID(int=i) for i in range(system_count)
            ]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertEqual(data['systems_count'], system_count)

    @override_settings(CLOUD_CONNECTOR_HOST='localhost', CLOUD_CONNECTOR_PORT='8080')
    @responses.activate
    def test_executed_task_create_bash_http_error(self):
        responses.post(
            'http://localhost:8080/api/cloud-connector/v2/connections/00112233-4455-6677-8899-cccccccccc01/message',
            status=500,
        )

        responses.post(
            'http://localhost:8080/api/cloud-connector/v2/connections/00112233-4455-6677-8899-cccccccccc03/message',
            status=201,
            json={'id': str(uuid.UUID(int=0))}
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.bash_task_slug, 'hosts': [
                constants.host_01_uuid,  # direct connect
                constants.host_03_uuid,
            ]},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertEqual(len(data['jobs']), 2)
        self.assertEqual(data['jobs'][0]['system_id'], constants.host_01_uuid)
        self.assertEqual(data['jobs'][1]['system_id'], constants.host_03_uuid)
        self.assertEqual(data['jobs'][0]['status'], constants.status_failure)
        self.assertEqual(data['jobs'][1]['status'], constants.status_running)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_disconnected_system(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 201, 'id': '00112233-4455-6677-8899-52554E494401'},
                {'code': 404},  # system disconnected from rhc
                {'code': 201, 'id': '00112233-4455-6677-8899-52554E494405'},
            ]
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [
                constants.host_01_uuid,  # direct connect
                constants.host_03_uuid,  # direct connect
                constants.host_04_uuid   # satellite connect
            ]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)

        jobs = data['jobs']
        self.assertEqual(jobs[0]['status'], constants.status_running)
        self.assertEqual(jobs[1]['status'], constants.status_failure)
        self.assertEqual(jobs[2]['status'], constants.status_running)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_create_all_disconnected(self):
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 404},
                {'code': 404},
                {'code': 404},
            ]
        )

        res = self.client.post(
            reverse('tasks-executedtask-list'),
            data={'task': constants.task_slug, 'hosts': [
                constants.host_01_uuid,  # direct connect
                constants.host_03_uuid,  # direct connect
                constants.host_04_uuid  # satellite connect
            ]},
            content_type='application/json', **self.std_auth
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('end_time', data)
        self.assertIsNotNone(data['end_time'])
        self.assertIn('status', data)
        self.assertEqual(data['status'], constants.status_failure)

        jobs = data['jobs']
        self.assertEqual(jobs[0]['status'], constants.status_failure)
        self.assertEqual(jobs[1]['status'], constants.status_failure)
        self.assertEqual(jobs[2]['status'], constants.status_failure)

    @responses.activate
    def test_executed_task_destroy_completed_task(self):
        # access allowed with auth
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.completed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 204)
        # And now there's no executed tasks to list
        res = self.client.get(
            reverse('tasks-executedtask-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]['id'], constants.executed_task_id)
        self.assertEqual(data[1]['id'], constants.executed_task_parameters_id)
        self.assertEqual(data[2]['id'], constants.bash_executed_task_id)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_destroy(self):
        # Deleting an executed_task that is not completed will cancel the
        # task and its jobs, and so invoke the playbook dispatcher.
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/cancel', status=207,
            # Responses in the order that the systems were given: RUNIDx
            json=[
                {'code': 204, 'run_id': constants.job_1_run_id},
                {'code': 204, 'run_id': constants.job_2_run_id},
            ]
        )
        # no auth, no access
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id})
        )
        self.assertEqual(res.status_code, 403)
        # Delete a completed task
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.completed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 204)
        # And now there's no executed tasks to list
        res = self.client.get(
            reverse('tasks-executedtask-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]['id'], constants.executed_task_id)
        self.assertEqual(data[1]['id'], constants.executed_task_parameters_id)
        self.assertEqual(data[2]['id'], constants.bash_executed_task_id)
        # extask in wrong org?  not known
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id_org_2}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_destroy_bad_playbook_dispatcher(self):
        # Deleting an executed_task that is not completed will cancel the
        # task and its jobs, and so invoke the playbook dispatcher.
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/cancel', status=403,
            body="Missing authentication"
        )
        # access allowed with auth, problem handled internally
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.completed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 204)

    @override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL)
    @responses.activate
    def test_executed_task_destroy_missing_systems(self):
        # Delete the host:
        job = Job.objects.filter(
            executed_task_id=constants.executed_task_id,
        ).order_by('id')[0]
        self.assertEqual(str(job.system_id), constants.host_01_uuid)
        job.system.delete()
        # Deleting an executed_task that is not completed will cancel the
        # task and its jobs, and so invoke the playbook dispatcher.
        responses.post(
            PLAYBOOK_DISPATCHER_URL + '/internal/v2/cancel', status=207,
            # Responses in the order that the systems were given
            json=[
                {'code': 204, 'run_id': constants.job_1_run_id},
                {'code': 204, 'run_id': constants.job_2_run_id},
            ]
        )
        # no auth, no access
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.completed_task_id})
        )
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.delete(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.completed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 204)
        # And now there's only the running executed tasks to list
        res = self.client.get(
            reverse('tasks-executedtask-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]['id'], constants.executed_task_id)
        self.assertEqual(data[1]['id'], constants.executed_task_parameters_id)
        self.assertEqual(data[2]['id'], constants.bash_executed_task_id)

    def test_executed_task_jobs(self):
        # no auth, no access
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id})
        )
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        result = res.json()
        meta = result['meta']
        self.assertEqual(meta['count'], 3)
        data = result['data']
        self.assertIsInstance(data, list)
        self.assertEqual(data[0]['status'], constants.status_running)
        self.assertEqual(data[0]['display_name'], constants.host_01_name)
        self.assertEqual(data[0]['connection_type'], 'direct')
        self.assertEqual(data[1]['status'], constants.status_success)
        self.assertEqual(data[1]['display_name'], constants.host_03_name)
        self.assertEqual(data[1]['connection_type'], 'direct')
        self.assertEqual(data[2]['status'], constants.status_failure)
        self.assertEqual(data[2]['display_name'], constants.host_04_name)
        self.assertEqual(data[2]['connection_type'], 'satellite')
        # jobs for an executed task in a different org gives a 404
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id_org_2}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)
        # jobs for an executed task with a bad ID gets a 404
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': 'undefined'}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

    def test_executed_task_jobs_sort(self):
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'sort': 'os_version'},
            **self.std_auth
        )
        result = res.json()
        data = result['data']
        self.assertEqual(len(data), 3)
        # Just test results of sort.  os_version is the same, so back to id
        self.assertEqual(data[0]['display_name'], constants.host_01_name)
        self.assertEqual(data[1]['display_name'], constants.host_03_name)
        self.assertEqual(data[2]['display_name'], constants.host_04_name)

        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'sort': 'last_seen'},
            **self.std_auth
        )
        result = res.json()
        data = result['data']
        # Just test results of sort.  systems updated order:
        self.assertEqual(data[0]['display_name'], constants.host_03_name)
        self.assertEqual(data[1]['display_name'], constants.host_01_name)
        self.assertEqual(data[2]['display_name'], constants.host_04_name)

        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'sort': 'status'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        result = res.json()
        data = result['data']
        # Just test results of sort.  status order, both running, sort by uuid
        self.assertEqual(data[0]['display_name'], constants.host_01_name)
        self.assertEqual(data[1]['display_name'], constants.host_03_name)
        self.assertEqual(data[2]['display_name'], constants.host_04_name)

    def test_executed_task_jobs_filter(self):
        # Filter by display_name
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'display_name': '03'},
            **self.std_auth
        )
        result = res.json()
        data = result['data']
        self.assertEqual(len(data), 1)
        # Just test results of filter.
        self.assertEqual(data[0]['display_name'], constants.host_03_name)

        # Filter by os version
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'os_version': '7.2'},
            **self.std_auth
        )
        result = res.json()
        data = result['data']
        # None of these systems have that version number - empty list
        self.assertEqual(len(data), 0)

        # Filter by status - found
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'status': constants.status_running},
            **self.std_auth
        )
        result = res.json()
        data = result['data']
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['display_name'], constants.host_01_name)
        # Filter by status - not found
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            data={'status': constants.status_timeout},
            **self.std_auth
        )
        result = res.json()
        data = result['data']
        self.assertEqual(len(data), 0)

    def test_executed_task_jobs_with_deleted_host(self):
        # Delete the host:
        Job.objects.filter(
            executed_task_id=constants.executed_task_id,
        ).order_by('id')[0].system.delete()
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-executedtask-jobs', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        result = res.json()
        meta = result['meta']
        # One system is missing, but both jobs should still show up
        self.assertEqual(meta['count'], 3)
        data = result['data']
        # Job status should be left as is
        self.assertEqual(data[0]['system'], constants.host_01_uuid)
        self.assertEqual(data[0]['status'], constants.status_running)
        # The system fields for the missing system should be blank
        self.assertEqual(data[0]['display_name'], None)
        self.assertEqual(data[0]['connection_type'], 'none')
        # The system fields for the other job should be OK
        self.assertEqual(data[1]['system'], constants.host_03_uuid)
        self.assertEqual(data[1]['status'], constants.status_success)
        self.assertEqual(data[1]['display_name'], constants.host_03_name)
        self.assertEqual(data[1]['connection_type'], 'direct')

    def test_executed_task_job_log(self):
        res = self.client.get(
            reverse('tasks-executedtask-job-logs', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        logs_page = res.json()
        self.assertIn('meta', logs_page)
        self.assertIn('links', logs_page)
        self.assertIn('data', logs_page)
        self.assertIsInstance(logs_page['data'], list)
        prev_date = None
        logs = logs_page['data']
        for log in logs:
            self.assertIn('system_id', log)
            self.assertIn('display_name', log)
            self.assertIn('created_at', log)
            self.assertIn('is_ok', log)
            self.assertIn('line', log)
            self.assertIn('run_id', log)
            if prev_date is not None:
                self.assertLessEqual(prev_date, log['created_at'])
            prev_date = log['created_at']
        self.assertEqual(logs[0]['system_id'], constants.host_01_uuid)
        self.assertEqual(logs[0]['display_name'], constants.host_01_name)
        self.assertEqual(logs[0]['line'], "Job dispatched to Playbook Dispatcher")
        self.assertEqual(logs[0]['run_id'], constants.job_1_run_id)
        # logs for an executed task with a bad ID gets a 404
        res = self.client.get(
            reverse('tasks-executedtask-job-logs', kwargs={'id': 'undefined'}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

    def test_executed_task_job_log_deleted_host(self):
        # Test that if we display logs for a system that's deleted we can
        # still read them.
        Host.objects.get(id=constants.host_03_uuid).delete()
        # And the job logs should still show up
        res = self.client.get(
            reverse('tasks-executedtask-job-logs', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        logs = res.json()['data']
        self.assertEqual(logs[0]['system_id'], constants.host_01_uuid)
        self.assertEqual(logs[0]['display_name'], constants.host_01_name)
        self.assertEqual(logs[0]['line'], "Job dispatched to Playbook Dispatcher")
        self.assertEqual(logs[0]['run_id'], constants.job_1_run_id)
        self.assertEqual(logs[1]['system_id'], constants.host_03_uuid)  # still know it's ID
        self.assertIsNone(logs[1]['display_name'])  # but its host name is no longer there
        self.assertEqual(logs[1]['line'], "Job dispatched to Playbook Dispatcher")
        self.assertEqual(logs[1]['run_id'], constants.job_2_run_id)
