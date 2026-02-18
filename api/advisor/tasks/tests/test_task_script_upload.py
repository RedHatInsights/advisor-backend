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
from django.test import TestCase

from django.conf import settings
from tasks.management.commands.tasks_service import handle_script_job_updates
from tasks.models import Job, JobStatusChoices, ExecutedTaskStatusChoices
from tasks.tests import constants


def ingress_kafka_message():
    return {
        "account": "1234567",
        "org_id": "9876543",
        "category": "payload",
        "content_type": "application/vnd.redhat.tasks.payload+tgz",
        "request_id": "11111111-1111-1111-1111-111111111111",
        "principal": "9876543",
        "service": "tasks",
        "size": "1337",
        "url": "http://s3bucket/file.tar.gz",
        "id": "",
        "b64_identity": "",
        "timestamp": "2023-09-07 02:24:46Z",
        "metadata": ""
    }


def script_worker_message():
    return {
        'stdout': """
        stdout line 1
        stdout line 2
        ### JSON START ###
        {
          "alert": false,
          "message": "No issues found.",
          "report": "text output",
          "report_json": { "data": "structured data#" },
          "error": false
        }
        ### JSON END ###
        """,
        'correlation_id': constants.job_5_run_id
    }


class TaskJobUpdateScriptUploadTestCase(TestCase):
    fixtures = ['basic_task_test_data']

    @responses.activate
    def test_job_update_script_upload(self):
        message = script_worker_message()
        responses.get(
            'http://s3bucket/file.tar.gz',
            status=200,
            json=message
        )

        handle_script_job_updates(settings.WEBHOOKS_TOPIC, ingress_kafka_message())

        self.assertEqual(len(responses.calls), 1)
        job = Job.objects.get(run_id=message['correlation_id'])

        self.assertEqual(job.status, JobStatusChoices.SUCCESS)
        self.assertEqual(job.executed_task.status, ExecutedTaskStatusChoices.COMPLETED)
        self.assertEqual(job.stdout, message['stdout'])
        results = job.results
        self.assertEqual(results['alert'], False)
        self.assertEqual(results['message'], 'No issues found.')
        self.assertEqual(results['report'], 'text output')
        self.assertEqual(results['report_json'], {"data": "structured data#"})
        self.assertEqual(results['error'], False)

    @responses.activate
    def test_job_update_script_upload_failure(self):
        message = script_worker_message()
        message['stdout'] = """
        ### JSON START ###
        {
          "error": true
        }
        ### JSON END ###
        """
        responses.get(
            'http://s3bucket/file.tar.gz',
            status=200,
            json=message
        )

        handle_script_job_updates(settings.WEBHOOKS_TOPIC, ingress_kafka_message())

        self.assertEqual(len(responses.calls), 1)
        job = Job.objects.get(run_id=message['correlation_id'])

        self.assertEqual(job.status, JobStatusChoices.SUCCESS)
        self.assertEqual(job.executed_task.status, ExecutedTaskStatusChoices.COMPLETED)
        results = job.results
        self.assertEqual(results['error'], True)

    @responses.activate
    def test_job_update_script_upload_parse_fail(self):
        message = script_worker_message()
        message['stdout'] = ""  # Blank stdout because of some error on the rhc worker
        responses.get(
            'http://s3bucket/file.tar.gz',
            status=200,
            json=message
        )

        handle_script_job_updates(settings.WEBHOOKS_TOPIC, ingress_kafka_message())

        self.assertEqual(len(responses.calls), 1)
        job = Job.objects.get(run_id=message['correlation_id'])

        self.assertEqual(job.status, JobStatusChoices.FAILURE)
        self.assertEqual(job.executed_task.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        results = job.results
        self.assertEqual(results['error'], True)

    @responses.activate
    def test_job_update_script_upload_missing_alert_flag(self):
        message = script_worker_message()
        message['stdout'] = (
            message['stdout']
            .replace('"alert": false,', '')
            .replace('"error": false', '"error": true')
            .replace('"message": "No issues found."', '"message": "Found X, Conversion cannot proceed."')
        )
        responses.get(
            'http://s3bucket/file.tar.gz',
            status=200,
            json=message
        )

        handle_script_job_updates(settings.WEBHOOKS_TOPIC, ingress_kafka_message())

        self.assertEqual(len(responses.calls), 1)
        job = Job.objects.get(run_id=message['correlation_id'])

        self.assertEqual(job.status, JobStatusChoices.SUCCESS)
        self.assertEqual(job.executed_task.status, ExecutedTaskStatusChoices.COMPLETED)
        results = job.results
        self.assertEqual(results['error'], True)
        self.assertEqual(results['alert'], True)  # caused by error=True and no alert field
        self.assertEqual(results['message'], 'Found X, Conversion cannot proceed.')
        self.assertEqual(results['report'], 'text output')
        self.assertEqual(results['report_json'], {"data": "structured data#"})

    @responses.activate
    def test_job_update_script_upload_completed_with_alert_true(self):
        message = script_worker_message()
        message['stdout'] = (
            message['stdout']
            .replace('"alert": false,', '"alert": true,')
            .replace('"message": "No issues found."', '"message": "Found X, Conversion cannot proceed."')
        )
        responses.get(
            'http://s3bucket/file.tar.gz',
            status=200,
            json=message
        )

        handle_script_job_updates(settings.WEBHOOKS_TOPIC, ingress_kafka_message())

        self.assertEqual(len(responses.calls), 1)
        job = Job.objects.get(run_id=message['correlation_id'])

        # Job status is success because the worker completed the job.
        self.assertEqual(job.status, JobStatusChoices.SUCCESS)
        self.assertEqual(job.executed_task.status, ExecutedTaskStatusChoices.COMPLETED)
        results = job.results
        self.assertEqual(results['error'], False)
        self.assertEqual(results['alert'], True)
        self.assertEqual(results['message'], 'Found X, Conversion cannot proceed.')
        self.assertEqual(results['report'], 'text output')
        self.assertEqual(results['report_json'], {"data": "structured data#"})
