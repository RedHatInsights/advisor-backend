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
from django.test import TestCase
import splunk_logger

TEST_SPLUNK_URL = 'http://localhost/'


class SplunkTestCase(TestCase):

    @responses.activate
    def test_splunk_body_format(self):
        responses.add(
            responses.POST, TEST_SPLUNK_URL,
            status=200
        )
        with self.settings(SPLUNK_URL=TEST_SPLUNK_URL, SPLUNK_TOKEN='0000', ENABLE_SPLUNK_HEC=True):
            splunk_logger.log("Test Message", account='123456')

        self.assertEqual(len(responses.calls), 1)
        request = responses.calls[0].request
        body = json.loads(request.body)
        headers = request.headers
        self.assertEqual(headers['Authorization'], 'Splunk 0000')
        self.assertEqual(body['index'], 'rh_insights_tasks')
        self.assertEqual(body['source'], 'insights-tasks.log')
        self.assertEqual(body['sourcetype'], '_json')
        self.assertIsNotNone(body['host'])

        event = json.loads(body['event'])
        self.assertEqual(event['message'], 'Test Message')
        self.assertEqual(event['account'], '123456')
        self.assertIsNotNone(event['timestamp'])
        self.assertIsNotNone(event['namespace'])
