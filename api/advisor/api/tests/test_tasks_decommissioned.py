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

from django.test import Client, TestCase
from django.urls import reverse

from api.permissions import auth_header_for_testing
from api.tests import update_stale_dates
from project_settings import settings


class TasksDecommissionedTestCase(TestCase):
    """
    The Tasks API has been decommissioned (RHINENG-31068 / RHINENG-31069) -
    every method on every Tasks path, public or internal, returns 410 Gone.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data',
    ]
    methods = ('get', 'post', 'put', 'patch', 'delete', 'head', 'options')
    paths = (
        '', 'task', 'task/log4shell', 'task/log4shell/playbook',
        'executed_task', 'executed_task/1', 'executed_task/1/cancel',
        'job', 'job/1', 'job/1/stdout', 'system', 'openapi.json',
    )

    def setUp(self):
        # Enforce CSRF checks, as a real client would get them, to make sure
        # writes get the 410 rather than a CSRF 403.
        self.client = Client(enforce_csrf_checks=True)
        self.headers = auth_header_for_testing()

    def assert_gone(self, url):
        for method in self.methods:
            response = getattr(self.client, method)(url, **self.headers)
            self.assertEqual(response.status_code, 410, f"{method.upper()} {url}")
            if method != 'head':
                self.assertEqual(response.json(), {
                    'detail': 'The Tasks API has been decommissioned.'
                })

    def test_tasks_api_gone(self):
        prefix = '/' + settings.TASKS_PATH_PREFIX
        self.assert_gone(prefix.rstrip('/'))
        for path in self.paths:
            self.assert_gone(prefix + path)

    def test_internal_tasks_api_gone(self):
        prefix = '/internal/' + settings.TASKS_PATH_PREFIX
        self.assert_gone(prefix.rstrip('/'))
        for path in self.paths:
            self.assert_gone(prefix + path)

    def test_advisor_api_unaffected(self):
        update_stale_dates()
        response = self.client.get(reverse('rule-list'), **self.headers)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse('system-list'), **self.headers)
        self.assertEqual(response.status_code, 200)
