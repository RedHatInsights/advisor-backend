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

import base64
import json

import responses

from django.test import TestCase, override_settings
from django.urls import reverse

from api.kessel import add_kessel_response
from api.permissions import auth_header_for_testing, make_rbac_url
from tasks.tests import constants

TEST_RBAC_URL = 'http://rbac.svc/'
TEST_RBAC_V1_ACCESS = make_rbac_url(
    "access/?application=advisor,tasks,inventory&limit=1000",
    rbac_base=TEST_RBAC_URL
)
TEST_RBAC_V2_WKSPC = make_rbac_url(
    "workspaces/?type=default",
    version=2, rbac_base=TEST_RBAC_URL
)

raw_insights_qa_identity = ''.join("""
eyJlbnRpdGxlbWVudHMiOnsib3BlbnNoaWZ0Ijp
7ImlzX2VudGl0bGVkIjp0cnVlLCJpc190cmlhbCI6ZmFsc2V9LCJyaGVsIjp7ImlzX2VudGl0bGVk
Ijp0cnVlLCJpc190cmlhbCI6ZmFsc2V9LCJyaG9hbSI6eyJpc19lbnRpdGxlZCI6ZmFsc2UsImlzX
3RyaWFsIjpmYWxzZX0sImludGVybmFsIjp7ImlzX2VudGl0bGVkIjp0cnVlLCJpc190cmlhbCI6Zm
Fsc2V9LCJpbnNpZ2h0cyI6eyJpc19lbnRpdGxlZCI6dHJ1ZSwiaXNfdHJpYWwiOmZhbHNlfSwic2V
0dGluZ3MiOnsiaXNfZW50aXRsZWQiOnRydWUsImlzX3RyaWFsIjpmYWxzZX0sInNtYXJ0X21hbmFn
ZW1lbnQiOnsiaXNfZW50aXRsZWQiOnRydWUsImlzX3RyaWFsIjpmYWxzZX0sInVzZXJfcHJlZmVyZ
W5jZXMiOnsiaXNfZW50aXRsZWQiOnRydWUsImlzX3RyaWFsIjpmYWxzZX0sInJob2RzIjp7ImlzX2
VudGl0bGVkIjpmYWxzZSwiaXNfdHJpYWwiOmZhbHNlfSwiYW5zaWJsZSI6eyJpc19lbnRpdGxlZCI
6dHJ1ZSwiaXNfdHJpYWwiOmZhbHNlfSwicmhvc2FrIjp7ImlzX2VudGl0bGVkIjpmYWxzZSwiaXNf
dHJpYWwiOmZhbHNlfSwic3Vic2NyaXB0aW9ucyI6eyJpc19lbnRpdGxlZCI6dHJ1ZSwiaXNfdHJpY
WwiOmZhbHNlfSwiY29zdF9tYW5hZ2VtZW50Ijp7ImlzX2VudGl0bGVkIjp0cnVlLCJpc190cmlhbC
I6ZmFsc2V9LCJtaWdyYXRpb25zIjp7ImlzX2VudGl0bGVkIjp0cnVlLCJpc190cmlhbCI6ZmFsc2V
9fSwiaWRlbnRpdHkiOnsib3JnX2lkIjoiMTE3ODk3NzIiLCJ1c2VyIjp7ImlzX29yZ19hZG1pbiI6
dHJ1ZSwiZmlyc3RfbmFtZSI6Ikluc2lnaHRzIiwibGFzdF9uYW1lIjoiUUEiLCJpc19hY3RpdmUiO
nRydWUsImxvY2FsZSI6ImVuX1VTIiwidXNlcm5hbWUiOiJpbnNpZ2h0cy1xYSIsImVtYWlsIjoiaW
5zaWdodHMtcWUtc3RhZ2Utbm90aWZpY2F0aW9ucytpbnNpZ2h0cy1xYUByZWRoYXQuY29tIiwidXN
lcl9pZCI6IjUxODM0Nzc2IiwiaXNfaW50ZXJuYWwiOnRydWV9LCJpbnRlcm5hbCI6eyJvcmdfaWQi
OiIxMTc4OTc3MiIsImF1dGhfdGltZSI6MCwiY3Jvc3NfYWNjZXNzIjpmYWxzZX0sInR5cGUiOiJVc
2VyIiwiYWNjb3VudF9udW1iZXIiOiI2MDg5NzE5IiwiYXV0aF90eXBlIjoiand0LWF1dGgifX0=
""".splitlines())


class RBACTestCase(TestCase):
    # We don't test RBAC failure modes, nor do we test 'no auth views'.

    def _get_view(self, view_name, auth=True, auth_args={}):
        return self.client.get(
            reverse(view_name),
            **(auth_header_for_testing(user_opts=auth_args) if auth else {})
        )

    @responses.activate
    def test_rbac_basic_allowed(self):
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': [{'permission': 'advisor:*:*'}, {'permission': 'tasks:*:*'}]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in ('tasks-executedtask-list', 'tasks-system-list', 'tasks-task-list'):
                response = self._get_view(view_name, auth_args={'is_org_admin': True})
                request = responses.calls[0].request
                auth_header = json.loads(base64.b64decode(request.headers['x-rh-identity']))
                self.assertIsNotNone(auth_header['identity']['user']['is_org_admin'])
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible with RBAC allowing all"
                )

    @responses.activate
    def test_rbac_basic_allowed_full_response(self):
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={
                "meta": {
                    "count": 1,
                    "limit": 1000,
                    "offset": 0
                },
                "links": {
                    "first": "/api/rbac/v1/access/?application=tasks&limit=1000&offset=0",
                    "next": None,
                    "previous": None,
                    "last": "/api/rbac/v1/access/?application=tasks&limit=1000&offset=0"
                },
                "data": [
                    {
                        "resourceDefinitions": [],
                        "permission": "tasks:*:*"
                    }
                ]
            },
            status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in ('tasks-executedtask-list', 'tasks-system-list', 'tasks-task-list'):
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible with RBAC allowing all"
                )
            for view_name in ('tasks-executedtask-list', 'tasks-system-list', 'tasks-task-list'):
                response = self.client.get(
                    reverse(view_name),
                    **auth_header_for_testing(raw=raw_insights_qa_identity)
                )
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible with RBAC allowing all"
                )

    @responses.activate
    def test_rbac_basic_denied(self):
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': [{'permission': 'advisor:*:*'}]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in ('tasks-executedtask-list', 'tasks-system-list', 'tasks-task-list'):
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should not be visible with RBAC denying tasks access"
                )


class KesselTestCase(TestCase):
    basic_auth_header = auth_header_for_testing()

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True, RBAC_URL=TEST_RBAC_URL)
    @responses.activate
    @add_kessel_response(
        permission_checks=constants.kessel_tasks_rw
    )
    def test_rbac_basic_allowed_full(self):
        responses.add(
            responses.GET, TEST_RBAC_V2_WKSPC,
            json={'data': [{'id': constants.kessel_std_workspace_id}]}
        )

        # Check that we can access the basic views
        reply = self.client.get(reverse('tasks-task-list'), **self.basic_auth_header)
        self.assertEqual(reply.status_code, 200)
        reply = self.client.get(reverse('tasks-system-list'), **self.basic_auth_header)
        self.assertEqual(reply.status_code, 200)
        reply = self.client.get(reverse('tasks-executedtask-list'), **self.basic_auth_header)
        self.assertEqual(reply.status_code, 200)

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True, RBAC_URL=TEST_RBAC_URL)
    @responses.activate
    @add_kessel_response(
        permission_checks=constants.kessel_tasks_ro
    )
    def test_rbac_basic_allowed_read_only(self):
        responses.add(
            responses.GET, TEST_RBAC_V2_WKSPC,
            json={'data': [{'id': constants.kessel_std_workspace_id}]}
        )

        # Check that we can access the basic views
        reply = self.client.get(reverse('tasks-task-list'), **self.basic_auth_header)
        self.assertEqual(reply.status_code, 200)
        reply = self.client.get(reverse('tasks-system-list'), **self.basic_auth_header)
        self.assertEqual(reply.status_code, 200)
        reply = self.client.get(reverse('tasks-executedtask-list'), **self.basic_auth_header)
        self.assertEqual(reply.status_code, 200)
