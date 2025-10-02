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

import csv
from json import loads
import responses

from django.test import TestCase, override_settings
from django.urls import reverse

from api import kessel
# from api.models import sync_kessel_with_model
from api.tests import constants, rbac_data, update_stale_dates
from api.permissions import (
    host_group_attr, auth_header_for_testing,
    find_host_groups, make_rbac_url, request_object_for_testing
)

TEST_RBAC_URL = 'http://rbac.svc'
TEST_RBAC_V1_ACCESS = make_rbac_url(
    "access/?application=advisor,tasks,inventory&limit=1000",
    rbac_base=TEST_RBAC_URL
)
TEST_RBAC_V2_WKSPC = make_rbac_url(
    "workspace/?type=default",
    version=2, rbac_base=TEST_RBAC_URL
)


class HostGroupsTestCase(TestCase):
    """
    We do both specific tests on the find_host_groups function and the views
    that should filter on host groups.  Because this data comes to us via
    RBAC, and that requires heavier infrastructure than the view tests
    currently use, we do those tests here.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _get_view(
        self, view_name, view_kwargs={}, data={}, auth=True, auth_args={}
    ):
        response = self.client.get(
            reverse(
                view_name, kwargs=view_kwargs
            ),
            data=data,
            **(auth_header_for_testing(user_opts=auth_args) if auth else {})
        )

        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, 'application/json')
        return response.json()

    def _get_export_view(self, response):
        """
        Try to check that the response is good, handling both accepted media
        types and both the standard and streaming HTTP response classes.
        """
        self.assertEqual(response.status_code, 200)

        # Get content, either from streaming or regular
        if hasattr(response, 'content'):
            content = response.content.decode()
        elif hasattr(response, 'streaming_content'):
            content = ''.join(s.decode() for s in response.streaming_content)
        else:
            self.Fail("Response object has no content/streaming content")

        # Decode the content, whatever it is
        if hasattr(response, 'accepted_media_type') and response.accepted_media_type == constants.csv_mime:
            csv_data = list(csv.reader(content.splitlines()))
            # Header should be first
            self.assertIsInstance(csv_data[0], list)
            header_list = csv_data[0]
            return [{
                header_list[index]: field
                for index, field in enumerate(row)
            } for row in csv_data[1:]]
        elif 'Content-Type' in response.headers and response.headers['Content-Type'] == constants.json_mime:
            return loads(content)
        else:
            self.Fail(f"Don't know how to decode {response} (headers {response.headers}")

    def assertHostGroupSet(self, role_list, expected_groups):
        """
        Do the actual tests for test_bad_host_group_data
        """
        request = request_object_for_testing()
        find_host_groups(role_list, request)
        if expected_groups is None:
            self.assertFalse(hasattr(request, host_group_attr))
        else:
            self.assertTrue(hasattr(request, host_group_attr))
            self.assertEqual(getattr(request, host_group_attr), expected_groups)

    def test_bad_host_group_data(self):
        """
        find_host_groups includes a number of tests to avoid failure when
        walking through the RBAC permission data.  We need to test those, for
        coverage - but if we go through the 'correct' route we have to invoke
        an authentication class that uses `has_rbac_permission` to make a
        HTTP request to RBAC.  Or we can just munge RBAC-like data into
        `find_host_groups` and check for the `host_group_attr` attribute on
        the attached object, which is much easier.  `find_host_groups` doesn't
        care where the data comes from and it doesn't check any other part of
        the request object.  But we do need to set attributes on it, and a
        request object is the easiest way to set that up.
        """
        # Has no 'permission' key
        self.assertHostGroupSet(
            [{"spatula": "confirmed"}],
            None
        )
        # Has no 'inventory:hosts:read' permission
        self.assertHostGroupSet(
            [{"permission": "advisor:*:read"}],
            None
        )
        # Has a 'inventory:hosts:read' permission with no resource definitions
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {"permission": "inventory:hosts:read"}
            ],
            None
        )
        # Has a 'inventory:hosts:read' permission with a bad resource
        # definitions list
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": "null"
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list that does not contain objects
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": ['foo']
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list with no attribute filter property
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": [
                        {'some other': 'value'}
                    ]
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list with attribute filter property not a dict
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": [
                        {'some other': 'value'},
                        {'attributeFilter': 'removed'}
                    ]
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list with a attribute filter property that is a dict
        # without the 'key' and 'value' properties
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": [
                        {'some other': 'value'},
                        {'attributeFilter': {
                            'operation': 'or'
                        }}
                    ]
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list with a attribute filter property that is a dict
        # with the 'key' and 'value' properties but not keyed to
        # 'group.id'
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": [
                        {'some other': 'value'},
                        {'attributeFilter': {
                            'key': 'inventory.status',
                            'value': 'operational',
                            'operation': 'or'
                        }}
                    ]
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list with a attribute filter property that is a dict
        # with the 'key' and 'value' properties keyed to 'group.id'
        # but where the value is not a list...
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": [
                        {'some other': 'value'},
                        {'attributeFilter': {
                            'key': 'inventory.status',
                            'value': 'operational',
                            'operation': 'or'
                        }},
                        {'attributeFilter': {
                            'key': 'group.id',
                            'value': 'not a list',
                            'operation': 'or'
                        }}
                    ]
                }
            ],
            None
        )

        # Has a 'inventory:hosts:read' permission with a resource
        # definitions list with a attribute filter property that is a dict
        # with the 'key' and 'value' properties keyed to 'group.id'
        # but where the value is a list - yay!
        self.assertHostGroupSet(
            [
                {"permission": "advisor:*:read"},
                {
                    "permission": "inventory:hosts:read",
                    "resourceDefinitions": [
                        {'some other': 'value'},
                        {'attributeFilter': {
                            'key': 'inventory.status',
                            'value': 'operational',
                            'operation': 'or'
                        }},
                        {'attributeFilter': {
                            'key': 'group.id',
                            'value': ['group 1', 'group 2'],
                            'operation': 'or'
                        }}
                    ]
                }
            ],
            ['group 1', 'group 2']
        )

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True)
    @responses.activate
    def test_groups_match(self):
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS, status=200,
            json=rbac_data(groups=[constants.host_group_1_id])
        )
        #
        # sync_kessel_with_model()
        # kessel.client.grant_access_to_org(constants.standard_user_id, "advisor:*:*", [constants.standard_org])
        # kessel.client.grant_access_to_workspace(constants.standard_user_id, "inventory:hosts:read", [constants.host_group_1_id])

        # Rules list - systems counts will change
        page = self._get_view('rule-list')
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['rule_id'], constants.acked_rule)
        self.assertEqual(page['data'][0]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][1]['rule_id'], constants.active_rule)
        self.assertEqual(page['data'][1]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][2]['rule_id'], constants.second_rule)
        self.assertEqual(page['data'][2]['impacted_systems_count'], 0)
        # Systems list
        page = self._get_view('system-list')
        self.assertEqual(page['meta']['count'], 1)  # one system
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)
        # Systems detail - system not in group
        response = self.client.get(
            reverse(
                'system-detail', kwargs={'uuid': constants.host_05_uuid}
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        # Systems detail - system in group
        page = self._get_view(
            'system-detail', view_kwargs={'uuid': constants.host_01_uuid}
        )
        self.assertEqual(page['display_name'], constants.host_01_name)
        # Export views
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['rhel_version'], '7.5')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(len(row_data), 1)
        response = self.client.get(
            reverse('export-systems-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['display_name'], constants.host_01_name)
        self.assertEqual(len(row_data), 1)
        # Stats views
        stats = self._get_view('stats-systems')
        # Systems in account 1234567 in host group 1: system 01
        self.assertEqual(
            stats,
            {
                'total': 1,
                'category': {
                    'Availability': 1,
                    'Performance': 0,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0}
            }
        )

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True, KESSEL_ENABLED=True)
    @kessel.add_kessel_response(
        permission_checks=constants.kessel_allow_recom_read_ro,
        resource_lookups=constants.kessel_user_in_workspace_host_group_1
    )
    @responses.activate
    def test_groups_match_kessel_enabled_recom_read_only(self):
        responses.add(
            responses.GET, TEST_RBAC_V2_WKSPC,
            json={'data': [{'id': constants.kessel_std_workspace_id}]}
        )
        # No RBACv1 use when Kessel enabled
        page = self._get_view('rule-list')
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        # Systems list - Resource lookup allows access to host group 1
        page = self._get_view('system-list')
        self.assertEqual(page['meta']['count'], 1)
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True)
    @responses.activate
    def test_groups_match_query_param(self):
        # No groups defined in RBAC, but given as query parameter
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS, status=200, json=rbac_data()
        )
        # Pathways systems list
        page = self._get_view(
            'pathway-systems', view_kwargs={'slug': constants.first_pathway['slug']},
            data={'groups': constants.host_group_1_name}
        )
        self.assertEqual(page['meta']['count'], 1)  # one system
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)
        # Rules list - systems counts will change
        page = self._get_view(
            'rule-list', data={'groups': constants.host_group_1_name}
        )
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['rule_id'], constants.acked_rule)
        self.assertEqual(page['data'][0]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][1]['rule_id'], constants.active_rule)
        self.assertEqual(page['data'][1]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][2]['rule_id'], constants.second_rule)
        self.assertEqual(page['data'][2]['impacted_systems_count'], 0)
        # Systems list
        page = self._get_view(
            'system-list', data={'groups': constants.host_group_1_name}
        )
        self.assertEqual(page['meta']['count'], 1)  # one system
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)
        # Systems detail - system not in group
        response = self.client.get(
            reverse(
                'system-detail', kwargs={'uuid': constants.host_05_uuid}
            ), data={'groups': constants.host_group_1_name},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        # Systems detail - system in group
        page = self._get_view(
            'system-detail', view_kwargs={'uuid': constants.host_01_uuid},
            data={'groups': constants.host_group_1_name}
        )
        self.assertEqual(page['display_name'], constants.host_01_name)
        # Export views
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'),
            data={'groups': constants.host_group_1_name}, **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['rhel_version'], '7.5')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(len(row_data), 1)
        response = self.client.get(
            reverse('export-systems-list'),
            data={'groups': constants.host_group_1_name}, **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['display_name'], constants.host_01_name)
        self.assertEqual(len(row_data), 1)
        # Stats views
        stats = self._get_view(
            'stats-systems', data={'groups': constants.host_group_1_name}
        )
        # Systems in account 1234567 in host group 1: system 01
        self.assertEqual(
            stats,
            {
                'total': 1,
                'category': {
                    'Availability': 1,
                    'Performance': 0,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0}
            }
        )

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True)
    @responses.activate
    def test_groups_match_several_ihr_entries(self):
        multiple_ihr_entries_rbac = rbac_data(groups=[constants.host_group_1_id])
        multiple_ihr_entries_rbac['data'].append({
            'permission': 'inventory:hosts:read',
            'resourceDefinitions': [{'attributeFilter': {
                'key': 'group.id',
                'value': [constants.host_group_2_id],
                'operation': 'in'
            }}]
        })
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS, status=200,
            json=multiple_ihr_entries_rbac
        )
        # Pathways systems list
        page = self._get_view(
            'pathway-systems', view_kwargs={'slug': constants.first_pathway['slug']}
        )
        self.assertEqual(page['meta']['count'], 2)  # two systems
        self.assertEqual(len(page['data']), 2)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)
        self.assertEqual(page['data'][1]['display_name'], constants.host_03_name)
        # Rules list - systems counts will change
        page = self._get_view('rule-list')
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['rule_id'], constants.acked_rule)
        self.assertEqual(page['data'][0]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][1]['rule_id'], constants.active_rule)
        self.assertEqual(page['data'][1]['impacted_systems_count'], 2)
        self.assertEqual(page['data'][2]['rule_id'], constants.second_rule)
        self.assertEqual(page['data'][2]['impacted_systems_count'], 1)
        # Systems list
        page = self._get_view('system-list')
        self.assertEqual(page['meta']['count'], 2)
        self.assertEqual(len(page['data']), 2)
        self.assertEqual(page['data'][0]['display_name'], constants.host_03_name)
        self.assertEqual(page['data'][1]['display_name'], constants.host_01_name)
        # Systems detail - system not in group
        response = self.client.get(
            reverse(
                'system-detail', kwargs={'uuid': constants.host_05_uuid}
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        # Systems detail - system in group
        page = self._get_view(
            'system-detail', view_kwargs={'uuid': constants.host_01_uuid}
        )
        self.assertEqual(page['display_name'], constants.host_01_name)
        # Export views
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(len(row_data), 3)
        response = self.client.get(
            reverse('export-systems-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['display_name'], constants.host_03_name)
        self.assertEqual(row_data[1]['display_name'], constants.host_01_name)
        self.assertEqual(len(row_data), 2)
        # Stats views
        stats = self._get_view('stats-systems')
        # Systems in account 1234567 in host group 1 or 2: system 01, 03
        self.assertEqual(
            stats,
            {
                'total': 2,
                'category': {
                    'Availability': 2,
                    'Performance': 1,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0}
            }
        )

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True)
    @responses.activate
    def test_groups_match_group_string(self):
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS, status=200,
            json=rbac_data(groups=f'["{constants.host_group_1_id}"]')
        )
        # Pathways systems list
        page = self._get_view(
            'pathway-systems', view_kwargs={'slug': constants.first_pathway['slug']}
        )
        self.assertEqual(page['meta']['count'], 1)  # one system
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)
        # Rules list - systems counts will change
        page = self._get_view('rule-list')
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['rule_id'], constants.acked_rule)
        self.assertEqual(page['data'][0]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][1]['rule_id'], constants.active_rule)
        self.assertEqual(page['data'][1]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][2]['rule_id'], constants.second_rule)
        self.assertEqual(page['data'][2]['impacted_systems_count'], 0)
        # Systems list
        page = self._get_view('system-list')
        self.assertEqual(page['meta']['count'], 1)  # one system
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)
        # Systems detail - system not in group
        response = self.client.get(
            reverse(
                'system-detail', kwargs={'uuid': constants.host_05_uuid}
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        # Systems detail - system in group
        page = self._get_view(
            'system-detail', view_kwargs={'uuid': constants.host_01_uuid}
        )
        self.assertEqual(page['display_name'], constants.host_01_name)
        # Export views
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['rhel_version'], '7.5')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(len(row_data), 1)
        response = self.client.get(
            reverse('export-systems-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['display_name'], constants.host_01_name)
        self.assertEqual(len(row_data), 1)
        # Stats views
        stats = self._get_view('stats-systems')
        # Systems in account 1234567 in host group 1: system 01
        self.assertEqual(
            stats,
            {
                'total': 1,
                'category': {
                    'Availability': 1,
                    'Performance': 0,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0}
            }
        )

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True)
    @responses.activate
    def test_groups_match_null_group(self):
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS, status=200,
            json=rbac_data(groups=[constants.host_group_2_id, None])
        )
        # Pathways systems list
        page = self._get_view(
            'pathway-systems', view_kwargs={'slug': constants.first_pathway['slug']}
        )
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['display_name'], constants.host_06_name)
        self.assertEqual(page['data'][1]['display_name'], constants.host_03_name)
        self.assertEqual(page['data'][2]['display_name'], constants.host_04_name)
        # Rules list - systems counts will change (most hosts but not group 1)
        page = self._get_view('rule-list')
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['rule_id'], constants.acked_rule)
        self.assertEqual(page['data'][0]['impacted_systems_count'], 0)  # group 1
        self.assertEqual(page['data'][1]['rule_id'], constants.active_rule)
        self.assertEqual(page['data'][1]['impacted_systems_count'], 3)
        self.assertEqual(page['data'][2]['rule_id'], constants.second_rule)
        self.assertEqual(page['data'][2]['impacted_systems_count'], 2)
        # Systems list
        page = self._get_view('system-list')
        self.assertEqual(page['meta']['count'], 4)
        self.assertEqual(len(page['data']), 4)
        # not host 1 which is in group 1, but hosts which have no group set
        # Ordered by... display name?
        self.assertEqual(page['data'][0]['display_name'], constants.host_03_name)
        self.assertEqual(page['data'][1]['display_name'], constants.host_04_name)
        self.assertEqual(page['data'][2]['display_name'], constants.host_06_name)
        self.assertEqual(page['data'][3]['display_name'], constants.host_05_name)
        # Systems detail - system not in group
        response = self.client.get(
            reverse(
                'system-detail', kwargs={'uuid': constants.host_01_uuid}
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        # Systems detail - system in group
        page = self._get_view(
            'system-detail', view_kwargs={'uuid': constants.host_05_uuid}
        )
        self.assertEqual(page['display_name'], constants.host_05_name)
        # Export views
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['rhel_version'], '7.5')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[2]['title'], constants.active_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['title'], constants.second_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[4]['title'], constants.active_title)
        self.assertEqual(len(row_data), 5)
        response = self.client.get(
            reverse('export-systems-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['display_name'], constants.host_03_name)
        self.assertEqual(len(row_data), 4)
        # Stats views
        stats = self._get_view('stats-systems')
        # Systems in account 1234567 not in host group 1: system 3, 4, (5), 6
        self.assertEqual(
            stats,
            {
                'total': 3,
                'category': {
                    'Availability': 3,
                    'Performance': 2,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 3, '2': 0, '3': 0, '4': 0}
            }
        )

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True)
    @responses.activate
    def test_groups_match_include_all(self):
        multiple_ihr_entries_rbac = rbac_data(groups=[constants.host_group_1_id])
        multiple_ihr_entries_rbac['data'].append({
            'permission': 'inventory:hosts:*',
            'resourceDefinitions': []
        })
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS, status=200,
            json=multiple_ihr_entries_rbac
        )
        # Should be all systems now
        # Pathways systems list
        page = self._get_view(
            'pathway-systems', view_kwargs={'slug': constants.first_pathway['slug']}
        )
        self.assertEqual(page['meta']['count'], 4)
        self.assertEqual(len(page['data']), 4)
        self.assertEqual(page['data'][0]['display_name'], constants.host_06_name)
        self.assertEqual(page['data'][1]['display_name'], constants.host_01_name)
        self.assertEqual(page['data'][2]['display_name'], constants.host_03_name)
        self.assertEqual(page['data'][3]['display_name'], constants.host_04_name)
        # Rules list - systems counts will change
        page = self._get_view('rule-list')
        self.assertEqual(page['meta']['count'], 3)
        self.assertEqual(len(page['data']), 3)
        self.assertEqual(page['data'][0]['rule_id'], constants.acked_rule)
        self.assertEqual(page['data'][0]['impacted_systems_count'], 1)
        self.assertEqual(page['data'][1]['rule_id'], constants.active_rule)
        self.assertEqual(page['data'][1]['impacted_systems_count'], 4)
        self.assertEqual(page['data'][2]['rule_id'], constants.second_rule)
        self.assertEqual(page['data'][2]['impacted_systems_count'], 2)
        # Systems list
        page = self._get_view('system-list')
        self.assertEqual(page['meta']['count'], 5)
        self.assertEqual(len(page['data']), 5)
        self.assertEqual(page['data'][0]['display_name'], constants.host_03_name)
        self.assertEqual(page['data'][1]['display_name'], constants.host_04_name)
        self.assertEqual(page['data'][2]['display_name'], constants.host_01_name)
        self.assertEqual(page['data'][3]['display_name'], constants.host_06_name)
        self.assertEqual(page['data'][4]['display_name'], constants.host_05_name)
        # Systems detail - system not in group
        response = self.client.get(
            reverse(
                'system-detail', kwargs={'uuid': constants.host_e1_uuid}
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        # Systems detail - system in group
        page = self._get_view(
            'system-detail', view_kwargs={'uuid': constants.host_01_uuid}
        )
        self.assertEqual(page['display_name'], constants.host_01_name)
        # Export views
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(len(row_data), 6)
        response = self.client.get(
            reverse('export-systems-list'), **headers
        )
        row_data = self._get_export_view(response)
        self.assertEqual(row_data[0]['display_name'], constants.host_03_name)
        self.assertEqual(row_data[1]['display_name'], constants.host_04_name)
        self.assertEqual(row_data[2]['display_name'], constants.host_01_name)
        self.assertEqual(row_data[3]['display_name'], constants.host_06_name)
        self.assertEqual(row_data[4]['display_name'], constants.host_05_name)
        self.assertEqual(len(row_data), 5)
        # Stats views
        stats = self._get_view('stats-systems')
        # Systems in account 1234567 no host groups filtered: 1, 3, 4, 5, 6
        self.assertEqual(
            stats,
            {
                'total': 4,
                'category': {
                    'Availability': 4,
                    'Performance': 2,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 4, '2': 0, '3': 0, '4': 0}
            }
        )
