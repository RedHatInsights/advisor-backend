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

from django.test import TestCase, override_settings
from django.urls import reverse

from api.tests import update_stale_dates
from api.permissions import auth_header_for_testing
from tasks.tests import constants
from tasks.utils import playbook_dispatcher_connection_status_path

PD_TEST_URL = "http://localhost/"
PD_TEST_RECIP_STATUS_URL = PD_TEST_URL + playbook_dispatcher_connection_status_path
PDAPI_PSK = 'test'

# A somewhat arbitrary choice...
are_connected = {constants.host_01_uuid, constants.host_03_uuid}


def pd_connection_status_response(request):
    payload = json.loads(request.body)
    # Return status, headers, body
    # Note that this doesn't attempt to replicate the way that the
    # RecipientWithConnectionInfo will group Satellite systems together.
    # We just recreate the HighLevelRecipientStatus as if each
    # RecipientWithConnectionInfo was separate.
    """
        recipient:
          $ref: './public.openapi.yaml#/components/schemas/RunRecipient'
        org_id:
          $ref: '#/components/schemas/OrgId'
        sat_id:
          $ref: '#/components/schemas/SatelliteId'
        sat_org_id:
          $ref: '#/components/schemas/SatelliteOrgId'
        recipient_type:
          $ref: '#/components/schemas/RecipientType'
        systems:
          type: array
          items:
            $ref: '#/components/schemas/HostId'
        status:
          description: Indicates the current run status of the recipient
          type: string
          enum: [connected, disconnected, rhc_not_configured]
    """
    return (200, {}, json.dumps([
        {
            'recipient': "beefface-c7a6-4cc3-89bc-9066ffda695e",  # ignored
            'org_id': payload['org_id'],
            'sat_id': '',  # ignored
            'sat_org_id': '',  # ignored
            'recipient_type': (
                'satellite' if host == constants.host_04_uuid else 'directConnect'
            ),  # ignored
            'systems': [host],
            'status': ('connected' if host in are_connected else 'disconnected'),
        }
        for host in payload['hosts']
    ]))


class SystemViewTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    std_auth = auth_header_for_testing()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_system_list(self):
        # no auth, no access
        res = self.client.get(reverse('tasks-system-list'))
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-system-list'), **self.std_auth
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
        self.assertEqual(page['meta']['count'], 6)
        self.assertIn('data', page)
        data = page['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 6)
        # Sorted by display name by default
        self.assertIsInstance(data[0], dict)
        self.assertIn('display_name', data[0])
        self.assertEqual(data[0]['display_name'], constants.host_0b_name)
        self.assertEqual(data[1]['display_name'], constants.host_e1_name)
        self.assertEqual(data[2]['display_name'], constants.host_06_name)
        self.assertEqual(data[3]['display_name'], constants.host_01_name)
        self.assertEqual(data[4]['display_name'], constants.host_03_name)
        self.assertEqual(data[5]['display_name'], constants.host_04_name)
        # Check one row's properties:
        self.assertIn('id', data[3])
        self.assertEqual(data[3]['id'], constants.host_01_uuid)
        self.assertIn('display_name', data[3])
        self.assertEqual(data[3]['display_name'], constants.host_01_name)
        self.assertIn('os_version', data[3])
        self.assertEqual(data[3]['os_version'], 'RHEL 7.5')
        self.assertIn('tags', data[3])
        self.assertEqual(data[3]['tags'], [])
        self.assertIn('groups', data[3])
        self.assertEqual(data[3]['groups'][0]['name'], 'group01')
        self.assertIn('updated', data[3])
        self.assertEqual(data[3]['updated'], '2018-12-04T05:15:38Z')
        self.assertIn('last_check_in', data[3])
        self.assertIn('connection_type', data[3])
        self.assertEqual(data[3]['connection_type'], 'direct')
        self.assertIn('connected', data[3])
        # If Playbook Dispatcher isn't available, all systems are unavailable
        self.assertEqual(data[3]['connected'], False)
        # Check a satellite connected system properties:
        self.assertIn('display_name', data[5])
        self.assertEqual(data[5]['display_name'], constants.host_04_name)
        self.assertIn('tags', data[5])
        self.assertEqual(data[5]['tags'], [
            {
                'key': 'satellite_instance_id', 'namespace': 'satellite',
                'value': '82148fc8-afba-44ba-8d48-1d497f4b3b11'
            },
            {'key': 'organization_id', 'namespace': 'satellite', 'value': '1'}
        ])
        self.assertIn('connection_type', data[5])
        self.assertEqual(data[5]['connection_type'], 'satellite')
        self.assertEqual(data[0]['connection_type'], 'direct')
        # Check connection status - with no PD available this should all be false
        self.assertEqual(data[0]['connected'], False)  # Host 0b
        self.assertEqual(data[1]['connected'], False)  # Host e1
        self.assertEqual(data[2]['connected'], False)  # Host 06
        self.assertEqual(data[3]['connected'], False)  # Host 01
        self.assertEqual(data[4]['connected'], False)  # Host 03
        self.assertEqual(data[5]['connected'], False)  # Host 0b

    def test_system_list_sort(self):
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'sort': 'os_version'},
            **self.std_auth
        )
        page = res.json()
        data = page['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 6)
        # Just a basic check of the ordering, not the whole list
        self.assertIsInstance(data[0], dict)
        # Because these systems already have the same OS version, the Host
        # table defaults to sorting by ID.
        self.assertEqual(data[0]['id'], constants.host_01_uuid)
        self.assertEqual(data[1]['id'], constants.host_03_uuid)
        self.assertEqual(data[2]['id'], constants.host_04_uuid)
        self.assertEqual(data[3]['id'], constants.host_06_uuid)
        # Except for this host, which is sorted later (and happens to have a
        # higher ID as well)
        self.assertEqual(data[4]['id'], constants.host_0b_uuid)
        self.assertEqual(data[5]['id'], constants.host_e1_uuid)

        res = self.client.get(
            reverse('tasks-system-list'),
            data={'sort': 'last_seen'},
            **self.std_auth
        )
        page = res.json()
        data = page['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 6)
        # Just a basic check of the ordering, not the whole list
        self.assertIsInstance(data[0], dict)
        self.assertEqual(data[0]['id'], constants.host_03_uuid)
        self.assertEqual(data[1]['id'], constants.host_01_uuid)
        self.assertEqual(data[2]['id'], constants.host_04_uuid)
        self.assertEqual(data[3]['id'], constants.host_06_uuid)
        self.assertEqual(data[4]['id'], constants.host_e1_uuid)
        self.assertEqual(data[5]['id'], constants.host_0b_uuid)

        res = self.client.get(
            reverse('tasks-system-list'),
            data={'sort': 'last_check_in'},
            **self.std_auth
        )
        page = res.json()
        data = page['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 6)
        # Ordering for last_check_in is kind of based on stale then host order
        self.assertIsInstance(data[0], dict)
        self.assertEqual(data[0]['id'], constants.host_06_uuid)
        self.assertEqual(data[1]['id'], constants.host_01_uuid)
        self.assertEqual(data[2]['id'], constants.host_03_uuid)
        self.assertEqual(data[3]['id'], constants.host_04_uuid)
        self.assertEqual(data[4]['id'], constants.host_0b_uuid)
        self.assertEqual(data[5]['id'], constants.host_e1_uuid)

        # Test bad sort parameter
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'sort': '-last_seeninsights-client/OS=CentOS7'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        content = res.content.decode()
        self.assertIn(
            "The value is required to be one of the following values:",
            content
        )
        # data = res.json()
        # self.assertEqual(data, {'error': {'sort': ['foo']}})

    def test_system_list_filtering(self):
        # OS version filtering
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'os_version': '8.4'},
            **self.std_auth
        )
        data = res.json()['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 0)  # Nonexistent RHEL version

        # Display name filtering
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'display_name': 'STALE'},  # should be case insensitive
            **self.std_auth
        )
        data = res.json()['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], constants.host_06_uuid)  # stale_warn

        # Host tags filtering
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'tags': 'satellite/organization_id=1'},
            **self.std_auth
        )
        data = res.json()['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)  # sort on display_name then id
        self.assertEqual(data[0]['id'], constants.host_e1_uuid)
        self.assertEqual(data[1]['id'], constants.host_04_uuid)

        # System profile filters
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'filter[system_profile][sap_system]': 'true'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(data[0]['id'], constants.host_e1_uuid)
        self.assertEqual(data[1]['id'], constants.host_01_uuid)
        self.assertEqual(data[2]['id'], constants.host_04_uuid)
        self.assertEqual(len(data), 3)
        res = self.client.get(
            reverse('tasks-system-list'),
            data={
                'filter[system_profile][sap_system]': 'true',
                'filter[system_profile][ansible][not_nil]': True,
                'filter[system_profile][mssql][not_nil]': False
            },
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 0)
        res = self.client.get(
            reverse('tasks-system-list'),
            data={
                'filter[system_profile][host_type][ne]': 'edge',
            },
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(data[0]['id'], constants.host_0b_uuid)
        self.assertEqual(data[1]['id'], constants.host_06_uuid)
        self.assertEqual(data[2]['id'], constants.host_01_uuid)
        self.assertEqual(data[3]['id'], constants.host_03_uuid)
        self.assertEqual(data[4]['id'], constants.host_04_uuid)
        self.assertEqual(len(data), 5)

        # OS name filtering - single value
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'os_name': 'CentOS'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(data[0]['id'], constants.host_0b_uuid)
        self.assertEqual(len(data), 1)
        # OS name filtering - multiple value
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'os_name': 'CentOS,Rocky'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(data[0]['id'], constants.host_0b_uuid)
        self.assertEqual(len(data), 1)
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'os_name': 'CentOS,RHEL'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(data[0]['id'], constants.host_0b_uuid)
        self.assertEqual(data[1]['id'], constants.host_e1_uuid)
        self.assertEqual(data[2]['id'], constants.host_06_uuid)
        self.assertEqual(data[3]['id'], constants.host_01_uuid)
        self.assertEqual(data[4]['id'], constants.host_03_uuid)
        self.assertEqual(data[5]['id'], constants.host_04_uuid)
        self.assertEqual(len(data), 6)
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'operating_system': ['CentOS|8.6', 'RHEL|9.2']},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]['id'], constants.host_0b_uuid)
        self.assertEqual(data[1]['id'], constants.host_e1_uuid)

        # Host group filtering - a group with a matching system
        res = self.client.get(reverse('tasks-system-list'), data={'groups': 'group01'}, **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], constants.host_01_uuid)

        # Host group filtering - a group without any matching systems
        res = self.client.get(reverse('tasks-system-list'), data={'groups': 'nosystems'}, **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 0)

    def test_system_list_filtering_new_rhc_connection(self):
        from tasks.models import Host

        # system05 is a CentOS Linux system, but it isn't connected via RHC - no match
        res = self.client.get(reverse('tasks-system-list'), data={'os_name': 'CentOS Linux'}, **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        self.assertEqual(len(res.json()['data']), 0)

        # Add rhc_client_id attribute to system05 system_profile to simulate a new RHC connection
        system05 = Host.objects.get(id=constants.host_05_uuid)
        system05.system_profile['rhc_client_id'] = "00112233-4455-6677-8899-CCCCCCCCCC05"
        system05.save()

        # Match system05 now that it has an RHC connection
        res = self.client.get(reverse('tasks-system-list'), data={'os_name': 'CentOS Linux'}, **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()['data']
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], constants.host_05_uuid)

    def test_bad_os_filter(self):
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'operating_system': 'bogus_value'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        content = res.content.decode()
        self.assertIn(
            "Badly formatted operating_system filter.  Must be of "
            "the form <NAME>|<VERSION>", content
        )

    @responses.activate
    @override_settings(PLAYBOOK_DISPATCHER_URL=PD_TEST_URL, PDAPI_PSK=PDAPI_PSK)
    def test_system_list_connection_status_pd_available(self):
        responses.add_callback(
            responses.POST, PD_TEST_RECIP_STATUS_URL,
            content_type='application/json',
            callback=pd_connection_status_response,
        )
        # Test that if Playbook Disptcher is connected and giving recipient
        # status responses that we get those.
        res = self.client.get(
            reverse('tasks-system-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()['data']
        self.assertEqual(data[0]['display_name'], constants.host_0b_name)
        self.assertEqual(data[1]['display_name'], constants.host_e1_name)
        self.assertEqual(data[2]['display_name'], constants.host_06_name)
        self.assertEqual(data[3]['display_name'], constants.host_01_name)
        self.assertEqual(data[4]['display_name'], constants.host_03_name)
        self.assertEqual(data[5]['display_name'], constants.host_04_name)
        self.assertEqual(data[0]['connected'], False)
        self.assertEqual(data[1]['connected'], False)
        self.assertEqual(data[2]['connected'], False)
        self.assertEqual(data[3]['connected'], True)
        self.assertEqual(data[4]['connected'], True)
        self.assertEqual(data[5]['connected'], False)

    @responses.activate
    @override_settings(PLAYBOOK_DISPATCHER_URL=PD_TEST_URL, PDAPI_PSK=PDAPI_PSK)
    def test_system_list_connection_status_pd_available_multiple_parts(self):
        # Return everything true, but in a complicated fashion
        responses.post(
            PD_TEST_RECIP_STATUS_URL,
            status=200, json=[
                {
                    'org_id': constants.standard_org,
                    'systems': [constants.host_01_uuid, constants.host_03_uuid],
                    'status': 'connected'
                },
                {
                    'org_id': constants.standard_org,
                    'systems': [
                        constants.host_e1_uuid, constants.host_06_uuid,
                        constants.host_0b_uuid, constants.host_05_uuid
                    ],
                    'status': 'connected'
                },
                {
                    'org_id': constants.alternate_org,
                    'systems': [constants.host_02_uuid, constants.host_09_uuid],
                    'status': 'connected'
                },
                {
                    'org_id': constants.standard_org,
                    'systems': [constants.host_04_uuid],
                    'status': 'connected'
                }
            ],
        )
        res = self.client.get(
            reverse('tasks-system-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()['data']
        self.assertEqual(data[0]['display_name'], constants.host_0b_name)
        self.assertEqual(data[1]['display_name'], constants.host_e1_name)
        self.assertEqual(data[2]['display_name'], constants.host_06_name)
        self.assertEqual(data[3]['display_name'], constants.host_01_name)
        self.assertEqual(data[4]['display_name'], constants.host_03_name)
        self.assertEqual(data[5]['display_name'], constants.host_04_name)
        self.assertEqual(len(data), 6)
        self.assertEqual(data[0]['connected'], True)
        self.assertEqual(data[1]['connected'], True)
        self.assertEqual(data[2]['connected'], True)
        self.assertEqual(data[3]['connected'], True)
        self.assertEqual(data[4]['connected'], True)
        self.assertEqual(data[5]['connected'], True)

    def test_system_detail(self):
        # No auth = no access
        res = self.client.get(
            reverse('tasks-system-detail', kwargs={'id': constants.host_01_uuid})
        )
        self.assertEqual(res.status_code, 403)
        # access allowed with auth
        res = self.client.get(
            reverse('tasks-system-detail', kwargs={'id': constants.host_01_uuid}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertEqual(data['id'], constants.host_01_uuid)
        self.assertIn('display_name', data)
        self.assertEqual(data['display_name'], constants.host_01_name)
        self.assertIn('os_version', data)
        self.assertEqual(data['os_version'], 'RHEL 7.5')
        self.assertIn('groups', data)
        self.assertEqual(sorted(data['groups'][0].keys()), ['id', 'name'])
        self.assertEqual(data['groups'][0]['name'], 'group01')
        self.assertIn('connection_type', data)
        self.assertEqual(data['connection_type'], 'direct')
        self.assertIn('last_check_in', data)
        self.assertIn('culled_timestamp', data)
        self.assertIn('stale_timestamp', data)
        self.assertIn('stale_warning_timestamp', data)
        self.assertNotIn('requirements', data)  # requirements are not added for the detail endpoint
        self.assertIn('connected', data)
        self.assertEqual(data['connected'], False)  # without PD, systems are not connected

    @responses.activate
    @override_settings(PLAYBOOK_DISPATCHER_URL=PD_TEST_URL, PDAPI_PSK=PDAPI_PSK)
    def test_system_detail_connection_status_pd_available(self):
        responses.add_callback(
            responses.POST, PD_TEST_RECIP_STATUS_URL,
            content_type='application/json',
            callback=pd_connection_status_response,
        )

        res = self.client.get(
            reverse('tasks-system-detail', kwargs={'id': constants.host_01_uuid}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIn('connected', data)
        self.assertEqual(data['connected'], True)  # Some systems are connected, Mr Anderson...
        res = self.client.get(
            reverse('tasks-system-detail', kwargs={'id': constants.host_e1_uuid}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIn('connected', data)
        self.assertEqual(data['connected'], False)  # and some systems... are not.

    def test_all_systems_param(self):
        # Without the all_systems=true param, only connected systems will be
        # returned (sorted by display name by default) - system05 isn't
        # connected so won't appear
        res = self.client.get(
            reverse('tasks-system-list'),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 6)
        self.assertEqual(hosts[0]['display_name'], constants.host_0b_name)
        self.assertEqual(hosts[0]['connection_type'], 'direct')
        self.assertEqual(hosts[1]['display_name'], constants.host_e1_name)
        self.assertEqual(hosts[1]['connection_type'], 'satellite')
        self.assertNotIn(constants.host_05_uuid, [x['id'] for x in hosts])

        # With all_systems=true param, all systems will be returned, including system05 with connection_type none
        res = self.client.get(
            reverse('tasks-system-list'),
            data={'all_systems': 'true'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 7)
        self.assertEqual(hosts[6]['display_name'], constants.host_05_name)
        self.assertEqual(hosts[6]['connection_type'], 'none')

        # Try to get details of system05 without all_systems=true, but it won't be found - 404 error returned
        res = self.client.get(
            reverse('tasks-system-detail',
                    kwargs={'id': constants.host_05_uuid}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404, res.content.decode())

        # Get details of system05 with all_systems=true, which will be returned now with all_systems=true param
        res = self.client.get(
            reverse('tasks-system-detail',
                    kwargs={'id': constants.host_05_uuid}),
            data={'all_systems': 'true'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        data = res.json()
        self.assertEqual(data['display_name'], constants.host_05_name)
        self.assertEqual(data['connection_type'], 'none')
