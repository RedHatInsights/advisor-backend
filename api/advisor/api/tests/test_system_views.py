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

from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from api import kessel
from api.models import Ack, InventoryHost
from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing


class SystemViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'high_severity_rule',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        return response.json()

    def test_list_system(self):
        response = self.client.get(
            reverse('system-list'), **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']

        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 5)

        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[0]['last_seen'], '2018-09-22T02:00:51Z')
        self.assertEqual(systems[0]['rhel_version'], '7.5')
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[0]['critical_hits'], 0)
        self.assertEqual(systems[0]['important_hits'], 0)
        self.assertEqual(systems[0]['moderate_hits'], 0)
        self.assertEqual(systems[0]['low_hits'], 2)
        self.assertEqual(
            systems[0]['hits'],
            sum(systems[0][field] for field in (
                'critical_hits', 'important_hits', 'moderate_hits', 'low_hits'
            ))
        )
        self.assertEqual(systems[0]['group_name'], 'group_2')

        self.assertEqual(systems[1]['system_uuid'], constants.host_04_uuid)
        self.assertEqual(systems[1]['display_name'], constants.host_04_name)
        self.assertEqual(systems[1]['last_seen'], '2018-12-10T23:32:13Z')
        self.assertEqual(systems[1]['hits'], 2)
        self.assertEqual(systems[1]['critical_hits'], 0)
        self.assertEqual(systems[1]['important_hits'], 0)
        self.assertEqual(systems[1]['moderate_hits'], 0)
        self.assertEqual(systems[1]['low_hits'], 2)
        self.assertEqual(
            systems[1]['hits'],
            sum(systems[1][field] for field in (
                'critical_hits', 'important_hits', 'moderate_hits', 'low_hits'
            ))
        )
        self.assertEqual(systems[1]['group_name'], None)

        self.assertEqual(systems[2]['system_uuid'], constants.host_01_uuid)
        self.assertEqual(systems[2]['display_name'], constants.host_01_name)
        self.assertEqual(systems[2]['last_seen'], '2018-12-04T05:10:36Z')
        self.assertEqual(systems[2]['hits'], 1)
        self.assertEqual(systems[2]['critical_hits'], 0)
        self.assertEqual(systems[2]['important_hits'], 0)
        self.assertEqual(systems[2]['moderate_hits'], 0)
        self.assertEqual(systems[2]['low_hits'], 1)
        self.assertEqual(
            systems[2]['hits'],
            sum(systems[2][field] for field in (
                'critical_hits', 'important_hits', 'moderate_hits', 'low_hits'
            ))
        )
        self.assertEqual(systems[2]['group_name'], 'group_1')

        self.assertEqual(systems[3]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(systems[3]['display_name'], constants.host_06_name)
        self.assertEqual(systems[3]['last_seen'], '2019-04-05T14:30:00Z')
        self.assertEqual(systems[3]['hits'], 1)
        self.assertEqual(systems[3]['critical_hits'], 0)
        self.assertEqual(systems[3]['important_hits'], 0)
        self.assertEqual(systems[3]['moderate_hits'], 0)
        self.assertEqual(systems[3]['low_hits'], 1)
        self.assertEqual(
            systems[3]['hits'],
            sum(systems[3][field] for field in (
                'critical_hits', 'important_hits', 'moderate_hits', 'low_hits'
            ))
        )
        self.assertEqual(systems[3]['group_name'], None)

        self.assertEqual(systems[4]['system_uuid'], constants.host_05_uuid)
        self.assertEqual(systems[4]['display_name'], constants.host_05_name)
        self.assertEqual(systems[4]['last_seen'], '2018-12-10T23:32:15Z')
        self.assertEqual(systems[4]['hits'], 0)
        self.assertEqual(systems[4]['critical_hits'], 0)
        self.assertEqual(systems[4]['important_hits'], 0)
        self.assertEqual(systems[4]['moderate_hits'], 0)
        self.assertEqual(systems[4]['low_hits'], 0)
        self.assertEqual(
            systems[4]['hits'],
            sum(systems[4][field] for field in (
                'critical_hits', 'important_hits', 'moderate_hits', 'low_hits'
            ))
        )
        self.assertEqual(systems[4]['group_name'], None)

    def test_list_system_name_filter(self):
        response = self.client.get(
            reverse('system-list'), data={
                'display_name': 'system'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']

        # Should filter out stale-warn.example.com
        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 4)
        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[1]['hits'], 2)
        self.assertEqual(systems[1]['display_name'], constants.host_04_name)
        self.assertEqual(systems[2]['hits'], 1)
        self.assertEqual(systems[2]['display_name'], constants.host_01_name)
        self.assertEqual(systems[3]['hits'], 0)
        self.assertEqual(systems[3]['display_name'], constants.host_05_name)

    def test_list_incident_filter(self):
        # Filter systems with incidents:
        response = self.client.get(
            reverse('system-list'), data={
                'incident': 'true'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        # Without the incident-creating high severity rule, we have no hits.
        self.assertEqual(json['data'], [])

        # Filter on systems without incidents
        response = self.client.get(
            reverse('system-list'), data={
                'incident': 'no'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']

        self.assertIsInstance(systems, list)
        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[1]['display_name'], constants.host_04_name)
        self.assertEqual(systems[1]['hits'], 2)
        self.assertEqual(systems[2]['display_name'], constants.host_01_name)
        self.assertEqual(systems[2]['hits'], 1)
        self.assertEqual(systems[3]['display_name'], constants.host_06_name)
        self.assertEqual(systems[3]['hits'], 1)
        self.assertEqual(systems[4]['display_name'], constants.host_05_name)
        self.assertEqual(systems[4]['hits'], 0)
        self.assertEqual(len(systems), 5)

        # Advisor-3047 - in the special case where the UI requests both
        # 'incident=true' and 'incident=false', we get a 400.
        response = self.client.get(
            reverse('system-list') + "?incident=true&incident=false",
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, response.content.decode())

    def test_list_system_profile_filter(self):
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][sap_system]': 'true'},
            **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']
        # Systems 1, 4, 5, 8, 9 and A are SAP systems:
        self.assertIsInstance(systems, list)
        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[0]['display_name'], constants.host_04_name)
        self.assertEqual(systems[1]['hits'], 1)
        self.assertEqual(systems[1]['display_name'], constants.host_01_name)
        self.assertEqual(systems[2]['hits'], 0)
        self.assertEqual(systems[2]['display_name'], constants.host_05_name)
        self.assertEqual(len(systems), 3)

        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][sap_sids][contains][]': 'E02'},
            **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']
        # Systems 1 and 4 have SAP SID E02:
        self.assertIsInstance(systems, list)
        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[0]['display_name'], constants.host_04_name)
        self.assertEqual(systems[1]['hits'], 1)
        self.assertEqual(systems[1]['display_name'], constants.host_01_name)
        self.assertEqual(len(systems), 2)
        # Hack together a MultiValueDict here:
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][sap_sids][contains][]': ['E01', 'E02']},
            **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']
        # Only system 1 has SAP SIDs E01 *and* E02:
        self.assertIsInstance(systems, list)
        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['hits'], 1)
        self.assertEqual(systems[0]['display_name'], constants.host_01_name)
        self.assertEqual(len(systems), 1)
        # If we ask for a SID that doesn't exist, we get no matches.
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][sap_sids][contains]': 'fake'},
            **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']
        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 0)

        # A query that includes all systems shouldn't change the results
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][system_memory_bytes][gt]': '33554432000'},
            **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']
        self.assertIsInstance(systems, list)
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[1]['hits'], 2)
        self.assertEqual(systems[1]['display_name'], constants.host_04_name)
        self.assertEqual(systems[2]['hits'], 1)
        self.assertEqual(systems[2]['display_name'], constants.host_01_name)
        self.assertEqual(systems[3]['hits'], 1)
        self.assertEqual(systems[3]['display_name'], constants.host_06_name)
        self.assertEqual(systems[4]['hits'], 0)
        self.assertEqual(systems[4]['display_name'], constants.host_05_name)
        self.assertEqual(len(systems), 5)

    def test_list_system_hits_filter(self):
        # hits=yes lists only those systems with hits - expect 4
        response = self.client.get(reverse('system-list'), data={'hits': 'yes'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 4)
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[1]['display_name'], constants.host_04_name)
        self.assertEqual(systems[1]['hits'], 2)
        self.assertEqual(systems[2]['display_name'], constants.host_01_name)
        self.assertEqual(systems[2]['hits'], 1)
        self.assertEqual(systems[3]['display_name'], constants.host_06_name)
        self.assertEqual(systems[3]['hits'], 1)

        # hits=all lists all systems, with or without hits - expect 5
        response = self.client.get(reverse('system-list'), data={'hits': 'all'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 5)
        self.assertEqual(systems[4]['display_name'], constants.host_05_name)
        self.assertEqual(systems[4]['hits'], 0)

        # hits=no lists systems without hits - expect 1
        response = self.client.get(reverse('system-list'), data={'hits': 'no'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 1)
        self.assertEqual(systems[0]['display_name'], constants.host_05_name)
        self.assertEqual(systems[0]['hits'], 0)

        # hits=1 lists systems with low_risk hits - expect 4
        response = self.client.get(reverse('system-list'), data={'hits': '1'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 4)
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[0]['low_hits'], 2)
        self.assertEqual(systems[3]['display_name'], constants.host_06_name)
        self.assertEqual(systems[3]['low_hits'], 1)

        # hits=4 lists systems with critical_risk hits - expect 0
        response = self.client.get(reverse('system-list'), data={'hits': '4'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 0)

        # hits=1,4 lists systems with either low_risk or critical_risk hits - expect 4
        response = self.client.get(reverse('system-list'), data={'hits': '1,4'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 4)

        # hits=1,4,yes shouldn't happen, but will prioritize the hits=yes to list all systems - expect 4
        response = self.client.get(reverse('system-list'), data={'hits': '1,4,yes'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 4)

        # hits=no,all,yes shouldn't happen, but will prioritize the hits=all to list all systems - expect 5
        response = self.client.get(reverse('system-list'), data={'hits': 'no,all,yes'}, **auth_header_for_testing())
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 5)

    def test_list_system_last_seen_sort(self):
        response = self.client.get(
            reverse('system-list'), data={
                'sort': 'last_seen'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']

        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 5)
        self.assertEqual(systems[0]['last_seen'], '2018-09-22T02:00:51Z')
        self.assertEqual(systems[1]['last_seen'], '2018-12-04T05:10:36Z')
        self.assertEqual(systems[2]['last_seen'], '2018-12-10T23:32:13Z')
        self.assertEqual(systems[3]['last_seen'], '2018-12-10T23:32:15Z')
        self.assertEqual(systems[4]['last_seen'], '2019-04-05T14:30:00Z')

    def test_list_system_host_group_name_sort(self):
        # We can only sort by one field, we don't populate the groups
        # field for most of our test data, and the group names are in the
        # same order as other fields (id, display_name).  So we select only
        # the groups, and try both forward and reverse sorts to make sure
        # that is obeyed.  Forward:
        response = self.client.get(
            reverse('system-list'), data={
                'groups': 'group_1,group_2',
                'sort': 'group_name'
            }, **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 2)
        self.assertEqual(systems[0]['display_name'], constants.host_01_name)
        self.assertEqual(systems[1]['display_name'], constants.host_03_name)
        # Reverse:
        response = self.client.get(
            reverse('system-list'), data={
                'groups': 'group_1,group_2',
                'sort': '-group_name'
            }, **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 2)
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[1]['display_name'], constants.host_01_name)

    def test_list_system_low_hits_sort(self):
        response = self.client.get(
            reverse('system-list'), data={'sort': 'low_hits'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 5)
        # Systems are sorted by number of low risk hits asc, then name asc
        self.assertEqual(systems[0]['display_name'], constants.host_05_name)
        self.assertEqual(systems[0]['low_hits'], 0)
        self.assertEqual(systems[4]['display_name'], constants.host_04_name)
        self.assertEqual(systems[4]['low_hits'], 2)

        response = self.client.get(
            reverse('system-list'), data={'sort': '-low_hits'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 5)
        # Systems are sorted by number of low risk hits desc, then name asc
        self.assertEqual(systems[0]['display_name'], constants.host_03_name)
        self.assertEqual(systems[0]['low_hits'], 2)
        self.assertEqual(systems[4]['display_name'], constants.host_05_name)
        self.assertEqual(systems[4]['low_hits'], 0)

    def test_list_system_rhel_version_sort(self):
        # Test reversing this, since it relies on two sort fields
        response = self.client.get(
            reverse('system-list'), data={'sort': '-rhel_version'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 5)
        # Systems are sorted by OS version - all in this account are 7.5
        # except for system 5 which is 7.1 so is last (reverse).  Sorted then by UUID.
        self.assertEqual(systems[0]['display_name'], constants.host_01_name)
        self.assertEqual(systems[1]['display_name'], constants.host_03_name)
        self.assertEqual(systems[2]['display_name'], constants.host_04_name)
        self.assertEqual(systems[3]['display_name'], constants.host_06_name)
        self.assertEqual(systems[4]['display_name'], constants.host_05_name)

    def test_list_system_rhel_version_filter(self):
        # All of the standard account's systems are on RHEL 7.5
        response = self.client.get(
            reverse('system-list'),
            data={'rhel_version': '7.5', 'sort': 'display_name'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(systems[0]['display_name'], constants.host_06_name)
        self.assertEqual(systems[1]['display_name'], constants.host_01_name)
        self.assertEqual(systems[2]['display_name'], constants.host_03_name)
        self.assertEqual(systems[3]['display_name'], constants.host_04_name)
        # Note that we filter out system 5 because it's on RHEL 7.1
        self.assertEqual(len(systems), 4)

        # Get empty list on request for version we don't have (and it's in
        # another account)
        response = self.client.get(
            reverse('system-list'), data={'rhel_version': '6.8'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(systems, [])

    def test_list_system_pathway_filter(self):
        response = self.client.get(
            reverse('system-list'),
            data={'pathway': 'test-component-1', 'sort': 'display_name'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(systems[0]['display_name'], constants.host_06_name)
        self.assertEqual(systems[1]['display_name'], constants.host_01_name)
        self.assertEqual(systems[2]['display_name'], constants.host_03_name)
        self.assertEqual(systems[3]['display_name'], constants.host_04_name)
        # Note that we filter out system 5 because it doesn't have hits for
        # Pathway 1.
        self.assertEqual(len(systems), 4)

    def test_list_system_bad_sort_value(self):
        response = self.client.get(
            reverse('system-list'), data={
                'sort': 'bad_sort_value'
            }, **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400)

    def test_list_system_update_method_filter(self):
        # update_method=dnfyum lists only those systems with hits
        # Matches systems01, 03, 04, and stale-warn
        response = self.client.get(
            reverse('system-list'), data={'update_method': 'dnfyum'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)['data']
        self.assertEqual(len(systems), 5)

    def test_list_system_overall_staleness_up_to_date(self):
        # Update all hosts to have up-to-date host staleness
        updated = InventoryHost.objects.update(
            stale_timestamp=timezone.now(),
            stale_warning_timestamp=timezone.now(),
            culled_timestamp=timezone.now(),
            updated=timezone.now(),
        )
        self.assertGreater(updated, 0)
        stale_hide_2 = InventoryHost.objects.get(id=constants.host_0a_uuid)
        self.assertGreater(stale_hide_2.updated, timezone.now() - timedelta(seconds=5))
        response = self.client.get(
            reverse('system-list'), **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        systems = json['data']

        self.assertIsInstance(systems, list)
        # Systems are by default sorted by number of hits, then name
        self.assertEqual(systems[0]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(systems[1]['system_uuid'], constants.host_04_uuid)
        self.assertEqual(systems[2]['system_uuid'], constants.host_01_uuid)
        self.assertEqual(systems[3]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(systems[4]['system_uuid'], constants.host_05_uuid)
        self.assertEqual(len(systems), 5)
        # Should NOT see stale_hide or stale_hide_2 hosts here.

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True)
    # Our Test Zed client doesn't allow us to explicitly specify wildcards,
    # because it has no idea what these things are.  It just matches exactly.
    @kessel.add_zed_response(
        permission_checks=constants.kessel_zedrsp_allow_disable_recom_rw,
        resource_lookups=constants.kessel_zedlur_workspace_host_group_1
    )
    def test_list_system_kessel_on(self):
        response = self.client.get(
            reverse('system-list'), **auth_header_for_testing()
        )
        page = self._response_is_good(response)
        # Results should be filtered to host group 1.
        self.assertEqual(page['meta']['count'], 1)  # one system
        self.assertEqual(len(page['data']), 1)
        self.assertEqual(page['data'][0]['display_name'], constants.host_01_name)

    def test_get_system(self):
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': constants.host_01_uuid
            }), **auth_header_for_testing()
        )
        system = self._response_is_good(response)

        self.assertIsInstance(system, dict)
        self.assertEqual(system['hits'], 1)
        self.assertEqual(system['system_uuid'], constants.host_01_uuid)
        self.assertEqual(system['display_name'], constants.host_01_name)
        self.assertEqual(system['last_seen'], '2018-12-04T05:10:36Z')

    def test_get_system_with_no_hits(self):
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': constants.host_05_uuid
            }), **auth_header_for_testing()
        )
        system = self._response_is_good(response)

        self.assertIsInstance(system, dict)
        self.assertEqual(system['hits'], 0)
        self.assertEqual(system['system_uuid'], constants.host_05_uuid)
        self.assertEqual(system['last_seen'], '2018-12-10T23:32:15Z')

    def test_get_nonexistent_system(self):
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': '123'
            }), **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    def test_get_system_from_outside_account(self):
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': constants.host_05_uuid
            }), **auth_header_for_testing(account='7654321', org_id='7654321')
        )
        self.assertEqual(response.status_code, 404)

    def test_reports_on_system(self):
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_01_uuid
            }), **auth_header_for_testing()
        )
        json = self._response_is_good(response)

        self.assertIsInstance(json, list)
        # The most recent upload for system 1 only contains the test|Active_rule report
        self.assertEqual(len(json), 1)
        report = json[0]
        self.assertIsInstance(report, dict)
        self.assertIn('rule', report)
        self.assertEqual(report['rule']['rule_id'], constants.active_rule)
        self.assertIn('details', report)
        self.assertIsInstance(report['details'], dict)
        self.assertIn('error_key', report['details'])
        self.assertEqual(report['details']['error_key'], "ACTIVE_RULE")

    def test_branch_id_filter(self):
        # Requests with a valid branch ID should filter on that even here
        response = self.client.get(
            reverse('system-detail', kwargs={'uuid': constants.host_01_uuid}),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        system = self._response_is_good(response)
        self.assertIsInstance(system, dict)
        self.assertEqual(system['hits'], 1)
        self.assertEqual(system['system_uuid'], constants.host_01_uuid)
        self.assertEqual(system['display_name'], constants.host_01_name)
        self.assertEqual(system['last_seen'], '2018-12-04T05:10:36Z')

        response = self.client.get(
            reverse('system-reports', kwargs={'uuid': constants.host_01_uuid}),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        self.assertIsInstance(json[0], dict)
        self.assertEqual(json[0]['rule']['rule_id'], constants.active_rule)
        self.assertIsInstance(json[0]['details'], dict)
        self.assertIn('error_key', json[0]['details'])
        self.assertEqual(json[0]['details']['error_key'], "ACTIVE_RULE")

        # Requests with an invalid branch ID should 400 (not 500)
        response = self.client.get(
            reverse('system-reports', kwargs={'uuid': constants.host_01_uuid}),
            data={'branch_id': "satellite.example.com"},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, response.content.decode())

    def test_reports_on_satellite_system_can_see(self):
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_06_uuid
            }), **auth_header_for_testing()
        )
        json = self._response_is_good(response)

        self.assertIsInstance(json, list)
        # The most recent upload for system 6 only contains the test|Active_rule report
        self.assertEqual(len(json), 1)
        report = json[0]
        self.assertIsInstance(report, dict)
        self.assertIn('rule', report)
        self.assertEqual(report['rule']['rule_id'], constants.active_rule)

    def test_reports_on_no_system(self):
        # If there are no uploads for a system, whether it be because it's in
        # the wrong account or because the system UUID doesn't exist, we
        # should get an empty list.
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': '00001111-2222-3333-4444-555566667777'
            }), **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        self.assertIsInstance(json, list)
        self.assertEqual(len(json), 0)

        # - existing system but in wrong (implicit) account
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_02_uuid
            }), **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        self.assertIsInstance(json, list)
        self.assertEqual(len(json), 0)

        # - existing system but in wrong (explicit) account
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_01_uuid
            }), **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        json = self._response_is_good(response)
        self.assertIsInstance(json, list)
        self.assertEqual(len(json), 0)

    def test_system_disabled_recommendation_query_param(self):
        response = self.client.get(
            reverse('system-list'), data={
                'has_disabled_recommendation': 'true'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        #  host_01 has one disabled recommendation
        self.assertEqual(len(json['data']), 1)
        self.assertEqual(json['data'][0]['system_uuid'], constants.host_01_uuid)

        # now testing with the parameter False, which means, bring all systems
        response = self.client.get(
            reverse('system-list'), data={
                'has_disabled_recommendation': 'false'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        #  host_01 has one disabled recommendation, so, it should not be in the response
        self.assertTrue(constants.host_01_uuid not in [system['system_uuid'] for system in json['data']])

        # Now check that when we ack another rule not covered by a hostack,
        # that rule also shows up affecting systems.
        # assert(Rule.objects.get(id=1).rule_id == constants.active_rule)
        Ack.objects.create(rule_id=1, org_id=constants.standard_org)
        response = self.client.get(
            reverse('system-list'), data={
                'has_disabled_recommendation': 'true',
                'sort': 'display_name'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        # Now most hosts are shown, as they report the active rule.
        self.assertEqual(len(json['data']), 4)
        # Sort by display_name...
        self.assertEqual(json['data'][0]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(json['data'][1]['system_uuid'], constants.host_01_uuid)  # both ack and hostack
        self.assertEqual(json['data'][2]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(json['data'][3]['system_uuid'], constants.host_04_uuid)

        # now testing with the parameter False, which means, bring all systems
        response = self.client.get(
            reverse('system-list'), data={
                'has_disabled_recommendation': 'false',
                'sort': 'display_name'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        self.assertEqual(json['meta']['count'], 1)
        self.assertEqual(len(json['data']), 1)
        self.assertEqual(json['data'][0]['system_uuid'], constants.host_05_uuid)


class SystemHighSevViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'high_severity_rule', 'high_severity_reports',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        return response.json()

    def test_list_impacting_filter(self):
        #
        response = self.client.get(
            reverse('system-list'), data={
                'incident': 'true'
            }, **auth_header_for_testing()
        )
        json = self._response_is_good(response)
        # With the incident-creating high severity rule, we have one system
        systems = json['data']
        # But the hit counts are based on all rules - is this OK?
        self.assertEqual(systems[0]['hits'], 2)
        self.assertEqual(systems[0]['display_name'], constants.host_01_name)
        self.assertEqual(len(json['data']), 1)


class SystemHostTagsViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        return response.json()

    # Remember, there's a host ack for rule 5 on host 1

    def test_system_list(self):
        response = self.client.get(
            reverse('system-list'),
            data={'sort': 'display_name'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        json = self._response_is_good(response)
        self.assertIsInstance(json, dict)
        self.assertIn('meta', json)
        self.assertIn('count', json['meta'])
        self.assertIn('links', json)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 4)
        self.assertEqual(len(json['data']), json['meta']['count'])
        # Since we've sorted by display name we can check them in that order
        self.assertEqual(json['data'][0]['display_name'], constants.host_ht_01_name)
        self.assertEqual(json['data'][0]['hits'], 1)
        self.assertEqual(json['data'][1]['display_name'], constants.host_ht_02_name)
        self.assertEqual(json['data'][1]['hits'], 2)
        self.assertEqual(json['data'][2]['display_name'], constants.host_ht_03_name)
        self.assertEqual(json['data'][2]['hits'], 2)
        self.assertEqual(json['data'][3]['display_name'], constants.host_ht_04_name)
        self.assertEqual(json['data'][3]['hits'], 2)

        # Test some host tag filtered permutations
        response = self.client.get(
            reverse('system-list'),
            data={'sort': 'display_name', 'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        json = self._response_is_good(response)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 1)
        self.assertEqual(json['data'][0]['display_name'], constants.host_ht_01_name)
        self.assertEqual(json['data'][0]['hits'], 1)

        # Test of multiple tag intersections.
        response = self.client.get(
            reverse('system-list'),
            data={'sort': 'display_name', 'tags': 'AWS/location=SFO,customer/security=high'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        json = self._response_is_good(response)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 2)
        self.assertEqual(json['data'][0]['display_name'], constants.host_ht_02_name)
        self.assertEqual(json['data'][0]['hits'], 2)
        self.assertEqual(json['data'][1]['display_name'], constants.host_ht_03_name)
        self.assertEqual(json['data'][1]['hits'], 2)

        response = self.client.get(
            reverse('system-list'),
            data={'sort': 'display_name', 'tags': 'AWS/location=SFO,customer/security=low'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        json = self._response_is_good(response)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 1)
        self.assertEqual(json['data'][0]['display_name'], constants.host_ht_04_name)
        self.assertEqual(json['data'][0]['hits'], 2)

        # Test that tag filters that match no tags return no results
        response = self.client.get(
            reverse('system-list'),
            data={'sort': 'display_name', 'tags': 'AWS/location=MSP'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        json = self._response_is_good(response)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 0)

        # Test that tag filters where there's no intersection return no results
        response = self.client.get(
            reverse('system-list'),
            data={'sort': 'display_name', 'tags': 'AWS/location=SFO,AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        json = self._response_is_good(response)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 0)

    def test_system_tags_query_param_format(self):
        #  Test that tags can be used in both tags=tag1,tag2 as well as tags=tag1&tags=tag2 formats
        response = self.client.get(
            reverse('system-list') + '?tags=AWS/location=SFO,customer/environment=web&tags=customer/security=low',
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )

        json = self._response_is_good(response)
        self.assertIn('data', json)
        self.assertIsInstance(json['data'], list)
        self.assertEqual(len(json['data']), 1)
        self.assertEqual(json['data'][0]['display_name'], constants.host_ht_04_name)

    def test_system_tags_query_param_format_inventory(self):
        with self.settings(INVENTORY_TAG_FILTERING=True):
            response = self.client.get(
                reverse('system-list') + '?tags=AWS/location=SFO,customer/environment=web&tags=customer/security=low',
                **auth_header_for_testing(account='1000000', org_id='1000000')
            )

            json = self._response_is_good(response)
            self.assertIn('data', json)
            self.assertIsInstance(json['data'], list)
            self.assertEqual(len(json['data']), 1)
            self.assertEqual(json['data'][0]['display_name'], constants.host_ht_04_name)

    def test_get_system(self):
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': constants.host_ht_01_uuid
            }),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        system = self._response_is_good(response)
        self.assertIn('hits', system)
        self.assertEqual(system['hits'], 1)
        self.assertIn('system_uuid', system)
        self.assertEqual(system['system_uuid'], constants.host_ht_01_uuid)
        self.assertIn('display_name', system)
        self.assertEqual(system['display_name'], constants.host_ht_01_name)
        self.assertIn('last_seen', system)
        self.assertEqual(system['last_seen'], '2019-12-17T02:00:51Z')

        # Use a tag filter that includes this host:
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': constants.host_ht_01_uuid
            }),
            data={'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        system = self._response_is_good(response)
        self.assertIn('system_uuid', system)
        self.assertEqual(system['system_uuid'], constants.host_ht_01_uuid)
        self.assertIn('display_name', system)
        self.assertEqual(system['display_name'], constants.host_ht_01_name)

        # Use a tag filter that excludes this host:
        response = self.client.get(
            reverse('system-detail', kwargs={
                'uuid': constants.host_ht_01_uuid
            }),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        # And we should get a 404
        self.assertEqual(response.status_code, 404)

    def test_reports_on_system(self):
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_ht_01_uuid
            }),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        rules = self._response_is_good(response)
        self.assertIsInstance(rules, list)
        self.assertEqual(len(rules), 1)  # one non-acked rule on this system
        self.assertIn('rule', rules[0])
        self.assertIn('rule_id', rules[0]['rule'])
        self.assertEqual(rules[0]['rule']['rule_id'], constants.active_rule)

        # Use a tag filter that includes this host:
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_ht_01_uuid
            }),
            data={'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        rules = self._response_is_good(response)
        self.assertIsInstance(rules, list)
        self.assertEqual(rules[0]['rule']['rule_id'], constants.active_rule)

        # Use a tag filter that excludes this host:
        response = self.client.get(
            reverse('system-reports', kwargs={
                'uuid': constants.host_ht_01_uuid
            }),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        # We don't get a 404, we get no data.
        rules = self._response_is_good(response)
        self.assertIsInstance(rules, list)
        self.assertEqual(len(rules), 0)
