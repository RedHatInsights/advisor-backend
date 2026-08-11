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
from django.urls import reverse

from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing


class WorkloadsFieldRedirectionTestCase(TestCase):
    """
    Test workloads-related field filtering through actual API endpoints.

    SAP, Ansible, and MSSQL use flat legacy paths (e.g. filter[system_profile][ansible])
    that are redirected internally to filter[system_profile][workloads][*].

    CrowdStrike, IBM Db2, InterSystems, Oracle DB, and RHEL AI were introduced
    directly under filter[system_profile][workloads][*] and require no redirection.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        """Helper to verify response is valid and return JSON data."""
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        return response.json()

    def test_sap_system_field_redirection_new_schema(self):
        """Test SAP system field filtering works through API."""
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][sap_system]': 'true'},
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        self.assertIsInstance(systems, list)
        # Expect exactly 4 SAP systems with workloads.sap in account 1234567
        expected_sap_systems = {
            constants.host_01_uuid,
            constants.host_04_uuid,
            constants.host_05_uuid,
            constants.host_e1_uuid,
        }
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), len(expected_sap_systems))
        self.assertEqual(json_data['meta']['count'], len(expected_sap_systems))
        self.assertEqual(actual_system_uuids, expected_sap_systems)

    def test_sap_sids_field_redirection_new_schema(self):
        """Test SAP SIDs field filtering works through API."""
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][sap_sids][contains]': 'E02'},
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        self.assertIsInstance(systems, list)
        # Expect exactly 2 systems with E02 SID in account 1234567
        expected_systems = {constants.host_01_uuid, constants.host_04_uuid}
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 2)
        self.assertEqual(json_data['meta']['count'], 2)
        self.assertEqual(actual_system_uuids, expected_systems)

    def test_ansible_field_redirection_new_schema(self):
        """Test Ansible field filtering works through API."""
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][ansible][not_nil]': 'true'},
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        self.assertIsInstance(systems, list)
        # Expect exactly 2 systems with Ansible workloads in account 1234567
        expected_ansible_systems = {constants.host_03_uuid, constants.host_05_uuid}
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 2)
        self.assertEqual(json_data['meta']['count'], 2)
        self.assertEqual(actual_system_uuids, expected_ansible_systems)

    def test_mssql_field_redirection_new_schema(self):
        """Test MSSQL field filtering works through API."""
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][mssql][not_nil]': 'true'},
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        self.assertIsInstance(systems, list)
        # Expect exactly 2 systems with MSSQL workloads in account 1234567
        expected_mssql_systems = {constants.host_04_uuid, constants.host_06_uuid}
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 2)
        self.assertEqual(json_data['meta']['count'], 2)
        self.assertEqual(actual_system_uuids, expected_mssql_systems)

    def test_multiple_workloads_fields_new_schema(self):
        """Test multiple workloads fields together through API."""
        # Test SAP + Ansible combination
        response = self.client.get(
            reverse('system-list'),
            data={
                'filter[system_profile][sap_system]': 'true',
                'filter[system_profile][ansible][not_nil]': 'true'
            },
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        self.assertIsInstance(systems, list)
        # Expect exactly 1 system with both SAP and Ansible workloads
        expected_combined_systems = {constants.host_05_uuid}
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 1)
        self.assertEqual(json_data['meta']['count'], 1)
        self.assertEqual(actual_system_uuids, expected_combined_systems)

    def test_non_workloads_fields_unaffected(self):
        """Test that non-workloads fields work normally through API."""
        response = self.client.get(
            reverse('system-list'),
            data={
                'filter[system_profile][arch][eq]': 'x86_64',
                'filter[system_profile][system_memory_bytes][gt]': '10000'
            },
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        # Non-workloads fields should work normally
        # This should return systems that meet the criteria
        self.assertIsInstance(systems, list)
        self.assertIn('meta', json_data)
        self.assertIn('count', json_data['meta'])

        # 6 systems are visible after staleness filtering (9 total - 3 stale-hide systems)
        self.assertEqual(len(systems), 6)
        self.assertEqual(json_data['meta']['count'], 6)

    def test_canonical_workloads_path(self):
        """Test filtering for workloads that live natively under filter[system_profile][workloads][*]."""
        cases = [
            ('crowdstrike', {constants.host_01_uuid, constants.host_e1_uuid}),
            ('ibm_db2', {constants.host_03_uuid}),
            ('intersystems', {constants.host_04_uuid}),
            ('oracle_db', {constants.host_06_uuid}),
            ('rhel_ai', {constants.host_05_uuid}),
        ]
        for workload_name, expected_uuids in cases:
            with self.subTest(workload=workload_name):
                response = self.client.get(
                    reverse('system-list'),
                    data={f'filter[system_profile][workloads][{workload_name}][not_nil]': 'true'},
                    **auth_header_for_testing()
                )
                json_data = self._response_is_good(response)
                systems = json_data['data']
                actual_uuids = {system['system_uuid'] for system in systems}
                self.assertEqual(actual_uuids, expected_uuids)
                self.assertEqual(json_data['meta']['count'], len(expected_uuids))

    def test_workloads_false_filtering(self):
        """Test filtering systems without specific workloads."""
        # Test filtering for systems without MSSQL
        response = self.client.get(
            reverse('system-list'),
            data={'filter[system_profile][mssql][not_nil]': 'false'},
            **auth_header_for_testing()
        )
        json_data = self._response_is_good(response)
        systems = json_data['data']

        self.assertIsInstance(systems, list)
        # Expect 3 systems (5 visible - 2 with workloads.mssql)
        # Note: stale-hide systems (host_08, host_0A, host_e1) are filtered out by staleness
        expected_non_mssql_systems = {
            constants.host_01_uuid, constants.host_03_uuid,
            constants.host_05_uuid, constants.host_e1_uuid,
        }
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 4)
        self.assertEqual(json_data['meta']['count'], 4)
        self.assertEqual(actual_system_uuids, expected_non_mssql_systems)


class WorkloadQueryParamTestCase(TestCase):
    """
    Test the workload query parameter (?workload=sap, ?workload=ansible, etc.)
    which filters systems by workload type via filter_on_workload().

    This is distinct from the filter[system_profile][...] bracket-syntax
    filtering tested in WorkloadsFieldRedirectionTestCase above.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _get_system_uuids(self, data=None):
        """Helper to GET system-list and return the set of system UUIDs."""
        response = self.client.get(
            reverse('system-list'), data=data or {},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        json_data = response.json()
        return json_data, {s['system_uuid'] for s in json_data['data']}

    def test_workload_sap(self):
        """SAP filter checks sap_system=True, not just presence of the sap key."""
        json_data, uuids = self._get_system_uuids({'workload': 'sap'})
        # host_01, host_04, host_05, host_e1 have sap_system=True
        # host_03, host_06 have sap_system=false so are excluded
        expected = {
            constants.host_01_uuid, constants.host_04_uuid,
            constants.host_05_uuid, constants.host_e1_uuid,
        }
        self.assertEqual(json_data['meta']['count'], len(expected))
        self.assertEqual(uuids, expected)

    def test_workload_ansible(self):
        json_data, uuids = self._get_system_uuids({'workload': 'ansible'})
        expected = {constants.host_03_uuid, constants.host_05_uuid}
        self.assertEqual(json_data['meta']['count'], len(expected))
        self.assertEqual(uuids, expected)

    def test_workload_mssql(self):
        json_data, uuids = self._get_system_uuids({'workload': 'mssql'})
        expected = {constants.host_04_uuid, constants.host_06_uuid}
        self.assertEqual(json_data['meta']['count'], len(expected))
        self.assertEqual(uuids, expected)

    def test_workload_crowdstrike(self):
        json_data, uuids = self._get_system_uuids({'workload': 'crowdstrike'})
        expected = {constants.host_01_uuid, constants.host_e1_uuid}
        self.assertEqual(json_data['meta']['count'], len(expected))
        self.assertEqual(uuids, expected)

    def test_workload_single_host_types(self):
        """Each of these workloads is present on exactly one visible host."""
        cases = [
            ('ibm_db2', {constants.host_03_uuid}),
            ('intersystems', {constants.host_04_uuid}),
            ('oracle_db', {constants.host_06_uuid}),
            ('rhel_ai', {constants.host_05_uuid}),
        ]
        for workload_name, expected in cases:
            with self.subTest(workload=workload_name):
                json_data, uuids = self._get_system_uuids({'workload': workload_name})
                self.assertEqual(json_data['meta']['count'], len(expected))
                self.assertEqual(uuids, expected)

    def test_multiple_workloads_ored(self):
        """Multiple workload values are OR'd together."""
        json_data, uuids = self._get_system_uuids({
            'workload': 'mssql,crowdstrike'
        })
        # mssql: host_04, host_06; crowdstrike: host_01, host_e1
        expected = {
            constants.host_01_uuid, constants.host_04_uuid,
            constants.host_06_uuid, constants.host_e1_uuid,
        }
        self.assertEqual(json_data['meta']['count'], len(expected))
        self.assertEqual(uuids, expected)

    def test_multiple_workloads_overlap(self):
        """OR with overlapping hosts doesn't duplicate."""
        json_data, uuids = self._get_system_uuids({
            'workload': 'sap,crowdstrike'
        })
        # sap: host_01, host_04, host_05, host_e1
        # crowdstrike: host_01, host_e1 (subset of sap hosts)
        expected = {
            constants.host_01_uuid, constants.host_04_uuid,
            constants.host_05_uuid, constants.host_e1_uuid,
        }
        self.assertEqual(json_data['meta']['count'], len(expected))
        self.assertEqual(uuids, expected)

    def test_no_workload_param_returns_all(self):
        """Without the workload param, all visible systems are returned."""
        json_data, uuids = self._get_system_uuids()
        # 6 visible systems in the standard org
        self.assertEqual(json_data['meta']['count'], 6)
        self.assertEqual(len(uuids), 6)

    def test_workload_on_rules_list(self):
        """The workload filter affects impacted_systems_count on rules."""
        # With ansible filter: only host_03 and host_05 are visible
        response = self.client.get(
            reverse('rule-list'), data={'workload': 'ansible'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        rules = response.json()['data']
        # Find the active rule and check its impacted count
        for rule in rules:
            if rule['rule_id'] == constants.active_rule:
                # active_rule hits: host_01, host_03, host_04, host_06
                # intersected with ansible hosts (host_03, host_05) => host_03
                self.assertEqual(rule['impacted_systems_count'], 1)
                break

    def test_workload_on_stats(self):
        """The workload filter affects stats-systems counts."""
        response = self.client.get(
            reverse('stats-systems'), data={'workload': 'mssql'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        stats = response.json()
        # mssql hosts: host_04, host_06
        # host_04 has hits (active_rule, second_rule), host_06 has hits (active_rule)
        self.assertEqual(stats['total'], 2)
