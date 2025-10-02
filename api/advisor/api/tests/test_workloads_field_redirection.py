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
    Test workloads field redirection functionality for schema compatibility.

    Tests that workloads-related fields (SAP, Ansible, MSSQL) are correctly
    redirected between old and new schemas through actual API endpoints.
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
        # Expect exactly 3 SAP systems with workloads.sap in account 1234567
        expected_sap_systems = {
            constants.host_01_uuid,
            constants.host_04_uuid,
            constants.host_05_uuid,
        }
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 3)
        self.assertEqual(json_data['meta']['count'], 3)
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

        # 5 systems are visible after staleness filtering (8 total - 3 stale-hide systems)
        self.assertEqual(len(systems), 5)
        self.assertEqual(json_data['meta']['count'], 5)

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
            constants.host_01_uuid, constants.host_03_uuid, constants.host_05_uuid
        }
        actual_system_uuids = {system['system_uuid'] for system in systems}

        self.assertEqual(len(systems), 3)
        self.assertEqual(json_data['meta']['count'], 3)
        self.assertEqual(actual_system_uuids, expected_non_mssql_systems)
