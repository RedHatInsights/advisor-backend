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

from unittest.mock import Mock, patch
from django.test import TestCase
from django.db.models import Q

from api.filters import filter_multi_param
from feature_flags import FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION


class WorkloadsFieldRedirectionTestCase(TestCase):
    """
    Test workloads field redirection functionality for schema compatibility.
    
    Tests that workloads-related fields (SAP, Ansible, MSSQL) are correctly
    redirected between old and new schemas based on the feature flag.
    """

    def setUp(self):
        """Set up mock request objects for testing."""
        self.mock_request = Mock()
        
    def _setup_mock_request(self, query_params):
        """Helper to set up mock request with given query parameters."""
        self.mock_request.query_params = query_params
        self.mock_request.query_params.lists.return_value = [
            (param, [value]) for param, value in query_params.items()
        ]

    def test_sap_system_field_redirection_old_schema(self):
        """Test SAP system field with old schema (feature flag OFF)."""
        self._setup_mock_request({
            'filter[system_profile][sap_system]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = False
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate original path: system_profile__sap_system
            self.assertIsInstance(result, Q)
            # The Q object should contain the old field path
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__sap_system', filter_dict)
            self.assertEqual(filter_dict['system_profile__sap_system'], True)

    def test_sap_system_field_redirection_new_schema(self):
        """Test SAP system field with new schema (feature flag ON)."""
        self._setup_mock_request({
            'filter[system_profile][sap_system]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate new path: system_profile__workloads__sap__sap_system
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__workloads__sap__sap_system', filter_dict)
            self.assertEqual(filter_dict['system_profile__workloads__sap__sap_system'], True)

    def test_sap_sids_field_redirection_old_schema(self):
        """Test SAP SIDs field with old schema (feature flag OFF)."""
        self._setup_mock_request({
            'filter[system_profile][sap_sids][contains]': 'ABC'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = False
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate original path: system_profile__sap_sids__contains
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__sap_sids__contains', filter_dict)
            self.assertEqual(filter_dict['system_profile__sap_sids__contains'], 'ABC')

    def test_sap_sids_field_redirection_new_schema(self):
        """Test SAP SIDs field with new schema (feature flag ON)."""
        self._setup_mock_request({
            'filter[system_profile][sap_sids][contains]': 'ABC'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate new path: system_profile__workloads__sap__sids__contains
            # Note: field name changes from sap_sids to sids
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__workloads__sap__sids__contains', filter_dict)
            self.assertEqual(filter_dict['system_profile__workloads__sap__sids__contains'], 'ABC')

    def test_ansible_field_redirection_old_schema(self):
        """Test Ansible field with old schema (feature flag OFF)."""
        self._setup_mock_request({
            'filter[system_profile][ansible]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = False
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate original path: system_profile__ansible
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__ansible', filter_dict)
            self.assertEqual(filter_dict['system_profile__ansible'], True)

    def test_ansible_field_redirection_new_schema(self):
        """Test Ansible field with new schema (feature flag ON)."""
        self._setup_mock_request({
            'filter[system_profile][ansible]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate new path: system_profile__workloads__ansible
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__workloads__ansible', filter_dict)
            self.assertEqual(filter_dict['system_profile__workloads__ansible'], True)

    def test_mssql_field_redirection_old_schema(self):
        """Test MSSQL field with old schema (feature flag OFF)."""
        self._setup_mock_request({
            'filter[system_profile][mssql]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = False
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate original path: system_profile__mssql
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__mssql', filter_dict)
            self.assertEqual(filter_dict['system_profile__mssql'], True)

    def test_mssql_field_redirection_new_schema(self):
        """Test MSSQL field with new schema (feature flag ON)."""
        self._setup_mock_request({
            'filter[system_profile][mssql]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate new path: system_profile__workloads__mssql
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('system_profile__workloads__mssql', filter_dict)
            self.assertEqual(filter_dict['system_profile__workloads__mssql'], True)

    def test_multiple_workloads_fields_new_schema(self):
        """Test multiple workloads fields together with new schema."""
        self._setup_mock_request({
            'filter[system_profile][sap_system]': 'true',
            'filter[system_profile][ansible]': 'true',
            'filter[system_profile][mssql]': 'false'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should generate new paths for all workloads fields
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            
            self.assertIn('system_profile__workloads__sap__sap_system', filter_dict)
            self.assertIn('system_profile__workloads__ansible', filter_dict)
            self.assertIn('system_profile__workloads__mssql', filter_dict)
            
            self.assertEqual(filter_dict['system_profile__workloads__sap__sap_system'], True)
            self.assertEqual(filter_dict['system_profile__workloads__ansible'], True)
            self.assertEqual(filter_dict['system_profile__workloads__mssql'], False)

    def test_non_workloads_fields_unaffected(self):
        """Test that non-workloads fields are not affected by redirection."""
        self._setup_mock_request({
            'filter[system_profile][cpu_count]': '4',
            'filter[system_profile][memory]': '8192'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Non-workloads fields should maintain original paths
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            
            self.assertIn('system_profile__cpu_count', filter_dict)
            self.assertIn('system_profile__memory', filter_dict)
            self.assertEqual(filter_dict['system_profile__cpu_count'], 4)  # Converted to int
            self.assertEqual(filter_dict['system_profile__memory'], 4096)  # Converted to int

    def test_workloads_with_relations(self):
        """Test workloads field redirection with relation prefixes."""
        self._setup_mock_request({
            'filter[system_profile][sap_system]': 'true'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(
                self.mock_request, 'system_profile', field_prefix='inventory'
            )
            
            # Should generate: inventory__system_profile__workloads__sap__sap_system
            self.assertIsInstance(result, Q)
            filter_dict = self._extract_q_filter_dict(result)
            self.assertIn('inventory__system_profile__workloads__sap__sap_system', filter_dict)
            self.assertEqual(filter_dict['inventory__system_profile__workloads__sap__sap_system'], True)

    def test_sap_sids_with_complex_operations(self):
        """Test SAP SIDs with complex operations like 'ne' (not equal)."""
        self._setup_mock_request({
            'filter[system_profile][sap_sids][ne]': 'ABC'
        })
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            result = filter_multi_param(self.mock_request, 'system_profile')
            
            # Should handle complex operations with new field path
            self.assertIsInstance(result, Q)
            # For 'ne' operations, the result should be a negated Q object
            self.assertTrue(result.negated)

    def test_feature_flag_import_availability(self):
        """Test that the feature flag is properly imported and accessible."""
        # This test ensures the feature flag import works correctly
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            # The feature flag should be callable
            from api.filters import feature_flag_is_enabled, FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION
            
            # Verify the import works
            result = feature_flag_is_enabled(FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION)
            self.assertTrue(result)
            mock_flag.assert_called_once_with(FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION)

    def _extract_q_filter_dict(self, q_object):
        """
        Helper method to extract filter dictionary from Q object.
        
        This handles the internal structure of Django Q objects to extract
        the actual field-value pairs for testing.
        """
        filter_dict = {}
        
        if hasattr(q_object, 'children') and q_object.children:
            for child in q_object.children:
                if isinstance(child, tuple) and len(child) == 2:
                    field_name, value = child
                    filter_dict[field_name] = value
                elif hasattr(child, 'children'):
                    # Recursively handle nested Q objects
                    nested_dict = self._extract_q_filter_dict(child)
                    filter_dict.update(nested_dict)
        
        return filter_dict


class WorkloadsFieldCompatibilityIntegrationTestCase(TestCase):
    """
    Integration tests to verify end-to-end compatibility of workloads field redirection.
    
    These tests verify that the field redirection works in realistic scenarios
    similar to actual API usage.
    """

    def test_api_parameter_compatibility_old_schema(self):
        """Test that API parameters work correctly with old schema."""
        mock_request = Mock()
        mock_request.query_params = {
            'filter[system_profile][sap_system]': 'true',
            'filter[system_profile][ansible]': 'true',
            'filter[system_profile][mssql]': 'false'
        }
        mock_request.query_params.lists.return_value = [
            ('filter[system_profile][sap_system]', ['true']),
            ('filter[system_profile][ansible]', ['true']),
            ('filter[system_profile][mssql]', ['false'])
        ]
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = False
            
            # This should work as before with old field paths
            system_profile_filter = filter_multi_param(mock_request, 'system_profile')
            
            self.assertIsInstance(system_profile_filter, Q)
            # Verify it doesn't contain new workloads paths
            q_str = str(system_profile_filter)
            self.assertNotIn('workloads', q_str)

    def test_api_parameter_compatibility_new_schema(self):
        """Test that API parameters work correctly with new schema."""
        mock_request = Mock()
        mock_request.query_params = {
            'filter[system_profile][sap_system]': 'true',
            'filter[system_profile][ansible]': 'true',
            'filter[system_profile][mssql]': 'false'
        }
        mock_request.query_params.lists.return_value = [
            ('filter[system_profile][sap_system]', ['true']),
            ('filter[system_profile][ansible]', ['true']),
            ('filter[system_profile][mssql]', ['false'])
        ]
        
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            
            # This should work with new workloads field paths
            system_profile_filter = filter_multi_param(mock_request, 'system_profile')
            
            self.assertIsInstance(system_profile_filter, Q)
            # Verify it contains new workloads paths
            q_str = str(system_profile_filter)
            self.assertIn('workloads', q_str)

    def test_backward_compatibility_guarantee(self):
        """Test that the same API call works with both schemas."""
        # Same request parameters
        query_params = {
            'filter[system_profile][sap_system]': 'true',
            'filter[system_profile][ansible]': 'true'
        }
        
        def create_mock_request():
            mock_request = Mock()
            mock_request.query_params = query_params
            mock_request.query_params.lists.return_value = [
                (param, [value]) for param, value in query_params.items()
            ]
            return mock_request
        
        # Test with old schema
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = False
            old_schema_result = filter_multi_param(create_mock_request(), 'system_profile')
        
        # Test with new schema
        with patch('api.filters.feature_flag_is_enabled') as mock_flag:
            mock_flag.return_value = True
            new_schema_result = filter_multi_param(create_mock_request(), 'system_profile')
        
        # Both should produce valid Q objects (different paths, same logical intent)
        self.assertIsInstance(old_schema_result, Q)
        self.assertIsInstance(new_schema_result, Q)
        
        # The results should be different (different field paths) but both valid
        self.assertNotEqual(str(old_schema_result), str(new_schema_result))

