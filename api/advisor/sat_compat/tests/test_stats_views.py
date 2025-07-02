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


class StatsTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_standard_stats_view(self):
        response = self.client.get(reverse('sat-compat-stats-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertIn('systems', json_data)
        self.assertIsInstance(json_data['systems'], dict)
        self.assertEqual(json_data['systems'], {
            'total': 6,
            'affected': 4,
        })
        self.assertIn('reports', json_data)
        self.assertIsInstance(json_data['reports'], dict)
        self.assertEqual(json_data['reports'], {
            'total': 6,
            'info': 6,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 4,
            'security': 0,
            'stability': 0,
            'performance': 2,
        })
        self.assertIn('rules', json_data)
        self.assertIsInstance(json_data['rules'], dict)
        self.assertEqual(json_data['rules'], {
            'total': 2,
            'info': 2,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 1,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })

    def test_standard_stats_view_cert_auth(self):
        # Certificate authentication should limit the view to only the
        # systems managed by Satellite host 03 - hosts 1, 3 and 5
        response = self.client.get(
            reverse('sat-compat-stats-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertIn('systems', json_data)
        self.assertIsInstance(json_data['systems'], dict)
        self.assertEqual(json_data['systems'], {
            'total': 6,
            'affected': 2,  # Only systems 1 and 3
        })
        self.assertIn('reports', json_data)
        self.assertIsInstance(json_data['reports'], dict)
        self.assertEqual(json_data['reports'], {  # Systems 1, 3 and 5
            'total': 3,
            'info': 3,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 2,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })
        self.assertIn('rules', json_data)
        self.assertIsInstance(json_data['rules'], dict)
        self.assertEqual(json_data['rules'], {  # Active and Second rule
            'total': 2,
            'info': 2,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 1,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })

    def test_standard_stats_view_min_severity(self):
        response = self.client.get(
            reverse('sat-compat-stats-list'),
            data={'minSeverity': 'CRITICAL'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertIn('systems', json_data)
        self.assertIsInstance(json_data['systems'], dict)
        self.assertEqual(json_data['systems'], {
            'total': 6,
            'affected': 0,
        })

    def test_standard_stats_view_with_branch_id(self):
        response = self.client.get(
            reverse('sat-compat-stats-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        # Systems 1, 3, 5 and 9 - 1 has two active reports, 3 has one
        self.assertIn('systems', json_data)
        self.assertIsInstance(json_data['systems'], dict)
        self.assertEqual(json_data['systems'], {
            'total': 4,
            'affected': 2,
        })
        self.assertIn('reports', json_data)
        self.assertIsInstance(json_data['reports'], dict)
        self.assertEqual(json_data['reports'], {
            'total': 3,
            'info': 3,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 2,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })
        self.assertIn('rules', json_data)
        self.assertIsInstance(json_data['rules'], dict)
        self.assertEqual(json_data['rules'], {
            'total': 2,
            'info': 2,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 1,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })

    def test_rules_stats_view(self):
        response = self.client.get(reverse('sat-compat-stats-rules'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {
            'total': 2,
            'info': 2,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 1,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })
        # Branch ID
        response = self.client.get(
            reverse('sat-compat-stats-rules'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {
            'total': 2,
            'info': 2,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 1,
            'security': 0,
            'stability': 0,
            'performance': 1,
        })

    def test_rules_stats_view_min_severity(self):
        response = self.client.get(
            reverse('sat-compat-stats-rules'),
            data={'minSeverity': 'CRITICAL'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {
            'total': 0,
            'info': 0,
            'warn': 0,
            'error': 0,
            'critical': 0,
            'availability': 0,
            'security': 0,
            'stability': 0,
            'performance': 0,
        })

    def test_systems_stats_view(self):
        response = self.client.get(reverse('sat-compat-stats-systems'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {
            'total': 6,
            'affected': 4,
        })
        # Branch ID
        response = self.client.get(
            reverse('sat-compat-stats-systems'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        # Systems 1, 3, 5 and 9 - 1 has two active reports, 3 has one
        self.assertEqual(json_data, {
            'total': 4,
            'affected': 2,
        })

    def test_systems_stats_view_min_severity(self):
        response = self.client.get(
            reverse('sat-compat-stats-systems'),
            data={'minSeverity': 'CRITICAL'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {
            'total': 6,
            'affected': 0,
        })
