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

from api.permissions import auth_header_for_testing
from api.tests import constants

"""
A test suite for all those views that just produce simple static data.
"""


class StaticViewsTestCase(TestCase):
    fixtures = ['system_types']
    std_header = auth_header_for_testing()
    cert_header = auth_header_for_testing(system_opts=constants.host_03_system_data)

    def test_account_products(self):
        response = self.client.get(reverse('sat-compat-account-products'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, ['rhel'])

        response = self.client.get(reverse('sat-compat-account-products'), **self.cert_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, ['rhel'])

    def test_account_settings(self):
        response = self.client.get(reverse('sat-compat-account-settings'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {"name": "Show Satellite Systems", "value": True}
        ])

        response = self.client.get(reverse('sat-compat-account-settings'), **self.cert_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {"name": "Show Satellite Systems", "value": True}
        ])

    def test_account_v2_products(self):
        response = self.client.get(reverse('sat-compat-v2-account-products'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, ['rhel'])

        response = self.client.get(reverse('sat-compat-v2-account-products'), **self.cert_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, ['rhel'])

    def test_account_v2_settings(self):
        response = self.client.get(reverse('sat-compat-v2-account-settings'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {"name": "Show Satellite Systems", "value": True}
        ])

        response = self.client.get(reverse('sat-compat-v2-account-settings'), **self.cert_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {"name": "Show Satellite Systems", "value": True}
        ])

    def test_articles_overview(self):
        response = self.client.get(reverse('sat-compat-articles-overview-satellite6'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertIn('content_html', json_data)
        self.assertIn('id', json_data)
        self.assertIn('title', json_data)
        self.assertIn('content', json_data)

        response = self.client.get(reverse('sat-compat-articles-overview-satellite6'), **self.cert_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertIn('content_html', json_data)
        self.assertIn('id', json_data)
        self.assertIn('title', json_data)
        self.assertIn('content', json_data)

    def test_branch_info(self):
        response = self.client.get(
            reverse('sat-compat-v1-branch-info-list'), **self.std_header
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data['remote_branch'], -1)
        self.assertEqual(json_data['remote_leaf'], -1)

    def test_evaluation_status(self):
        response = self.client.get(reverse('sat-compat-evaluation-status'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {
            'expired': False, 'purchased': True, 'available': []
        })

    def test_group_v1_list(self):
        response = self.client.get(reverse('sat-compat-v1-groups-list'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [])

    def test_group_v3_list(self):
        response = self.client.get(reverse('sat-compat-v3-groups-list'), **self.std_header)
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [])
