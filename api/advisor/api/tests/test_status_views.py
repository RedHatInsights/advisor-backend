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

import responses
from requests.exceptions import Timeout

from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse

from api.permissions import auth_header_for_testing
from api.tests import constants

TEST_RBAC_URL = 'http://rbac.svc/'

NORMAL_SETTINGS = {
    'MIDDLEWARE_HOST_URL': 'http://localhost',
    'INVENTORY_SERVER_URL': 'http://localhost',
    'REMEDIATIONS_URL': 'http://localhost/',
}


class StatusTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def test_status_list(self):
        # No auth required
        response = self.client.get(reverse('status-list'))
        self.assertEqual(response.status_code, 200)
        # But auth OK anyway
        response = self.client.get(reverse('status-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', **NORMAL_SETTINGS)
    @responses.activate
    def test_status_ready_all_good(self):
        # RBAC will respond, but we don't care if it's sensible or not.
        responses.add(
            responses.GET, settings.RBAC_URL,
            json={'nonsense': 'complete'}, status=200
        )
        # No auth required
        response = self.client.get(reverse('status-ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'database', 'rbac', 'environment', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], [])
        # But auth OK anyway
        response = self.client.get(reverse('status-ready'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'database', 'rbac', 'environment', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], [])

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', **NORMAL_SETTINGS)
    @responses.activate
    def test_status_ready_rbac_timing_out(self):
        # RBAC is taking a really long time
        responses.add(
            responses.GET, settings.RBAC_URL, body=Timeout()
        )
        # No auth required
        response = self.client.get(reverse('status-ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'environment', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Error connecting to RBAC: '])
        # But auth doesn't make a difference
        response = self.client.get(reverse('status-ready'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'environment', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Error connecting to RBAC: '])

    # We don't know what the build environment is going to have set, so
    # specifically undefine things so we can check this is detected.
    @override_settings(
        RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', MIDDLEWARE_HOST_URL=None,
        INVENTORY_SERVER_URL=None,
    )
    @responses.activate
    def test_status_ready_environment_not_set(self):
        responses.add(
            responses.GET, settings.RBAC_URL,
            json={'nonsense': 'complete'}, status=200
        )
        # No auth required
        response = self.client.get(reverse('status-ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'rbac', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('environment', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(sorted(json_data['errors']), [
            'Environment error: INVENTORY_SERVER_URL not set',
            'Environment error: MIDDLEWARE_HOST_URL not set',
            'Environment error: REMEDIATIONS_URL not set',
        ])
        # But auth doesn't make a difference
        response = self.client.get(reverse('status-ready'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'rbac', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('environment', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(sorted(json_data['errors']), [
            'Environment error: INVENTORY_SERVER_URL not set',
            'Environment error: MIDDLEWARE_HOST_URL not set',
            'Environment error: REMEDIATIONS_URL not set',
        ])

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', **NORMAL_SETTINGS)
    @responses.activate
    def test_status_ready_rbac_bad_connection(self):
        responses.add(
            responses.GET, TEST_RBAC_URL, body=ConnectionError("Test raises an exception")
        )
        # No auth required
        response = self.client.get(reverse('status-ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'environment', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Error connecting to RBAC: Test raises an exception'])
        # But auth doesn't make a difference
        response = self.client.get(reverse('status-ready'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'environment', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Error connecting to RBAC: Test raises an exception'])

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', **NORMAL_SETTINGS)
    @responses.activate
    def test_status_ready_rbac_failing(self):
        # RBAC is failing (politely at the moment)
        responses.add(
            responses.GET, settings.RBAC_URL, status=500
        )
        # No auth required
        response = self.client.get(reverse('status-ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'environment', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Connection to RBAC returned 500: '])
        # But auth doesn't make a difference
        response = self.client.get(reverse('status-ready'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'environment', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Connection to RBAC returned 500: '])

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', **NORMAL_SETTINGS)
    @responses.activate
    def test_status_live_all_good(self):
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true'):
            # RBAC will respond, but we don't care if it's sensible or not.
            responses.add(
                responses.GET, settings.RBAC_URL,
                json={'nonsense': 'complete'}, status=200
            )
            # No auth required
            response = self.client.get(reverse('status-live'))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.accepted_media_type, constants.json_mime)
            json_data = response.json()
            self.assertIsInstance(json_data, dict)
            for facility in ('django', 'database', 'rbac', 'environment', 'advisor'):
                self.assertIn(facility, json_data, f"Facility {facility} not found")
                self.assertTrue(json_data[facility], f"Facility {facility} should be True")
            self.assertIn('errors', json_data)
            self.assertEqual(json_data['errors'], [])
            # But auth OK anyway
            response = self.client.get(reverse('status-live'), **auth_header_for_testing())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.accepted_media_type, constants.json_mime)
            json_data = response.json()
            self.assertIsInstance(json_data, dict)
            for facility in ('django', 'database', 'rbac', 'environment', 'advisor'):
                self.assertIn(facility, json_data, f"Facility {facility} not found")
                self.assertTrue(json_data[facility], f"Facility {facility} should be True")
            self.assertIn('errors', json_data)
            self.assertEqual(json_data['errors'], [])

    @override_settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED='true', **NORMAL_SETTINGS)
    @responses.activate
    def test_status_live_rbac_failing(self):
        # RBAC is failing (politely at the moment)
        responses.add(
            responses.GET, settings.RBAC_URL, status=500
        )
        # No auth required
        response = self.client.get(reverse('status-live'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Connection to RBAC returned 500: '])
        # But auth doesn't make a difference
        response = self.client.get(reverse('status-live'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        for facility in ('django', 'database'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertTrue(json_data[facility], f"Facility {facility} should be True")
        for facility in ('rbac', 'advisor'):
            self.assertIn(facility, json_data, f"Facility {facility} not found")
            self.assertFalse(json_data[facility], f"Facility {facility} should be False")
        self.assertIn('errors', json_data)
        self.assertEqual(json_data['errors'], ['Connection to RBAC returned 500: '])
