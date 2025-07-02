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


class PreferencesTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data',
    ]

    def _response_is_good(self, response):
        # Good response status is 200
        self.assertEqual(response.status_code, 200, response.content.decode())
        # Standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Test content is decodable as JSON
        return response.json()

    def test_preferences_ddf_view(self):
        response = self.client.get(
            reverse('user-preferences-list'), **auth_header_for_testing()
        )
        preferences_ddf = self._response_is_good(response)
        # Break this down so diffs aren't so big:
        self.assertIsInstance(preferences_ddf, list)
        self.assertEqual(len(preferences_ddf), 1)
        self.assertIsInstance(preferences_ddf[0], dict)
        self.assertEqual(sorted(preferences_ddf[0].keys()), ['fields'])
        field_list = preferences_ddf[0]['fields']
        self.assertIsInstance(field_list, list)
        self.assertEqual(len(field_list), 1)
        self.assertIsInstance(field_list[0], dict)
        self.assertEqual(field_list[0], {
            "name": "is_subscribed",
            "title": "Weekly report",
            'label': 'Weekly Report',
            "description": "Subscribe to this account's Advisor Weekly Report email",
            'helperText': "User-specific setting to subscribe a user to the account's weekly reports email",
            "component": "descriptiveCheckbox",
            "isRequired": True,
            "initialValue": False,
            "isDisabled": False
        })

    def test_preferences_update(self):
        # Subscribe to my newsletter
        response = self.client.post(
            reverse('user-preferences-list'),
            data={
                'is_subscribed': True,
            },
            **auth_header_for_testing()
        )
        preferences = self._response_is_good(response)
        self.assertIsInstance(preferences, dict)
        self.assertEqual(preferences, {
            'is_subscribed': True,
        })

        # Get DDF list now that we've added an AccountSetting object
        response = self.client.get(
            reverse('user-preferences-list'), **auth_header_for_testing()
        )
        settings_ddf = self._response_is_good(response)
        # Break this down so diffs aren't so big:
        self.assertIsInstance(settings_ddf, list)
        self.assertEqual(len(settings_ddf), 1)
        self.assertIsInstance(settings_ddf[0], dict)
        self.assertEqual(sorted(settings_ddf[0].keys()), ['fields'])
        field_list = settings_ddf[0]['fields']
        self.assertIsInstance(field_list, list)
        self.assertEqual(len(field_list), 1)
        self.assertIsInstance(field_list[0], dict)
        self.assertEqual(field_list[0], {
            "name": "is_subscribed",
            "title": "Weekly report",
            'label': 'Weekly Report',
            "description": "Subscribe to this account's Advisor Weekly Report email",
            'helperText': "User-specific setting to subscribe a user to the account's weekly reports email",
            "component": "descriptiveCheckbox",
            "isRequired": True,
            "initialValue": True,
            "isDisabled": False
        })

        # Unsubscribe - this should delete the WRS object - other code path
        response = self.client.post(
            reverse('user-preferences-list'),
            data={
                'is_subscribed': False,
            },
            **auth_header_for_testing()
        )
        preferences = self._response_is_good(response)
        self.assertIsInstance(preferences, dict)
        self.assertEqual(preferences, {
            'is_subscribed': False,
        })
