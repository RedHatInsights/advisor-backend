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


class SettingsTestCase(TestCase):
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

    def test_settings_ddf_view(self):
        response = self.client.get(
            reverse('settings-list'), **auth_header_for_testing()
        )
        settings_ddf = self._response_is_good(response)
        # Break this down so diffs aren't so big:
        self.assertIsInstance(settings_ddf, list)
        self.assertEqual(len(settings_ddf), 1)
        self.assertIsInstance(settings_ddf[0], dict)
        self.assertEqual(sorted(settings_ddf[0].keys()), ['fields'])
        field_list = settings_ddf[0]['fields']
        self.assertIsInstance(field_list, list)
        self.assertEqual(len(field_list), 0)

    def test_settings_update(self):
        # Test that the show_satellite_hosts setting no longer exists
        response = self.client.post(
            reverse('settings-list'),
            data={
                'show_satellite_hosts': False,
            },
            **auth_header_for_testing(user_opts={'is_org_admin': True})
        )
        self.assertEqual(response.status_code, 405)
