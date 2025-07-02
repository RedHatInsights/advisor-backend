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

from api.tests import constants
from api.permissions import auth_header_for_testing


class PluginsViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data',
    ]

    def test_plugin_list(self):
        # Standard authentication
        response = self.client.get(
            reverse('sat-compat-plugins-list'), **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        plugins_page = response.json()
        self.assertIsInstance(plugins_page, dict)
        self.assertIn('total', plugins_page)
        self.assertIsInstance(plugins_page['total'], int)
        self.assertEqual(plugins_page['total'], 3)
        self.assertIn('resources', plugins_page)
        self.assertIsInstance(plugins_page['resources'], list)
        # Rules in order by plugin slug.
        self.assertEqual(plugins_page['resources'], [
            {'plugin': 'test', 'name': constants.acked_title},
            {'plugin': 'test', 'name': constants.active_title},
            {'plugin': 'test', 'name': constants.second_title},
        ])
