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


class DisabledRulesViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    default_header = auth_header_for_testing()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_disabled_rules_list(self):
        response = self.client.get(reverse('disabled-rules-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        disabled_page = response.json()
        self.assertIn('meta', disabled_page)
        self.assertIn('links', disabled_page)
        self.assertIn('data', disabled_page)
        self.assertIsInstance(disabled_page['data'], list)
        # List is ordered by rule_id then account/system
        disabled_rules = disabled_page['data']
        self.assertIn('rule_id', disabled_rules[0])
        self.assertIn('scope', disabled_rules[0])
        self.assertEqual(disabled_rules[0]['rule_id'], constants.acked_rule)
        self.assertEqual(disabled_rules[0]['scope'], 'account')
        self.assertEqual(disabled_rules[1]['rule_id'], constants.second_rule)
        self.assertEqual(disabled_rules[1]['scope'], 'system')
        self.assertEqual(len(disabled_rules), 2)
