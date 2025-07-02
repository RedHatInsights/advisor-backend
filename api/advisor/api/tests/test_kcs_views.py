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
from api.views.kcs import RULE_URL


class KcsViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data'
    ]

    def test_kcs_list(self):
        response = self.client.get(reverse('kcs-list'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        kcs_list = response.json()
        self.assertEqual(len(kcs_list), 2)
        self.assertIn('rule_url', kcs_list[0])
        self.assertIsInstance(kcs_list[0], dict)
        self.assertEqual(kcs_list[0]['rule_url'], RULE_URL + constants.acked_rule)
        self.assertEqual(kcs_list[0]['node_id'], '1048578')

    def test_kcs_detail(self):
        # test|Acked_rule
        response = self.client.get(reverse('kcs-detail', kwargs={'node_id': '1048578'}))
        self.assertEqual(response.status_code, 200)
        rule_urls = response.json()
        self.assertIsInstance(rule_urls, list)
        self.assertEqual(len(rule_urls), 1)
        self.assertEqual(rule_urls[0], RULE_URL + constants.acked_rule)

        # test|Active_rule
        response = self.client.get(reverse('kcs-detail', kwargs={'node_id': '1048576'}))
        self.assertEqual(response.status_code, 200)
        rule_urls = response.json()
        self.assertIsInstance(rule_urls, list)
        self.assertEqual(len(rule_urls), 1)
        self.assertEqual(rule_urls[0], RULE_URL + constants.active_rule)

    def test_kcs_detail_invalid_node_id(self):
        # node_id is for an inactive rule
        response = self.client.get(reverse('kcs-detail', kwargs={'node_id': '1048577'}))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'No Rule matches the given query.'})

        # No such node_id
        response = self.client.get(reverse('kcs-detail', kwargs={'node_id': '1234567'}))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'No Rule matches the given query.'})

        # node_id is not a number
        response = self.client.get(reverse('kcs-detail', kwargs={'node_id': 'abcdef'}))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'No Rule matches the given query.'})

        # node_id is too long (max_length=10)
        response = self.client.get(reverse('kcs-detail', kwargs={'node_id': '111111111111111'}))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'No Rule matches the given query.'})

    def test_node_ids_parameter(self):
        def expected_results_test_node_ids_parameter(kcs_list):
            self.assertEqual(len(kcs_list), 2)
            self.assertEqual(kcs_list[0]['rule_url'], RULE_URL + constants.acked_rule)
            self.assertEqual(kcs_list[0]['node_id'], '1048578')
            self.assertEqual(kcs_list[1]['rule_url'], RULE_URL + constants.active_rule)
            self.assertEqual(kcs_list[1]['node_id'], '1048576')

        # Normal parameters - no funny business here - expected 2 rule urls
        response = self.client.get(reverse('kcs-list'), data={'node_ids': '1048576,1048578'})
        self.assertEqual(response.status_code, 200)
        expected_results_test_node_ids_parameter(response.json())

        # Some non-existent KCS articles in the parameter string - expected 2 rule urls
        response = self.client.get(reverse('kcs-list'), data={'node_ids': '1984,1048576,2020,1048578,123456789,007'})
        self.assertEqual(response.status_code, 200)
        expected_results_test_node_ids_parameter(response.json())

        # Only non-existent KCS articles in the parameter string - expected 0 rule urls
        response = self.client.get(reverse('kcs-list'), data={'node_ids': '1984,2020,123456789,007'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 0)

        # Extra spaces in otherwise valid KCS article numbers - expected 0 rule urls
        response = self.client.get(reverse('kcs-list'), data={'node_ids': '104 8576,1 048578'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 0)

    def test_node_ids_bad_parameters(self):
        # Nothing in the parameter string - expected bad request
        response = self.client.get(reverse('kcs-list'), data={'node_ids': ''})
        self.assertEqual(response.status_code, 400)

        # Extra comma in the parameter string - expected bad request (should be numbers after commas)
        response = self.client.get(reverse('kcs-list'), data={'node_ids': '1048576,1048578,'})
        self.assertEqual(response.status_code, 400)

        # Extra spaces in the parameter string - expected bad request (should only be numbers or commas)
        response = self.client.get(reverse('kcs-list'), data={'node_ids': '1048576 , 1048578'})
        self.assertEqual(response.status_code, 400)
