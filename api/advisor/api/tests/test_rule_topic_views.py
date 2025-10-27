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


class RuleTopicViewsTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response, expected_code=200):
        # Good response status is 200
        self.assertEqual(response.status_code, expected_code, response.content.decode())
        # Standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Test content is decodable as JSON
        self.assertTrue(response.json, "Response cannot be decoded as json")
        return response.json()

    def test_topic_list(self):
        response = self.client.get(
            reverse('ruletopic-list'), **auth_header_for_testing()
        )
        topic_list = self._response_is_good(response)

        self.assertIsInstance(topic_list, list)
        # Test general properties of each topic
        for topic in topic_list:
            self.assertIsInstance(topic, dict)
            self.assertIn('name', topic)
            self.assertIn('slug', topic)
            self.assertIn('description', topic)
            self.assertIn('tag', topic)
        # Topics should be ordered by name
        self.assertEqual(topic_list[0]['name'], "Active rules")
        self.assertEqual(topic_list[0]['enabled'], True)
        self.assertEqual(topic_list[0]['impacted_systems_count'], 4)
        self.assertEqual(topic_list[1]['name'], "Kernel rules")
        self.assertEqual(topic_list[1]['enabled'], True)
        self.assertEqual(topic_list[1]['impacted_systems_count'], 4)
        self.assertEqual(len(topic_list), 2)

    def test_topic_list_system_profile_filter(self):
        response = self.client.get(
            reverse('ruletopic-list'),
            data={'filter[system_profile][sap_system]': 'true'},
            **auth_header_for_testing()
        )
        topic_list = self._response_is_good(response)

        self.assertIsInstance(topic_list, list)
        self.assertEqual(len(topic_list), 2)
        # Systems 1, 4, 5, 8, 9 and A are SAP systems
        self.assertEqual(topic_list[0]['name'], "Active rules")
        self.assertEqual(topic_list[0]['enabled'], True)
        self.assertEqual(topic_list[0]['impacted_systems_count'], 2)
        self.assertEqual(topic_list[1]['name'], "Kernel rules")
        self.assertEqual(topic_list[1]['enabled'], True)
        self.assertEqual(topic_list[1]['impacted_systems_count'], 2)

    def test_topic_detail(self):
        response = self.client.get(
            reverse('ruletopic-detail', kwargs={'slug': 'Active'}),
            **auth_header_for_testing()
        )
        topic = self._response_is_good(response)

        self.assertIsInstance(topic, dict)
        self.assertIn('name', topic)
        self.assertEqual(topic['name'], 'Active rules')
        self.assertIn('slug', topic)
        self.assertEqual(topic['slug'], 'Active')
        self.assertIn('description', topic)
        self.assertEqual(topic['description'], 'The set of active rules (including acked rules)')
        self.assertIn('tag', topic)
        self.assertEqual(topic['tag'], 'active')
        self.assertEqual(topic['impacted_systems_count'], 4)

    def test_enable_disable_topic(self):
        # Can't patch a topic even with an internal user - method not allowed.
        response = self.client.patch(
            reverse('ruletopic-detail', kwargs={'slug': 'Disabled'}),
            data={'enabled': True},
            content_type=constants.json_mime,
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 405)

    def test_topic_systems(self):
        response = self.client.get(
            reverse('ruletopic-systems', kwargs={'slug': 'Active'}),
            **auth_header_for_testing()
        )
        topic = self._response_is_good(response)

        self.assertIsInstance(topic, dict)
        self.assertIn('host_ids', topic)
        self.assertIsInstance(topic['host_ids'], list)
        self.assertEqual(len(topic['host_ids']), 4)
        self.assertEqual(
            topic['host_ids'],
            [
                constants.host_01_uuid,
                constants.host_03_uuid,
                constants.host_04_uuid,
                constants.host_06_uuid,
            ]
        )

        # Can sort list by other things, e.g. display_name, but still get back
        # UUIDs.
        response = self.client.get(
            reverse('ruletopic-systems', kwargs={'slug': 'Active'}),
            data={'sort': 'display_name,-last_seen'}, **auth_header_for_testing()
        )
        topic = self._response_is_good(response)
        self.assertEqual(
            topic['host_ids'],
            [
                constants.host_06_uuid,
                constants.host_01_uuid,
                constants.host_03_uuid,
                constants.host_04_uuid,
            ]
        )

    def test_topic_create_destroy(self):
        # Can't create topics - method not allowed
        response = self.client.post(
            reverse('ruletopic-list'), data={
                'name': 'New topic',
                'slug': 'New',
                'description': 'A new topic created through the API',
            },
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 405)

        # Not even if you're an internal user.
        response = self.client.post(
            reverse('ruletopic-list'), data={
                'name': 'New topic',
                'slug': 'New',
                'description': 'A new topic created through the API',
                'enabled': True,
                'tag': 'testing',
            },
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 405)

        # Nor delete
        response = self.client.delete(
            reverse('ruletopic-detail', kwargs={'slug': 'New'}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 405)
        # Nor delete for an internal user
        response = self.client.delete(
            reverse('ruletopic-detail', kwargs={'slug': 'New'}),
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 405)

    def test_topic_update(self):
        # Can't update a topic - method not allowed
        response = self.client.patch(
            reverse('ruletopic-detail', kwargs={'slug': 'Active'}), data={
                'name': 'Active topic (updated)',
                'slug': 'Updated',
            },
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 405)
        # Not even with an internal user
        response = self.client.patch(
            reverse('ruletopic-detail', kwargs={'slug': 'Active'}), data={
                'name': 'Active topic (updated)',
                'slug': 'Updated',
            },
            content_type=constants.json_mime,
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 405)

    def test_rules_with_tag(self):
        response = self.client.get(
            reverse('ruletopic-rules-with-tag', kwargs={'slug': 'Active'}),
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        rule_list = self._response_is_good(response)
        self.assertEqual(len(rule_list), 4)
        # Rules in rule_id order
        self.assertEqual(rule_list[0]['rule_id'], constants.acked_rule)
        self.assertEqual(rule_list[1]['rule_id'], constants.active_rule)
        self.assertEqual(rule_list[2]['rule_id'], constants.high_sev_rule)
        self.assertEqual(rule_list[3]['rule_id'], constants.second_rule)


class RuleTopicHostTagsViewsTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'host_tag_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response, expected_code=200):
        self.assertEqual(response.status_code, expected_code)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        self.assertTrue(response.json, "Response cannot be decoded as json")
        return response.json()

    def test_topic_list(self):
        response = self.client.get(
            reverse('ruletopic-list'),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        topic_list = self._response_is_good(response)
        self.assertIsInstance(topic_list, list)
        self.assertEqual(len(topic_list), 2)
        # Topics should be ordered by name
        self.assertEqual(topic_list[0]['name'], "Active rules")
        self.assertEqual(topic_list[0]['enabled'], True)
        self.assertEqual(topic_list[0]['impacted_systems_count'], 4)
        self.assertEqual(topic_list[1]['name'], "Kernel rules")
        self.assertEqual(topic_list[1]['enabled'], True)
        self.assertEqual(topic_list[1]['impacted_systems_count'], 4)

        response = self.client.get(
            reverse('ruletopic-list'),
            data={'tags': 'customer/security=low'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        topic_list = self._response_is_good(response)
        self.assertIsInstance(topic_list, list)
        self.assertEqual(len(topic_list), 2)
        # Topics should be ordered by name
        self.assertEqual(topic_list[0]['name'], "Active rules")
        self.assertEqual(topic_list[0]['enabled'], True)
        self.assertEqual(topic_list[0]['impacted_systems_count'], 2)
        self.assertEqual(topic_list[1]['name'], "Kernel rules")
        self.assertEqual(topic_list[1]['enabled'], True)
        self.assertEqual(topic_list[1]['impacted_systems_count'], 2)

    def test_topic_systems(self):
        response = self.client.get(
            reverse('ruletopic-systems', kwargs={'slug': 'Active'}),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        topic = self._response_is_good(response)
        self.assertIsInstance(topic, dict)
        self.assertIn('host_ids', topic)
        self.assertIsInstance(topic['host_ids'], list)
        self.assertEqual(topic['host_ids'], [
            constants.host_ht_01_uuid,
            constants.host_ht_02_uuid,
            constants.host_ht_03_uuid,
            constants.host_ht_04_uuid
        ])

        response = self.client.get(
            reverse('ruletopic-systems', kwargs={'slug': 'Active'}),
            data={'tags': 'customer/security=low'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        topic = self._response_is_good(response)
        self.assertIsInstance(topic, dict)
        self.assertIn('host_ids', topic)
        self.assertIsInstance(topic['host_ids'], list)
        self.assertEqual(topic['host_ids'], [
            constants.host_ht_01_uuid,
            constants.host_ht_04_uuid
        ])
