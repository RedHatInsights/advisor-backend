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


class TopicTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_topics_list(self):
        response = self.client.get(reverse('sat-compat-topics-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topics_list = response.json()

        self.assertIsInstance(topics_list, list)
        # Test structure
        for topic in topics_list:
            self.assertIsInstance(topic, dict)
            for field in ('rules', 'hitCount', 'affectedSystemCount', 'slug',):
                self.assertIn(field, topic, f"Field {field} not found in topic {topic}")
            self.assertIsInstance(topic['rules'], list)
            for rule in topic['rules']:
                for field in (
                    'rule_id', 'description', 'category', 'severity',
                    'hitCount', 'summary', 'summary_html', 'plugin',
                    'error_key', 'plugin_name', 'ansible', 'rec_impact',
                    'rec_likelihood', 'acked',
                ):
                    self.assertIn(
                        field, rule,
                        f"Field {field} not in rule {rule} of topic {topic}"
                    )

        # Test filter by branch ID
        response = self.client.get(
            reverse('sat-compat-topics-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topics_list = response.json()
        self.assertIsInstance(topics_list, list)
        for topic in topics_list:
            self.assertIsInstance(topic, dict)
            for field in ('rules', 'hitCount', 'affectedSystemCount', 'slug',):
                self.assertIn(field, topic, f"Field {field} not found in topic {topic}")
            self.assertIsInstance(topic['rules'], list)

    def test_topics_list_cert_auth(self):
        response = self.client.get(
            reverse('sat-compat-topics-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topics_list = response.json()

        self.assertIsInstance(topics_list, list)
        # Test structure
        for topic in topics_list:
            self.assertIsInstance(topic, dict)
            for field in ('rules', 'hitCount', 'affectedSystemCount', 'slug',):
                self.assertIn(field, topic, f"Field {field} not found in topic {topic}")
            self.assertIsInstance(topic['rules'], list)
            for rule in topic['rules']:
                for field in (
                    'rule_id', 'description', 'category', 'severity',
                    'hitCount', 'summary', 'summary_html', 'plugin',
                    'error_key', 'plugin_name', 'ansible', 'rec_impact',
                    'rec_likelihood', 'acked',
                ):
                    self.assertIn(
                        field, rule,
                        f"Field {field} not in rule {rule} of topic {topic}"
                    )

        # Test filter by branch ID
        response = self.client.get(
            reverse('sat-compat-topics-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topics_list = response.json()
        self.assertIsInstance(topics_list, list)
        for topic in topics_list:
            self.assertIsInstance(topic, dict)
            for field in ('rules', 'hitCount', 'affectedSystemCount', 'slug',):
                self.assertIn(field, topic, f"Field {field} not found in topic {topic}")
            self.assertIsInstance(topic['rules'], list)

    def test_topics_detail(self):
        response = self.client.get(
            reverse('sat-compat-topics-detail', kwargs={'slug': 'Active'}),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topic = response.json()

        self.assertIsInstance(topic, dict)
        self.assertIn('rules', topic)
        self.assertIn('hitCount', topic)
        self.assertEqual(topic['hitCount'], 3)  # Reports 8, 17, 7
        self.assertIn('affectedSystemCount', topic)
        self.assertEqual(topic['affectedSystemCount'], 2)  # Hosts 1 and 3
        self.assertIn('slug', topic)
        self.assertEqual(topic['slug'], 'Active')

        # Case insensitive matching
        response = self.client.get(
            reverse('sat-compat-topics-detail', kwargs={'slug': 'aCTIVE'}),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topic = response.json()

        self.assertIsInstance(topic, dict)
        self.assertIn('rules', topic)
        self.assertIn('hitCount', topic)
        self.assertEqual(topic['hitCount'], 3)  # Reports 8, 17, 7
        self.assertIn('affectedSystemCount', topic)
        self.assertEqual(topic['affectedSystemCount'], 2)  # Hosts 1 and 3
        self.assertIn('slug', topic)
        self.assertEqual(topic['slug'], 'Active')

        response = self.client.get(
            reverse('sat-compat-topics-detail', kwargs={'slug': 'Active'}),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topic = response.json()

        self.assertIsInstance(topic, dict)
        self.assertIn('rules', topic)
        self.assertIn('hitCount', topic)
        self.assertEqual(topic['hitCount'], 3)  # Reports 8, 17, 7
        self.assertIn('affectedSystemCount', topic)
        self.assertEqual(topic['affectedSystemCount'], 2)  # Hosts 1 and 3
        self.assertIn('slug', topic)
        self.assertEqual(topic['slug'], 'Active')

    def test_topics_detail_satellite_specials(self):
        # Test general properties
        for slug in (
            'incidents', 'low-risk', 'medium-risk', 'high-risk',
            'availability', 'security', 'stability', 'performance'
        ):
            response = self.client.get(
                reverse('sat-compat-topics-detail', kwargs={'slug': slug}),
                data={'branch_id': constants.remote_branch_lc},
                **auth_header_for_testing()
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.accepted_media_type, constants.json_mime)
            topic = response.json()

            self.assertIsInstance(topic, dict)
            for field in ('rules', 'hitCount', 'affectedSystemCount', 'slug'):
                self.assertIn(field, topic, f"Field {field} not found in topic {topic}")
            self.assertEqual(topic['slug'], slug)
            # Test that each rule only occurs once in the list of rules:
            rule_ids = set()
            for rule in topic['rules']:
                self.assertNotIn(rule['rule_id'], rule_ids, f"Topic {slug} had rule {rule['rule_id']} appearing more than once")
                rule_ids.add(rule['rule_id'])

            response = self.client.get(
                reverse('sat-compat-topics-detail', kwargs={'slug': slug}),
                data={'branch_id': constants.remote_branch_lc},
                **auth_header_for_testing(system_opts=constants.host_03_system_data)
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.accepted_media_type, constants.json_mime)
            topic = response.json()

            self.assertIsInstance(topic, dict)
            for field in ('rules', 'hitCount', 'affectedSystemCount', 'slug'):
                self.assertIn(field, topic, f"Field {field} not found in topic {topic}")
            self.assertEqual(topic['slug'], slug)
            # Test that each rule only occurs once in the list of rules:
            rule_ids = set()
            for rule in topic['rules']:
                self.assertNotIn(rule['rule_id'], rule_ids, f"Topic {slug} had rule {rule['rule_id']} appearing more than once")
                rule_ids.add(rule['rule_id'])

        # Test specific properties - number of rules, rules listed, etc.
        # Low-risk rules - active, acked, second
        # Also check case-insensitive matching
        response = self.client.get(
            reverse('sat-compat-topics-detail', kwargs={'slug': 'low-RISK'}),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        topic = response.json()
        # Rules list in name order
        self.assertEqual(topic['rules'][0]['rule_id'], constants.active_rule)
        self.assertEqual(topic['rules'][0]['hitCount'], 2)  # Hosts 1 and 3
        self.assertEqual(topic['rules'][1]['rule_id'], constants.second_rule)
        self.assertEqual(topic['rules'][1]['hitCount'], 1)  # Host 3, 1 host-acked
        self.assertEqual(len(topic['rules']), 2)

        # Availability category - just active rule.
        response = self.client.get(
            reverse('sat-compat-topics-detail', kwargs={'slug': 'availability'}),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        topic = response.json()
        self.assertIn('rules', topic)
        self.assertEqual(topic['rules'][0]['rule_id'], constants.active_rule)
        self.assertEqual(topic['rules'][0]['hitCount'], 2)  # Hosts 1 and 3
        self.assertEqual(len(topic['rules']), 1)
        # Security category - no active rules
        response = self.client.get(
            reverse('sat-compat-topics-detail', kwargs={'slug': 'security'}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        topic = response.json()
        self.assertIn('rules', topic)
        self.assertEqual(len(topic['rules']), 0)
