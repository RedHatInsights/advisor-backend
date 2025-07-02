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
from sat_compat.views.rules import sort_fields


class RuleTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        # Good response status is 200
        self.assertEqual(response.status_code, 200, response.content.decode())
        # Standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Test content is decodable as JSON
        json_data = response.json()
        # Test content is paginated in the standard way, with results and
        # page numbers and so forth
        self.assertIn('resources', json_data)
        self.assertIn('total', json_data)
        # Test the content returned so it matches what we expect.  Index it
        # by rule_id for convenience:
        rules = {}
        for pos, rule in enumerate(json_data['resources']):
            rules[rule['rule_id']] = rule
            rules[rule['rule_id']]['list_position'] = pos
        return rules

    def _impacted_systems_counts_correct(self, rules):
        if constants.active_rule in rules:
            self.assertIn('impacted_systems', rules[constants.active_rule])
            self.assertEqual(rules[constants.active_rule]['impacted_systems'], 4)
        if constants.second_rule in rules:
            self.assertIn('impacted_systems', rules[constants.second_rule])
            self.assertEqual(rules[constants.second_rule]['impacted_systems'], 2)
        if constants.acked_rule in rules:
            self.assertIn('impacted_systems', rules[constants.acked_rule])
            self.assertEqual(rules[constants.acked_rule]['impacted_systems'], 0)
        if constants.high_sev_rule in rules:
            self.assertIn('impacted_systems', rules[constants.high_sev_rule])
            self.assertEqual(rules[constants.high_sev_rule]['impacted_systems'], 0)

    def test_rule_list(self):
        response = self.client.get(reverse('sat-compat-rules-list'), **auth_header_for_testing())
        rules = self._response_is_good(response)
        self._impacted_systems_counts_correct(rules)

        self.assertEqual(len(rules), 4)
        # We should see all active rules, even acked rules
        # Default sort by rule ID
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertIn('ack_id', rules[constants.acked_rule])
        # This ack is the non-Satellite ack:
        self.assertEqual(rules[constants.acked_rule]['ack_id'], 1)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['list_position'], 1)
        self.assertNotIn('ack_id', rules[constants.active_rule])
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 2)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['list_position'], 3)
        # but not an inactive rule,
        self.assertNotIn(constants.inactive_rule, rules)
        # nor a deleted rule,
        self.assertNotIn(constants.deleted_rule, rules)

        # Rule articles are always included, it's just easier
        self.assertIn('article', rules[constants.acked_rule])
        self.assertEqual(
            rules[constants.acked_rule]['article'],
            'https://access.redhat.com/node/1048578'
        )
        self.assertIn('article', rules[constants.active_rule])
        self.assertEqual(
            rules[constants.active_rule]['article'],
            'https://access.redhat.com/node/1048576'
        )

        # Test sort ordering
        response = self.client.get(
            reverse('sat-compat-rules-list'),
            data={'sort_by': 'impacted_systems', 'sort_dir': 'DESC'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self._impacted_systems_counts_correct(rules)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['list_position'], 0)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['list_position'], 1)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 2)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 3)

        # Test filter by branch ID
        response = self.client.get(
            reverse('sat-compat-rules-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        # Impacted systems counts affected - systems 1, 3, 5 and 9
        rules = self._response_is_good(response)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['impacted_systems'], 2)
        self.assertNotIn('ack_id', rules[constants.active_rule])
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['impacted_systems'], 1)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['impacted_systems'], 0)
        self.assertIn('ack_id', rules[constants.acked_rule])
        # This ack is the Satellite ack:
        self.assertEqual(rules[constants.acked_rule]['ack_id'], 1)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['impacted_systems'], 0)

    def test_rule_list_cert_auth(self):
        headers = auth_header_for_testing(system_opts=constants.host_03_system_data)
        response = self.client.get(reverse('sat-compat-rules-list'), **headers)
        rules = self._response_is_good(response)

        # System counts are only from those systems managed by the Satellite
        # - hosts 1, 3 and 5
        self.assertEqual(len(rules), 4)
        # We should see all active rules, even acked rules
        # Default sort by rule ID
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertIn('ack_id', rules[constants.acked_rule])
        # This ack is the non-Satellite ack:
        self.assertEqual(rules[constants.acked_rule]['ack_id'], 1)
        self.assertEqual(rules[constants.acked_rule]['impacted_systems'], 0)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['list_position'], 1)
        self.assertNotIn('ack_id', rules[constants.active_rule])
        self.assertEqual(rules[constants.active_rule]['impacted_systems'], 2)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 2)
        self.assertEqual(rules[constants.high_sev_rule]['impacted_systems'], 0)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['list_position'], 3)
        self.assertEqual(rules[constants.second_rule]['impacted_systems'], 1)
        # but not an inactive rule,
        self.assertNotIn(constants.inactive_rule, rules)
        # nor a deleted rule,
        self.assertNotIn(constants.deleted_rule, rules)

        # Rule articles are always included, it's just easier
        self.assertIn('article', rules[constants.acked_rule])
        self.assertEqual(
            rules[constants.acked_rule]['article'],
            'https://access.redhat.com/node/1048578'
        )
        self.assertIn('article', rules[constants.active_rule])
        self.assertEqual(
            rules[constants.active_rule]['article'],
            'https://access.redhat.com/node/1048576'
        )

        # Test sort ordering
        response = self.client.get(
            reverse('sat-compat-rules-list'),
            data={'sort_by': 'impacted_systems', 'sort_dir': 'DESC'},
            **headers,
        )
        rules = self._response_is_good(response)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['list_position'], 0)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['list_position'], 1)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 2)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 3)

        # Test filter by branch ID
        response = self.client.get(
            reverse('sat-compat-rules-list'),
            data={'branch_id': constants.remote_branch_uc},
            **headers,
        )
        rules = self._response_is_good(response)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['impacted_systems'], 2)
        self.assertNotIn('ack_id', rules[constants.active_rule])
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['impacted_systems'], 1)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['impacted_systems'], 0)
        self.assertIn('ack_id', rules[constants.acked_rule])
        self.assertEqual(rules[constants.acked_rule]['ack_id'], 1)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['impacted_systems'], 0)

    def test_rule_list_sort_options(self):
        for sort_field in sort_fields:
            params = {'sort_by': sort_field}
            for sort_dir in ('ASC', 'DESC', None):
                if sort_dir:
                    params['sort_dir'] = sort_dir
                response = self.client.get(
                    reverse('sat-compat-rules-list'), data=params,
                    **auth_header_for_testing()
                )
                self.assertTrue(self._response_is_good(response))

    def test_rule_list_ansible_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'ansible': '1'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(rules[constants.active_rule]['list_position'], 0)
        self.assertEqual(len(rules), 1)

    def test_rule_list_category_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'category': 'stability'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 1)
        self.assertEqual(len(rules), 2)

    def test_rule_list_incident_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'incidents': '1'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 0)
        self.assertEqual(len(rules), 1)

    def test_rule_list_ignored_rules_search(self):
        # Active rules - not the acked rule
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'ignoredRules': 'active'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(len(rules), 3)
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)

        # Ignored rules - only the acked rule
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'ignoredRules': 'ignored'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(len(rules), 1)
        self.assertIn(constants.acked_rule, rules)
        # Others excluded by length of dictionary

    def test_rule_list_rec_impact_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'rec_impact': 'INFO'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertEqual(rules[constants.active_rule]['list_position'], 1)
        self.assertEqual(rules[constants.second_rule]['list_position'], 2)
        self.assertEqual(len(rules), 3)

    def test_rule_list_rec_likelihood_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'rec_likelihood': 'INFO'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertEqual(rules[constants.active_rule]['list_position'], 1)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 2)
        self.assertEqual(rules[constants.second_rule]['list_position'], 3)
        self.assertEqual(len(rules), 4)

    def test_rule_list_severity_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'severity': 'INFO'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertEqual(rules[constants.active_rule]['list_position'], 1)
        self.assertEqual(rules[constants.second_rule]['list_position'], 2)
        self.assertEqual(len(rules), 3)

    def test_rule_list_text_search(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'), data={'search_term': 'cti'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['list_position'], 0)
        self.assertEqual(len(rules), 1)

    def test_rule_list_report_count(self):
        response = self.client.get(
            reverse('sat-compat-rules-list'),
            data={'report_count': 'gt0'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self._impacted_systems_counts_correct(rules)

        self.assertEqual(len(rules), 2)
        # In insights classic, acked rules have 0 reports by definition
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['list_position'], 0)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['list_position'], 1)
        # No reports:
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

        response = self.client.get(
            reverse('sat-compat-rules-list'),
            data={'report_count': 'lt1'},
            **auth_header_for_testing()
        )
        rules = self._response_is_good(response)
        self._impacted_systems_counts_correct(rules)

        self.assertEqual(len(rules), 2)
        # Rules with no active reports
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['list_position'], 0)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['list_position'], 1)
        # Rules with reports are excluded reports:
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        # Only active rules:
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

    def test_rule_detail(self):
        response = self.client.get(
            reverse('sat-compat-rules-detail',
                kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json['rule_id'], constants.active_rule)
        # No branch ID: systems 4, 6, 8, A
        self.assertEqual(json['impacted_systems'], 4)

        response = self.client.get(
            reverse('sat-compat-rules-detail',
                kwargs={'rule_id': constants.active_rule}),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        # No branch ID: systems 1 and 3
        self.assertEqual(json['impacted_systems'], 2)

    def test_rule_ansible_resolutions(self):
        response = self.client.get(
            reverse('sat-compat-rules-ansible-resolutions', kwargs={
                'rule_id': constants.active_rule,
                'system_type_id': 105,
                'playbook_type': 'fixit',
            }),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertIsInstance(json, dict)
        self.assertIn('id', json)
        self.assertEqual(json['id'], 1)
        self.assertIn('resolution_type', json)
        self.assertEqual(json['resolution_type'], "fixit")
        self.assertIn('rule_id', json)
        self.assertEqual(json['rule_id'], "test|Active_rule")
        self.assertIn('system_type_id', json)
        self.assertEqual(json['system_type_id'], 105)
        self.assertIn('description', json)
        self.assertEqual(json['description'], "Fix for Active_rule on rhel/host")
        # Test data is minimal here
        self.assertIn('play', json)
        self.assertEqual(json['play'], '- name: Fix for Active_rule on rhel/host\n  become: true')
        self.assertIn('version', json)
        self.assertEqual(json['version'], 'f592d01dca6aca063f2c3b2f7f4c261cef9fe114')
        self.assertIn('needs_reboot', json)
        self.assertEqual(json['needs_reboot'], False)
        self.assertIn('needs_pydata', json)
        self.assertEqual(json['needs_pydata'], False)
        self.assertIn('resolution_risk', json)
        self.assertEqual(json['resolution_risk'], 1)

        # Test various 404s - no matching rule
        response = self.client.get(
            reverse('sat-compat-rules-ansible-resolutions', kwargs={
                'rule_id': constants.acked_rule,
                'system_type_id': 105,
                'playbook_type': 'fixit',
            }),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        response = self.client.get(
            reverse('sat-compat-rules-ansible-resolutions', kwargs={
                'rule_id': constants.active_rule,
                'system_type_id': 89,
                'playbook_type': 'fixit',
            }),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
        response = self.client.get(
            reverse('sat-compat-rules-ansible-resolutions', kwargs={
                'rule_id': constants.active_rule,
                'system_type_id': 105,
                'playbook_type': 'workaround',
            }),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())
