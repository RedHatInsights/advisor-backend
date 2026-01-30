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

import csv

from django.test import TestCase
from django.urls import reverse

from api.models import Ack, Rule, RuleCategory
from api.tests import constants, update_stale_dates
from api.permissions import (
    auth_header_for_testing, turnpike_auth_header_for_testing
)
from api.views.rules import (
    sort_field_map, systems_sort_field_map, systems_detail_sort_fields
)
from django.utils import timezone

TEST_RBAC_URL = 'http://rbac.svc/'


class RuleTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule'
    ]

    default_header = auth_header_for_testing()
    internal_header = auth_header_for_testing(user_opts={'is_internal': True})

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
        self.assertIn('count', json_data['meta'])
        self.assertIn('links', json_data)
        self.assertIn('data', json_data)
        # Test the content returned so it matches what we expect.  Index it
        # by rule_id for convenience:
        return {
            rule['rule_id']: rule
            for rule in json_data['data']
        }

    def _impacted_systems_counts_correct(self, rules):
        if constants.active_rule in rules:
            self.assertIn('impacted_systems_count', rules[constants.active_rule])
            self.assertEqual(rules[constants.active_rule]['impacted_systems_count'], 4)
        if constants.second_rule in rules:
            self.assertIn('impacted_systems_count', rules[constants.second_rule])
            self.assertEqual(rules[constants.second_rule]['impacted_systems_count'], 2)
        if constants.acked_rule in rules:
            # NB as of RHINENG-16203 acked rules show impacted systems counts
            self.assertIn('impacted_systems_count', rules[constants.acked_rule])
            self.assertEqual(rules[constants.acked_rule]['impacted_systems_count'], 1)
        if constants.high_sev_rule in rules:
            self.assertIn('impacted_systems_count', rules[constants.high_sev_rule])
            self.assertEqual(rules[constants.high_sev_rule]['impacted_systems_count'], 0)

    def _playbook_counts_correct(self, rules):
        if constants.active_rule in rules:
            self.assertEqual(rules[constants.active_rule]['playbook_count'], 1)
        if constants.second_rule in rules:
            self.assertEqual(rules[constants.second_rule]['playbook_count'], 0)
        if constants.acked_rule in rules:
            self.assertEqual(rules[constants.acked_rule]['playbook_count'], 0)
        if constants.high_sev_rule in rules:
            self.assertEqual(rules[constants.high_sev_rule]['playbook_count'], 0)

    def _hosts_acked_counts_correct(self, rules):
        if constants.active_rule in rules:
            self.assertIn('hosts_acked_count', rules[constants.active_rule])
            self.assertEqual(rules[constants.active_rule]['hosts_acked_count'], 0)
        if constants.second_rule in rules:
            self.assertIn('hosts_acked_count', rules[constants.second_rule])
            self.assertEqual(rules[constants.second_rule]['hosts_acked_count'], 1)
        if constants.acked_rule in rules:
            self.assertIn('hosts_acked_count', rules[constants.acked_rule])
            self.assertEqual(rules[constants.acked_rule]['hosts_acked_count'], 0)
        if constants.high_sev_rule in rules:
            self.assertIn('hosts_acked_count', rules[constants.high_sev_rule])
            self.assertEqual(rules[constants.high_sev_rule]['hosts_acked_count'], 0)

    def _rating_correct(self, rules):
        if constants.active_rule in rules:
            self.assertIn('rating', rules[constants.active_rule])
            self.assertEqual(rules[constants.active_rule]['rating'], 1)
        if constants.second_rule in rules:
            self.assertIn('rating', rules[constants.second_rule])
            self.assertEqual(rules[constants.second_rule]['rating'], 0)
        if constants.acked_rule in rules:
            self.assertIn('rating', rules[constants.acked_rule])
            self.assertEqual(rules[constants.acked_rule]['rating'], -1)
        if constants.high_sev_rule in rules:
            self.assertIn('rating', rules[constants.high_sev_rule])
            self.assertEqual(rules[constants.high_sev_rule]['rating'], 0)

    def test_rule_list(self):
        response = self.client.get(reverse('rule-list'), **self.default_header)
        rules = self._response_is_good(response)

        self.assertEqual(len(rules), 4)
        # We should see all active rules, even acked rules
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        # but not an inactive rule,
        self.assertNotIn(constants.inactive_rule, rules)
        # nor a deleted rule,
        self.assertNotIn(constants.deleted_rule, rules)

        # Check the number of systems affected
        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # Check reports_shown flag
        for rule in (constants.active_rule, constants.acked_rule):
            self.assertIn('reports_shown', rules[rule])
        self.assertEqual(rules[constants.active_rule]['reports_shown'], True)
        self.assertEqual(rules[constants.acked_rule]['reports_shown'], False)

        # Check rule_status flag
        for rule in (constants.active_rule, constants.acked_rule):
            self.assertIn('rule_status', rules[rule])
        self.assertEqual(rules[constants.active_rule]['rule_status'], 'enabled')
        self.assertEqual(rules[constants.acked_rule]['rule_status'], 'disabled')

    def test_rule_list_other_account(self):
        response = self.client.get(reverse('rule-list'), **auth_header_for_testing(account='1122334', org_id='9988776'))
        rules = self._response_is_good(response)

        # We should see all active rules, even acked rules
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        # but not an inactive rule,
        self.assertNotIn(constants.inactive_rule, rules)
        # nor a deleted rule,
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertEqual(len(rules), 4)

        # Check the number of systems affected
        self.assertIn('impacted_systems_count', rules[constants.active_rule])
        # Two systems - 02 and 07.
        self.assertEqual(rules[constants.active_rule]['impacted_systems_count'], 2)
        self.assertEqual(rules[constants.acked_rule]['impacted_systems_count'], 1)
        self.assertEqual(rules[constants.second_rule]['impacted_systems_count'], 0)
        self.assertEqual(rules[constants.high_sev_rule]['impacted_systems_count'], 0)

        # Check reports_shown flag
        for rule in (constants.active_rule, constants.acked_rule):
            self.assertIn('reports_shown', rules[rule])
        self.assertEqual(rules[constants.active_rule]['reports_shown'], True)
        self.assertEqual(rules[constants.acked_rule]['reports_shown'], False)

        # Check rule_status flag
        for rule in (constants.active_rule, constants.acked_rule):
            self.assertIn('rule_status', rules[rule])
        self.assertEqual(rules[constants.active_rule]['rule_status'], 'enabled')
        self.assertEqual(rules[constants.acked_rule]['rule_status'], 'disabled')

    def test_rule_list_page_size(self):
        response = self.client.get(reverse('rule-list'), {'limit': '1'}, **self.default_header)
        rules = self._response_is_good(response)
        self.assertEqual(len(rules), 1)

    def test_rule_list_offset_limit_links(self):
        response = self.client.get(reverse('rule-list'), {'limit': '2', 'offset': 2}, **self.default_header)
        rules = self._response_is_good(response)
        self.assertEqual(len(rules), 2)  # Four rules, starting from offset 2

        json = response.json()
        self.assertIn('meta', json)
        self.assertIsInstance(json['meta'], dict)
        self.assertIn('count', json['meta'])
        self.assertIsInstance(json['meta']['count'], int)
        self.assertEqual(json['meta']['count'], 4)

        self.assertIn('links', json)
        self.assertIsInstance(json['links'], dict)
        for direction in ('first', 'previous', 'next', 'last'):
            self.assertIn(direction, json['links'])
            self.assertIsInstance(json['links'][direction], str)

    def test_rule_list_filter_category(self):
        response = self.client.get(reverse('rule-list'), data={
            'category': '4'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the single rule in the performance category
        self.assertIn(constants.second_rule, rules)
        # And none of the others
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_multiple_categories(self):
        response = self.client.get(reverse('rule-list'), data={
            'category': '4,1'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the single rule in the performance category,
        # and the single rule in the availability category
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.active_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 2)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_nonexistent_category(self):
        response = self.client.get(reverse('rule-list'), data={
            'category': '5'
        }, **self.default_header)
        # Returns a 400 invalid response
        self.assertEqual(response.status_code, 400)
        # Body contains the list of valid categories
        content = response.content.decode()
        for category in RuleCategory.objects.all():
            self.assertIn(str(category.pk), content)

    def test_rule_list_filter_invalid_category(self):
        response = self.client.get(reverse('rule-list'), data={
            'category': 'foo'
        }, **self.default_header)
        # Returns a 400 invalid response
        self.assertEqual(response.status_code, 400)
        # Body contains the list of valid categories
        content = response.content.decode()
        self.assertIn("The value must be an integer", content)

    def test_rule_list_filter_res_risk(self):
        response = self.client.get(reverse('rule-list'), data={
            'res_risk': '1'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the three low resolution risk rules, including acked
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        # but not high resolution risk or inactive rules
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_multiple_res_risks(self):
        response = self.client.get(reverse('rule-list'), data={
            'res_risk': '1,4'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the three low resolution risk rules, including acked
        # and the one high resolution risk rule.
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        # but not inactive rules
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

        self.assertEqual(len(rules), 4)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_res_risk_invalid_risk(self):
        response = self.client.get(reverse('rule-list'), data={
            'res_risk': '9'
        }, **self.default_header)
        # Returns a 400 invalid response
        self.assertEqual(response.status_code, 400)
        # Body contains the list of valid rule resolution values
        content = response.content.decode()
        for risk_value in ('1', '3', '4'):
            self.assertIn(risk_value, content)

    def test_rule_list_filter_res_risk_no_rules(self):
        response = self.client.get(reverse('rule-list'), data={
            'res_risk': '3'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertEqual(len(rules), 0)

    def test_rule_list_filter_res_risk_and_category(self):
        response = self.client.get(reverse('rule-list'), data={
            'res_risk': '1', 'category': '4'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # Because performance category is more restrictive than low
        # resolution risk, we should only see the second rule
        self.assertNotIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_has_tag(self):
        response = self.client.get(reverse('rule-list'), data={
            'has_tag': 'testing'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # All rules have the testing tag, but we should not see the inactive
        # or deleted rules
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 4)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_has_union_of_tags(self):
        response = self.client.get(reverse('rule-list'), data={
            'has_tag': 'kernel,security'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # All rules have the testing tag, but we should not see the inactive
        # or deleted rules, and limited further by the kernel tag.
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_has_no_matching_tags(self):
        response = self.client.get(reverse('rule-list'), data={
            'has_tag': 'nfs',
        }, **self.default_header)
        rules = self._response_is_good(response)

        # No rules have the nfs tag.
        self.assertEqual(len(rules), 0)

    def test_rule_list_filter_incident(self):
        response = self.client.get(reverse('rule-list'), data={
            'incident': 'true'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # Incident is a tag and only high sev rule has it.
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_no_incident(self):
        response = self.client.get(reverse('rule-list'), data={
            'incident': 'false'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # Incident is a tag and only high sev rule has it; so we should see
        # all (normally available) rules but not the high sev one.
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_incident_and_tag(self):
        response = self.client.get(reverse('rule-list'), data={
            'incident': 'true',
            'has_tag': 'active',
        }, **self.default_header)
        rules = self._response_is_good(response)

        # Incident is a tag and only high sev rule has it.  Even the use of
        # other rule tags shouldn't include them (i.e. AND not OR).
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_has_playbook(self):
        response = self.client.get(reverse('rule-list'), data={
            'has_playbook': 'true'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_has_no_playbook(self):
        response = self.client.get(reverse('rule-list'), data={
            'has_playbook': 'false'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertNotIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.notyetactive_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_likelihood(self):
        response = self.client.get(reverse('rule-list'), data={
            'likelihood': '1'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the rules we expect to see
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

        self.assertEqual(len(rules), 4)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_multiple_likelihoods(self):
        response = self.client.get(reverse('rule-list'), data={
            'likelihood': '1,2'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the rules we expect to see
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

        self.assertEqual(len(rules), 4)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_impact(self):
        response = self.client.get(reverse('rule-list'), data={
            'impact': '1'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see the rules we expect to see
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_impact_highest(self):
        response = self.client.get(reverse('rule-list'), data={
            'impact': '4'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # We should see only the high impact rule
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_impact_invalid(self):
        response = self.client.get(reverse('rule-list'), data={
            'impact': '9'
        }, **self.default_header)
        # Returns a 400 invalid response
        self.assertEqual(response.status_code, 400)
        # Body contains the list of valid rule impact values
        content = response.content.decode()
        for impact in ('1', '3', '4'):
            self.assertIn(impact, content)

    def test_rule_list_filter_impact_no_rules(self):
        response = self.client.get(reverse('rule-list'), data={
            'impact': '3'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertEqual(len(rules), 0)

    def test_rule_list_filter_reboot_required(self):
        # Test showing only the rules for which reports are enabled
        response = self.client.get(reverse('rule-list'), data={
            'reboot': 'true'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertIn(constants.acked_rule, rules)

        self.assertEqual(len(rules), 2)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # Test showing only the rules for which reports are disabled
        response = self.client.get(reverse('rule-list'), data={
            'reboot': 'false'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 2)

    def test_rule_list_filter_reports_shown(self):
        # Test showing only the rules for which reports are enabled
        response = self.client.get(reverse('rule-list'), data={
            'reports_shown': 'true'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # Test showing only the rules for which reports are disabled
        response = self.client.get(reverse('rule-list'), data={
            'reports_shown': 'false'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 1)

    def test_rule_list_filter_impacting(self):
        response = self.client.get(reverse('rule-list'), data={
            'impacting': 'true'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # Active, second and acked rule are impacting systems currently.
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertNotIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 3)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # when 'impacting=false', rules that do not impact any system should
        # be listed.
        response = self.client.get(reverse('rule-list'), data={
            'impacting': 'false'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # Active, second and acked rule are impacting systems currently, but
        # acked rule will be listed as it's acked (and thus not 'impacting').
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(len(rules), 1)

    def test_rule_list_filter_text(self):
        # Search on text in the rule's generic description - a text field
        response = self.client.get(reverse('rule-list'), data={
            'text': 'markdown'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # We shouldn't be able to find inactive rules by text
        response = self.client.get(reverse('rule-list'), data={
            'text': 'inactive'
        }, **self.default_header)
        json_data = response.json()
        self.assertEqual(len(json_data['data']), 0)

        # We should be able to search for things with spaces
        response = self.client.get(reverse('rule-list'), data={
            'text': 'This rule'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(len(rules), 2)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # We should be able to search on resolution description
        response = self.client.get(reverse('rule-list'), data={
            'text': 'In order to fix this problem'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(len(rules), 2)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

        # Text searches are case insensitive
        response = self.client.get(reverse('rule-list'), data={
            'text': 'dot syntax'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_topic(self):
        response = self.client.get(reverse('rule-list'), data={
            'topic': 'Active'
        }, **self.default_header)
        rules = self._response_is_good(response)

        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

        self.assertEqual(len(rules), 4)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_topic_not_found(self):
        response = self.client.get(reverse('rule-list'), data={
            'topic': 'Sponge'
        }, **self.default_header)
        # No topic match, no rules
        rules = self._response_is_good(response)
        self.assertEqual(len(rules), 0)

    def test_rule_list_filter_total_risk(self):
        response = self.client.get(reverse('rule-list'), data={
            'total_risk': '2'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # High severity rule has likelihood 1 and impact 4, giving
        # total risk of floor(avg(1, 4)) = 2.  Everything else has impact
        # 1 so is total risk 1.
        self.assertNotIn(constants.active_rule, rules)
        self.assertNotIn(constants.second_rule, rules)
        self.assertNotIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 1)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_multiple_total_risks(self):
        response = self.client.get(reverse('rule-list'), data={
            'total_risk': '2,1'
        }, **self.default_header)
        rules = self._response_is_good(response)

        # High severity rule has likelihood 1 and impact 4, giving
        # total risk of floor(avg(1, 4)) = 2.  Everything else has impact
        # 1 so is total risk 1.
        self.assertIn(constants.active_rule, rules)
        self.assertIn(constants.second_rule, rules)
        self.assertIn(constants.acked_rule, rules)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)
        self.assertIn(constants.high_sev_rule, rules)

        self.assertEqual(len(rules), 4)

        self._impacted_systems_counts_correct(rules)
        self._playbook_counts_correct(rules)
        self._hosts_acked_counts_correct(rules)
        self._rating_correct(rules)

    def test_rule_list_filter_system_profile(self):
        response = self.client.get(
            reverse('rule-list'),
            data={'filter[system_profile][sap_system]': 'True'},
            **self.default_header
        )
        rules = self._response_is_good(response)

        # We should see the single rule in the performance category
        self.assertEqual(len(rules), 4)
        # We should see all active rules, even acked rules
        # Systems 1, 4, 5, 8, 9, and A are SAP systems - 1 and 5 are in view
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['impacted_systems_count'], 2)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['impacted_systems_count'], 1)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['impacted_systems_count'], 1)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['impacted_systems_count'], 0)
        # but not an inactive rule,
        self.assertNotIn(constants.inactive_rule, rules)
        # nor a deleted rule,
        self.assertNotIn(constants.deleted_rule, rules)

        response = self.client.get(
            reverse('rule-list'),
            data={'filter[system_profile][sap_sids][contains][]': 'E02'},
            **self.default_header
        )
        rules = self._response_is_good(response)

        # We should see the single rule in the performance category
        self.assertEqual(len(rules), 4)
        # We should see all active rules, even acked rules
        # Systems 1 and 4 have the SAP SID E02 - 1 and 5 are in view
        self.assertIn(constants.active_rule, rules)
        self.assertEqual(rules[constants.active_rule]['impacted_systems_count'], 2)
        self.assertIn(constants.acked_rule, rules)
        self.assertEqual(rules[constants.acked_rule]['impacted_systems_count'], 1)
        self.assertIn(constants.second_rule, rules)
        self.assertEqual(rules[constants.second_rule]['impacted_systems_count'], 1)
        self.assertIn(constants.high_sev_rule, rules)
        self.assertEqual(rules[constants.high_sev_rule]['impacted_systems_count'], 0)
        self.assertNotIn(constants.inactive_rule, rules)
        self.assertNotIn(constants.deleted_rule, rules)

    def test_rule_list_sort_correct_ordering(self):
        response = self.client.get(reverse('rule-list'), data={
            'sort': '-total_risk'
        }, **self.default_header)
        json_data = response.json()
        results = json_data['data']

        # In the order we expect them: highest severity first, then rule_id
        # as the back-up default ordering
        self.assertEqual(results[0]['rule_id'], constants.high_sev_rule)
        self.assertEqual(results[1]['rule_id'], constants.acked_rule)
        self.assertEqual(results[2]['rule_id'], constants.active_rule)
        self.assertEqual(results[3]['rule_id'], constants.second_rule)

        # Sort by category should be by name, not by category ID (was a bug)
        response = self.client.get(reverse('rule-list'), data={
            'sort': 'category'
        }, **self.default_header)
        json_data = response.json()
        results = json_data['data']

        # Categories in alphabetic order: Availability(1), Performance(4),
        # Security(3), Stability(2): active_rule(1), second_rule(4),
        # acked_rule(3), high_sev(3) (because the back-up sort order should
        # be rule_id).
        self.assertEqual(results[0]['rule_id'], constants.active_rule)
        self.assertEqual(results[1]['rule_id'], constants.second_rule)
        self.assertEqual(results[2]['rule_id'], constants.acked_rule)
        self.assertEqual(results[3]['rule_id'], constants.high_sev_rule)

    def test_rule_list_multi_sort_correct_ordering(self):
        response = self.client.get(reverse('rule-list'), data={
            'sort': '-total_risk,-impacted_count'
        }, **self.default_header)
        json_data = response.json()
        results = json_data['data']

        # In the order we expect them: highest severity first, then rule_id
        # as the back-up default ordering
        self.assertEqual(results[0]['rule_id'], constants.high_sev_rule)
        self.assertEqual(results[1]['rule_id'], constants.active_rule)
        self.assertEqual(results[2]['rule_id'], constants.second_rule)
        self.assertEqual(results[3]['rule_id'], constants.acked_rule)

    def test_rule_list_sort_impacted_systems_ordering(self):
        response = self.client.get(reverse('rule-list'), data={
            'sort': '-impacted_count'
        }, **self.default_header)
        json_data = response.json()
        results = json_data['data']

        # In the order we expect them: active rule with 3 reports, then
        # second rule with 2 reports, then acked (forced to be zero reports
        # because it's acked) and high severity on zero reports.
        self.assertEqual(results[0]['rule_id'], constants.active_rule)
        self.assertEqual(results[1]['rule_id'], constants.second_rule)
        self.assertEqual(results[2]['rule_id'], constants.acked_rule)
        self.assertEqual(results[3]['rule_id'], constants.high_sev_rule)

    def test_rule_list_sort_impacted_systems_count_unaffected(self):
        for direction in ('', '-'):
            for field in sort_field_map.keys():
                response = self.client.get(reverse('rule-list'), data={
                    'sort': direction + field
                }, **self.default_header)
                rules = self._response_is_good(response)
                # We should see the rules we expect to see
                self.assertIn(constants.active_rule, rules)
                self.assertIn(constants.acked_rule, rules)
                self.assertIn(constants.second_rule, rules)
                self.assertIn(constants.high_sev_rule, rules)
                self.assertNotIn(constants.inactive_rule, rules)
                self.assertNotIn(constants.deleted_rule, rules)
                self.assertEqual(len(rules), 4)
                # Impacted systems count should remain the same
                self._impacted_systems_counts_correct(rules)
                self._playbook_counts_correct(rules)
                self._hosts_acked_counts_correct(rules)
                self._rating_correct(rules)

    def test_rule_list_sort_bad_ordering(self):
        response = self.client.get(reverse('rule-list'), data={
            'sort': 'foo'
        }, **self.default_header)
        # Returns a 400 invalid response
        self.assertEqual(response.status_code, 400)

    def test_rule_detail(self):
        response = self.client.get(reverse(
            'rule-detail', kwargs={'rule_id': constants.active_rule}
        ), **self.default_header)
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Load content as JSON or fail!
        rule_api = response.json()

        # Test non-relation properties of rule against fetching it (which
        # saves changing the test when the data changes)
        rule_model = Rule.objects.get(pk=1)
        for prop in (
            'rule_id', 'description', 'active', 'reboot_required',
            'generic', 'summary', 'reason', 'more_info', 'node_id',
        ):
            self.assertEqual(rule_api[prop], getattr(rule_model, prop))
        # Test date properties separately because they're listed as strings
        self.assertEqual(rule_api['publish_date'], '2018-05-23T15:38:55Z')
        self.assertEqual(rule_api['created_at'], '2018-05-22T06:06:47Z')
        self.assertEqual(rule_api['updated_at'], '2018-05-22T06:06:47Z')

        # Check resolution set
        self.assertIn('resolution_set', rule_api)
        self.assertIsInstance(rule_api['resolution_set'], list)
        self.assertEqual(len(rule_api['resolution_set']), 1)
        # Should be ordered by role and product code within rule, so rhel < rhev
        self.assertIsInstance(rule_api['resolution_set'][0], dict)
        self.assertIn('system_type', rule_api['resolution_set'][0])
        self.assertEqual(rule_api['resolution_set'][0]['system_type'], 105)
        self.assertEqual(
            rule_api['resolution_set'][0]['resolution'],
            rule_model.resolution_set.all()[0].resolution
        )
        # First resolution also has a playbook
        self.assertIn('has_playbook', rule_api['resolution_set'][0])
        self.assertTrue(rule_api['resolution_set'][0]['has_playbook'])

        # Test that ruleset information is no longer included
        self.assertNotIn('ruleset', rule_api)

        # Test tags:
        self.assertIn('tags', rule_api)
        self.assertIsInstance(rule_api['tags'], str)
        self.assertEqual(rule_api['tags'], 'active kernel testing')

        # Test of annotated fields - impacted_systems_count:
        self.assertIn('impacted_systems_count', rule_api)
        # Four systems impacted - 01, 03, 04 and 06.  System 05 is no longer impacted.
        self.assertEqual(rule_api['impacted_systems_count'], 4)
        # Test reports_shown
        self.assertIn('reports_shown', rule_api)
        self.assertEqual(rule_api['reports_shown'], True)
        # Test rule_status
        self.assertIn('rule_status', rule_api)
        self.assertEqual(rule_api['rule_status'], 'enabled')
        # Test rating
        self.assertIn('rating', rule_api)
        self.assertEqual(rule_api['rating'], 1)

    def test_rule_detail_acked(self):
        response = self.client.get(reverse(
            'rule-detail', kwargs={'rule_id': constants.acked_rule}
        ), **self.default_header)
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Get it or die!
        rule_api = response.json()

        # Test of annotated fields - impacted_systems_count:
        self.assertIn('impacted_systems_count', rule_api)
        self.assertEqual(rule_api['impacted_systems_count'], 1)
        # Test reports_shown
        self.assertIn('reports_shown', rule_api)
        self.assertEqual(rule_api['reports_shown'], False)
        # Test rule_status
        self.assertIn('rule_status', rule_api)
        self.assertEqual(rule_api['rule_status'], 'disabled')

    def test_rule_usage_stats(self):
        # Standard 'test-user' account should get denied
        response = self.client.get(
            reverse('rule-stats', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.get(
            reverse('rule-stats', kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        stats = response.json()

        self.assertIsInstance(stats, dict)
        self.assertEqual(stats, {
            'rule_id': constants.active_rule,
            'description': "Active rule",
            'active': True,
            'systems_hit': 6,
            'accounts_hit': 2,
            'accounts_acked': 0,
        })

    def test_rule_usage_justifications(self):
        # Standard 'test-user' account should get denied
        response = self.client.get(
            reverse('rule-justifications', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 403)

        # But internal users should be allowed.
        response = self.client.get(
            reverse('rule-justifications', kwargs={'rule_id': constants.active_rule}),
            **self.internal_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        justifications = response.json()
        # No acks for the active rule...
        self.assertEqual(justifications, [])
        # But there should be acks for the acked rule
        response = self.client.get(
            reverse('rule-justifications', kwargs={'rule_id': constants.acked_rule}),
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        justifications = response.json()
        # Note that our test data lists the account, but in normal practice
        # we wouldn't expect customers to identify themselves...
        self.assertEqual(justifications, [
            {'justification': 'Account 1122334 acks test|Acked_rule', 'count': 1},
            {'justification': 'Account 1234567 acks test|Acked_rule', 'count': 1},
        ])

    def test_systems_for_a_rule(self):
        # Test for account 1234567 org 9876543 - expect to find 4 systems for test|Active_rule rule
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)

        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()

        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        # Four systems impacted - 01, 03, 04 and 06.  System 05 is no longer impacted.
        self.assertEqual(hosts['host_ids'][0], constants.host_01_uuid)
        self.assertEqual(hosts['host_ids'][1], constants.host_03_uuid)
        self.assertEqual(hosts['host_ids'][2], constants.host_04_uuid)
        self.assertEqual(hosts['host_ids'][3], constants.host_06_uuid)
        self.assertEqual(len(hosts['host_ids']), 4)

        # Test sorting
        for field in systems_sort_field_map.keys():
            for direction in ('', '-'):
                response = self.client.get(
                    reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
                    data={'sort': direction + field},
                    **self.default_header
                )
                hosts = response.json()
                self.assertIn('host_ids', hosts)
                self.assertIsInstance(hosts['host_ids'], list)

        # Test for account 1122334 org id 9988776 - both systems affected by active rule
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertEqual(len(hosts['host_ids']), 2)
        self.assertEqual(hosts['host_ids'][0], constants.host_02_uuid)
        self.assertEqual(hosts['host_ids'][1], constants.host_07_uuid)

        # Test for a non-existent rule - expect Not Found message
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': 'Non_existent_rule'}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "No Rule matches the given query."})

        # Sort list by other field, e.g. display_name - still get UUIDs.
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'sort': 'display_name'}, **self.default_header
        )
        hosts = response.json()
        self.assertEqual(hosts['host_ids'][0], constants.host_06_uuid)
        self.assertEqual(hosts['host_ids'][1], constants.host_01_uuid)
        self.assertEqual(hosts['host_ids'][2], constants.host_03_uuid)
        self.assertEqual(hosts['host_ids'][3], constants.host_04_uuid)
        self.assertEqual(len(hosts['host_ids']), 4)
        # Check sorting by 'last_seen' field
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'sort': '-last_seen'}, **self.default_header
        )
        hosts = response.json()
        self.assertEqual(hosts['host_ids'][0], constants.host_06_uuid)
        self.assertEqual(hosts['host_ids'][1], constants.host_04_uuid)
        self.assertEqual(hosts['host_ids'][2], constants.host_01_uuid)
        self.assertEqual(hosts['host_ids'][3], constants.host_03_uuid)
        self.assertEqual(len(hosts['host_ids']), 4)

    def test_systems_for_a_rule_filtering(self):
        # Test for account 1234567 org id 9876543 system name 01 - expect to find 1 system
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'name': 'system01'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'][0], constants.host_01_uuid)
        self.assertEqual(len(hosts['host_ids']), 1)

        # Test for account 1234567 org id 9876543 RHEL version 7.5 - all but system 5
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'rhel_version': '7.5', 'sort': 'display_name'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'][0], constants.host_06_uuid)
        self.assertEqual(hosts['host_ids'][1], constants.host_01_uuid)
        self.assertEqual(hosts['host_ids'][2], constants.host_03_uuid)
        self.assertEqual(hosts['host_ids'][3], constants.host_04_uuid)
        self.assertEqual(len(hosts['host_ids']), 4)

        # Test system_type filtering
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'system_type': 'bootc'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [])
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'system_type': 'edge'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [])

        # Can't find a system if it's not in our account
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'name': 'system01'},
            **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(len(hosts['host_ids']), 0)

    def test_systems_for_a_rule_csv(self):
        # Test for account 1234567 org id 9876543 - expect to find 4 systems for test|Active_rule rule
        headers = self.default_header
        headers['HTTP_ACCEPT'] = 'text/csv'

        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            **headers
        )
        self.assertEqual(response.status_code, 200)
        # Test standard return type is CSV
        self.assertEqual(response.accepted_media_type, 'text/csv')

        csv_data = list(csv.reader(response.content.decode().splitlines()))
        self.assertEqual(len(csv_data[0]), 1)  # one field
        # hosts in UUID order.
        self.assertEqual(csv_data[0][0], 'Host UUID')
        self.assertEqual(csv_data[1][0], constants.host_01_uuid)
        self.assertEqual(csv_data[2][0], constants.host_03_uuid)
        self.assertEqual(csv_data[3][0], constants.host_04_uuid)
        self.assertEqual(csv_data[4][0], constants.host_06_uuid)

        headers['HTTP_ACCEPT'] = '*/*'
        response = self.client.get(
            reverse('rule-systems', kwargs={
                'rule_id': constants.active_rule, 'format': 'csv'
            }),
            **headers
        )
        self.assertEqual(response.status_code, 200)
        # Test standard return type is CSV
        self.assertEqual(response.accepted_media_type, 'text/csv')

        csv_data = list(csv.reader(response.content.decode().splitlines()))
        self.assertEqual(len(csv_data[0]), 1)  # one field
        self.assertEqual(csv_data[0][0], 'Host UUID')
        self.assertEqual(csv_data[1][0], constants.host_01_uuid)
        self.assertEqual(csv_data[2][0], constants.host_03_uuid)
        self.assertEqual(csv_data[3][0], constants.host_04_uuid)
        self.assertEqual(csv_data[4][0], constants.host_06_uuid)

    def test_systems_detail_for_a_rule(self):
        # Test for account 1234567 org id 9876543 - expect to find 4 systems for test|Active_rule rule
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Systems detail is paginated:
        page = response.json()
        self.assertIn('meta', page)
        self.assertIn('links', page)
        self.assertIn('data', page)
        hosts = page['data']
        self.assertIsInstance(hosts, list)
        for prop in ('system_uuid', 'display_name', 'last_seen', 'stale_at'):
            self.assertTrue(all(prop in host for host in hosts))

        # Four systems impacted - 01, 03, 04 and 06.  System 05 is no longer impacted.
        # Systems sorted by display name - stale_warn comes first.
        self.assertEqual(hosts[0]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(hosts[0]['display_name'], constants.host_06_name)
        self.assertEqual(hosts[1]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[2]['display_name'], constants.host_03_name)
        self.assertEqual(hosts[3]['display_name'], constants.host_04_name)
        self.assertEqual(len(hosts), 4)

        # Test sorting
        for field in systems_detail_sort_fields:
            for direction in ('', '-'):
                response = self.client.get(
                    reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
                    data={'sort': direction + field},
                    **self.default_header
                )
                page = response.json()
                self.assertIn('data', page)
                self.assertIsInstance(page['data'], list)

        # Test for account 1122334 9988776 - both systems affected by active rule
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()['data']
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]['system_uuid'], constants.host_02_uuid)
        self.assertEqual(hosts[1]['system_uuid'], constants.host_07_uuid)

        # Test for a non-existent rule - expect Not Found message
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': 'Non_existent_rule'}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "No Rule matches the given query."})

        # Sort list by other field, e.g. descending order of hits
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': '-hits'}, **self.default_header
        )
        hosts = response.json()['data']
        self.assertEqual(hosts[0]['display_name'], constants.host_03_name)
        self.assertEqual(hosts[1]['display_name'], constants.host_04_name)
        self.assertEqual(hosts[2]['display_name'], constants.host_06_name)
        self.assertEqual(hosts[3]['display_name'], constants.host_01_name)
        self.assertEqual(len(hosts), 4)

        # Sort field invalid should return a 400.
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': 'invalid'}, **self.default_header
        )
        self.assertEqual(response.status_code, 400, response.content.decode())

    def test_no_systems_detail_for_acked_rules(self):
        # Test for account 1234567 org id 9876543
        # system01.example.com is affected by acked_rule - but expect to not return any hosts for acked rules
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.acked_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        page = response.json()
        hosts = page['data']
        self.assertEqual(len(hosts), 0)

        # Test for account 1122334 org id 9988776
        # It doesn't have any hosts affected by acked rules so just confirming that
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.second_rule}),
            **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        self.assertEqual(response.status_code, 200)
        page = response.json()
        hosts = page['data']
        self.assertEqual(len(hosts), 0)

    def test_no_systems_detail_for_hostacked_rules(self):
        # Test for account 1234567 org id 9876543
        # system01.example.com is affected by second_rule but is hostacked - expect no host details for hostacked rules
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.second_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        page = response.json()
        hosts = page['data']
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(hosts[1]['system_uuid'], constants.host_04_uuid)
        self.assertEqual([], list(filter(lambda host: host['system_uuid'] == constants.host_01_uuid, hosts)))

    def test_systems_detail_for_a_rule_name_filtering(self):
        # Test for account 1234567 org id 9876543 system name 01 - expect to find 1 system
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'name': 'system01'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        page = response.json()
        self.assertIn('data', page)
        hosts = page['data']
        self.assertIsInstance(hosts, list)
        self.assertEqual(hosts[0]['system_uuid'], constants.host_01_uuid)
        self.assertEqual(len(hosts), 1)

        # Can't find a system if it's not in our account
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'name': 'system01'},
            **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        page = response.json()
        self.assertIn('data', page)
        hosts = page['data']
        self.assertEqual(len(hosts), 0)

    def test_systems_detail_for_a_rule_rhel_version_filtering(self):
        # Test for RHEL 7.5 that has hits for the active rule (excludes
        # system 5 on both counts)
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'rhel_version': '7.5'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        page = response.json()
        self.assertIn('data', page)
        hosts = page['data']
        self.assertIsInstance(hosts, list)
        # Systems sorted by display name - stale_warn comes first.
        self.assertEqual(hosts[0]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(hosts[0]['display_name'], constants.host_06_name)
        self.assertEqual(hosts[1]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[2]['display_name'], constants.host_03_name)
        self.assertEqual(hosts[3]['display_name'], constants.host_04_name)
        self.assertEqual(len(hosts), 4)

        # If we don't have that version, we get no systems - even if there
        # are other systems with that version
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'rhel_version': '8.2'}, **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        page = response.json()
        self.assertIn('data', page)
        hosts = page['data']
        self.assertEqual(len(hosts), 0)

        # We can combine in-use versions with versions that aren't and get
        # only those that exist and have hits.
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'rhel_version': '7.1,7.2,7.3,7.4,7.5,7.6,7.7,7.8,7.9,7.10,8.10,9.8,10.0,10.2'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        page = response.json()
        self.assertIn('data', page)
        hosts = page['data']
        self.assertIsInstance(hosts, list)
        # Systems sorted by display name - stale_warn comes first.
        self.assertEqual(hosts[0]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(hosts[0]['display_name'], constants.host_06_name)
        self.assertEqual(hosts[1]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[2]['display_name'], constants.host_03_name)
        self.assertEqual(hosts[3]['display_name'], constants.host_04_name)
        # Note that we're only seeing hits for the active rule, so system 5,
        # which is on RHEL 7.1, is not seen here.
        self.assertEqual(len(hosts), 4)

    def test_systems_detail_for_a_rule_system_type_filter(self):
        # Test for 'conventional' systems, should exclude edge and bootc.
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'system_type': 'conventional'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        page = response.json()
        self.assertIn('data', page)
        hosts = page['data']
        self.assertIsInstance(hosts, list)
        self.assertEqual(hosts[0]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(hosts[1]['system_uuid'], constants.host_01_uuid)
        self.assertEqual(hosts[2]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(hosts[3]['system_uuid'], constants.host_04_uuid)
        self.assertEqual(len(hosts), 4)

    def test_systems_for_a_rule_acked(self):
        # Acked rules should display no systems
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.acked_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [])

    def test_rule_add_del_many_host_acks(self):
        # Add an ack to many hosts:
        systems_list = [
            constants.host_01_uuid,
            constants.host_03_uuid,
            constants.host_04_uuid,
        ]
        justification = 'All these can be ignored'
        response = self.client.post(
            reverse('rule-ack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': systems_list,
                'justification': justification,
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        new_list = response.json()
        self.assertIsInstance(new_list, dict)
        self.assertEqual(
            new_list, {
                'count': 3,
                'host_ids': [constants.host_06_uuid]
            }
        )

        # Check that we now have acks for those hosts on this rule
        response = self.client.get(
            reverse('hostack-list'),
            data={'rule_id': constants.active_rule},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        self.assertIn('data', hostack_page)
        self.assertIsInstance(hostack_page['data'], list)
        hostack_list = hostack_page['data']
        for row, system in enumerate(systems_list):
            # ID and create/update dates will change, just test the fields
            # that are fixed
            self.assertEqual(hostack_list[row]['rule'], constants.active_rule)
            self.assertEqual(hostack_list[row]['system_uuid'], system)
            self.assertEqual(hostack_list[row]['justification'], justification)
            self.assertEqual(hostack_list[row]['created_by'], 'testing')

        # Test blank justification, for Allen :-)
        response = self.client.post(
            reverse('rule-ack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': systems_list,
                'justification': '',
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        new_list = response.json()
        self.assertIsInstance(new_list, dict)
        self.assertEqual(
            new_list, {
                'count': 0,  # no new acks created.
                'host_ids': [constants.host_06_uuid],
            }
        )

        # Now delete some of those acks...
        removed_systems_list = [
            systems_list[0], systems_list[2],
        ]
        response = self.client.post(
            reverse('rule-unack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': removed_systems_list,
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        new_list = response.json()
        self.assertIsInstance(new_list, dict)
        self.assertEqual(
            new_list, {
                'count': 2,
                'host_ids': [
                    constants.host_01_uuid,
                    constants.host_04_uuid,
                    constants.host_06_uuid,
                ],
            }
        )

        # And the ack for system 3 should remain
        response = self.client.get(
            reverse('hostack-list'),
            data={'rule_id': constants.active_rule},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        self.assertIn('data', hostack_page)
        self.assertIsInstance(hostack_page['data'], list)
        hostack_list = hostack_page['data']
        self.assertEqual(len(hostack_list), 1)
        self.assertEqual(hostack_list[0]['rule'], constants.active_rule)
        self.assertEqual(hostack_list[0]['system_uuid'], systems_list[1])
        self.assertEqual(hostack_list[0]['justification'], '')
        self.assertEqual(hostack_list[0]['created_by'], 'testing')

        # If we try to delete exactly the same hosts again, we should get
        # a count of zero and an empty list:
        response = self.client.post(
            reverse('rule-unack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': removed_systems_list,
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        new_list = response.json()
        self.assertIsInstance(new_list, dict)
        self.assertEqual(new_list, {
            'count': 0,
            'host_ids': [  # list of hosts (still) affected by this rule
                constants.host_01_uuid,
                constants.host_04_uuid,
                constants.host_06_uuid,
            ],
        })

        # Adding a host that doesn't exist, or is in another account, should
        # be a 400 but not give away which host is in another account.
        response = self.client.post(
            reverse('rule-ack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': [constants.remote_branch_uc, constants.host_02_uuid],
                'justification': 'nonexistent host'
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"systems": {
                '0': [f"Host with UUID '{constants.remote_branch_lc}' not found"],
                '1': [f"Host with UUID '{constants.host_02_uuid}' not found"]
            }}
        )
        # Adding a host that isn't in UUID form should be a 400
        response = self.client.post(
            reverse('rule-ack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': [constants.host_01_name],
                'justification': 'invalid UUID'
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content.decode(),
            '{"systems":{"0":["Must be a valid UUID."]}}'
        )
        # Adding acks with a justification that's too long should be a 400
        response = self.client.post(
            reverse('rule-ack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': [constants.host_01_uuid],
                'justification': 'x' * 500
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content.decode(),
            '{"justification":["Ensure this field has no more than 255 characters."]}'
        )
        # Deleting a hostack from a host that doesn't exist, or isn't in this
        # account, should be a 400, with no differentiation between.
        response = self.client.post(
            reverse('rule-unack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': [constants.remote_branch_uc, constants.host_02_uuid],
                'justification': 'nonexistent host'
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"systems": {
                '0': [f"Host with UUID '{constants.remote_branch_lc}' not found"],
                '1': [f"Host with UUID '{constants.host_02_uuid}' not found"]
            }}
        )
        # Deleting a hostack from a host that isn't in UUID form should be a 400
        response = self.client.post(
            reverse('rule-ack-hosts', kwargs={'rule_id': constants.active_rule}),
            data={
                'systems': [constants.host_01_name],
                'justification': 'invalid UUID'
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content.decode(),
            '{"systems":{"0":["Must be a valid UUID."]}}'
        )

    def test_rule_component_pathway_counts(self):
        pathways = {'test-component-1': 2, 'test-component-2': 0}
        for pathway, count in pathways.items():
            response = self.client.get(reverse('rule-list'), data={'pathway': pathway},
                                       **auth_header_for_testing(account='1234567', org_id='9876543'))
            rules = response.json()['data']
            self.assertEqual(len(rules), count)

    def test_rule_pathway_serializer(self):
        # Testing the RulePathwaySerializer to get pathway info (if it exists) for various rules
        # Active_rule has pathway test component 1
        active_rule = self.client.get(reverse('rule-detail', kwargs={'rule_id': constants.active_rule}),
                                      **self.default_header).json()
        self.assertEqual(active_rule['pathway']['name'], 'test component 1')
        self.assertEqual(active_rule['pathway']['resolution_risk']['name'], 'Adjust Service Status')

        # Second_rule doesn't have a pathway, so it won't have a pathway key (due to the NonNullModelSerializer)
        second_rule = self.client.get(
            reverse('rule-detail', kwargs={'rule_id': constants.second_rule}),
            **self.default_header
        ).json()
        self.assertFalse('pathway' in second_rule.keys())


class InternalRuleTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule'
    ]

    default_header = auth_header_for_testing()
    internal_header = auth_header_for_testing(user_opts={'is_internal': True})

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_rule_list_detail(self):
        our_turnpike_user = turnpike_auth_header_for_testing(
            Role=['insights-rule-dev', 'other-ldap-group']
        )

        # Access is denied to normal users
        response = self.client.get(
            reverse('internal-rule-list'),
            **self.default_header
        )
        self.assertEqual(response.status_code, 403)
        # Access is denied to internal users even with RBAC being OK.
        response = self.client.get(
            reverse('internal-rule-list'),
            **self.internal_header
        )
        self.assertEqual(response.status_code, 403)
        # Turnpike users can access the reports list, regardless of their
        # LDAP groups
        response = self.client.get(
            reverse('internal-rule-list'),
            **our_turnpike_user
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        rules_page = response.json()
        self.assertEqual(sorted(rules_page.keys()), ['data', 'links', 'meta'])
        self.assertEqual(
            [r['rule_id'] for r in rules_page['data']],
            [
                constants.acked_rule, constants.active_rule, constants.deleted_rule,
                constants.high_sev_rule, constants.inactive_rule,
                constants.notyetactive_rule, constants.second_rule
            ]
        )

        # Access is denied to normal users
        response = self.client.get(
            reverse('internal-rule-detail', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 403)
        # Access is denied to internal users even with RBAC being OK.
        response = self.client.get(
            reverse('internal-rule-detail', kwargs={'rule_id': constants.active_rule}),
            **self.internal_header
        )
        self.assertEqual(response.status_code, 403)
        # Turnpike users can access the reports list, regardless of their
        # LDAP groups
        response = self.client.get(
            reverse('internal-rule-detail', kwargs={'rule_id': constants.active_rule}),
            **our_turnpike_user
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        rule = response.json()
        self.assertEqual(rule['rule_id'], constants.active_rule)

    def test_rule_reports_content_preview(self):
        our_turnpike_user = turnpike_auth_header_for_testing(
            Role=['insights-rule-dev', 'other-ldap-group']
        )

        # Access is denied to normal users
        response = self.client.get(
            reverse('internal-rule-reports', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 403)
        # Access is denied to internal users even with RBAC being OK.
        response = self.client.get(
            reverse('internal-rule-reports', kwargs={'rule_id': constants.active_rule}),
            **self.internal_header
        )
        self.assertEqual(response.status_code, 403)
        # Turnpike users can access the reports list, regardless of their
        # LDAP groups
        response = self.client.get(
            reverse('internal-rule-reports', kwargs={'rule_id': constants.active_rule}),
            **our_turnpike_user
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        reports_page = response.json()
        self.assertIsInstance(reports_page, dict)
        self.assertIn('meta', reports_page)
        self.assertIn('links', reports_page)
        self.assertIn('data', reports_page)
        reports = reports_page['data']
        self.assertIsInstance(reports, list)
        # Reports ordered by upload checked-on, so not affected by staleness
        # Rpt 24: stale-hide-2
        # Rpt 23: stale-hide-1
        # Rpt 19: customer 2 system 7
        # Rpt 21: stale-warn upload 2
        # Rpt 11: stale-warn upload 1
        # Rpt 8: system 1
        # Rpt 17: system 3
        # Rpt 4: customer 2 system 2
        self.assertTrue(all('delta' in report for report in reports))
        self.assertTrue(all('details' in report for report in reports))
        self.assertTrue(all(
            'error_key' in report['details'] for report in reports))
        # Most of these reports are on RHEL but one is on RHEV.
        self.assertEqual(len(reports), 8)


class RuleStatusAutoAckTestCase(TestCase):
    # Setup the test database with the basic_test_data fixture
    fixtures = ['rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data']

    default_header = auth_header_for_testing()

    def test_rule_status_with_autoacks(self):
        # Initial setup and import the content
        import json
        from project_settings.settings import AUTOACK
        from api.scripts import import_content
        from api.tests.test_import_content import BASIC_TEST_DATA_CONFIG, BASIC_TEST_DATA_CONTENT

        rtc = RuleTestCase()
        accounts_orgs = [
            {'account': '1234567', 'org_id': '9876543'},
            {'account': '1122334', 'org_id': '9988776'}
        ]

        # Get model instances for Active, Acked and Second rules
        active_rule = Rule.objects.get(rule_id="test|Active_rule")
        acked_rule = Rule.objects.get(rule_id="test|Acked_rule")
        second_rule = Rule.objects.get(rule_id="test|Second_rule")

        # Nothing up our sleeves ... should be acks on Acked and Second rules but none on Active
        self.assertTrue(Ack.objects.filter(rule__in=[acked_rule, second_rule]).exists())
        self.assertFalse(Ack.objects.filter(rule=active_rule).exists())
        self.assertEqual(Ack.objects.count(), 4)
        self.assertEqual(Ack.objects.filter(created_by=AUTOACK['CREATED_BY']).count(), 0)

        # Import the content and add an autoack for Active rule
        import_content.import_all(
            json.loads(BASIC_TEST_DATA_CONFIG),
            json.loads(BASIC_TEST_DATA_CONTENT.replace('replaceme1', AUTOACK['TAG']))
        )

        # Confirm there are 6 acks now, 2 of which are autoacks
        self.assertEqual(Ack.objects.count(), 6)
        self.assertEqual(Ack.objects.filter(created_by=AUTOACK['CREATED_BY']).count(), 2)

        # Ok, now to test rule_status
        # Test getting list of all rules with rule_status='all' and rule_status parameter missing
        for account_org in accounts_orgs:
            for response in (
                self.client.get(
                    reverse('rule-list'), data={'rule_status': 'all'},
                    **auth_header_for_testing(
                        account=account_org['account'],
                        org_id=account_org['org_id']
                    )
                ),
                self.client.get(
                    reverse('rule-list'),
                    **auth_header_for_testing(
                        account=account_org['account'],
                        org_id=account_org['org_id']
                    )
                )
            ):
                rules = rtc._response_is_good(response)
                self.assertEqual(len(rules), 3)
                self.assertIn(constants.active_rule, rules)
                self.assertIn(constants.second_rule, rules)
                self.assertIn(constants.acked_rule, rules)

                self.assertEqual(rules[constants.active_rule]['rule_status'], 'rhdisabled')
                if account_org['org_id'] == '9876543':
                    self.assertEqual(rules[constants.second_rule]['rule_status'], 'enabled')
                else:
                    self.assertEqual(rules[constants.second_rule]['rule_status'], 'disabled')
                self.assertEqual(rules[constants.acked_rule]['rule_status'], 'disabled')

        # Test getting rule list of Red Hat disabled rules - should be Active rule for both accounts
        for account_org in accounts_orgs:
            response = self.client.get(
                reverse('rule-list'), data={'rule_status': 'rhdisabled'},
                **auth_header_for_testing(
                    account=account_org['account'],
                    org_id=account_org['org_id']
                )
            )
            rules = rtc._response_is_good(response)
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[constants.active_rule]['rule_status'], 'rhdisabled')

            # Test getting rule detail of Active rule as well - should be
            # Red Hat Disabled
            response = self.client.get(
                reverse('rule-detail', kwargs={'rule_id': constants.active_rule}),
                **auth_header_for_testing(
                    account=account_org['account'],
                    org_id=account_org['org_id']
                )
            )
            self.assertEqual(response.data['rule_status'], 'rhdisabled')

        # Re-import the content and add an autoack for Second rule - but it
        # won't overwrite the existing User ack
        import_content.update_ruleset_with_content(
            json.loads(
                BASIC_TEST_DATA_CONTENT
                .replace("replaceme1", AUTOACK['TAG'])
                .replace("replaceme2", AUTOACK['TAG'])
            )
        )

        # Get list of Red Hat disabled rules again - should still be the
        # Active rule for both accounts, but only the Second rule for account
        # 1234567 org id 9876543
        for account_org in accounts_orgs:
            response = self.client.get(
                reverse('rule-list'), data={'rule_status': 'rhdisabled'},
                **auth_header_for_testing(
                    account=account_org['account'],
                    org_id=account_org['org_id']
                )
            )
            rules = rtc._response_is_good(response)
            if account_org['org_id'] == '9876543':
                self.assertEqual(len(rules), 2)
                self.assertEqual(rules[constants.active_rule]['rule_status'], 'rhdisabled')
                self.assertEqual(rules[constants.second_rule]['rule_status'], 'rhdisabled')
            else:
                self.assertEqual(len(rules), 1)
                self.assertEqual(rules[constants.active_rule]['rule_status'], 'rhdisabled')

        # Remove autoack from Second Rule for account 1234567 org id 9876543 -
        # should be enabled now and only Active rule disabled
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.second_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get(
            reverse('rule-list'), data={'rule_status': 'rhdisabled'},
            **self.default_header
        )
        rules = rtc._response_is_good(response)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[constants.active_rule]['rule_status'], 'rhdisabled')
        response = self.client.get(
            reverse('rule-list'), data={'rule_status': 'enabled'},
            **self.default_header
        )
        rules = rtc._response_is_good(response)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[constants.second_rule]['rule_status'], 'enabled')
        response = self.client.get(
            reverse('rule-detail', kwargs={'rule_id': constants.second_rule}),
            **self.default_header
        )
        self.assertEqual(response.data['rule_status'], 'enabled')

        # Add user ack to Second Rule for account 1234567 org id 9876543 - rule_status should be just Disabled
        response = self.client.post(
            reverse('ack-list'), data={
                'rule_id': constants.second_rule,
                'justification': 'Coz'
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.get(
            reverse('rule-detail', kwargs={'rule_id': constants.second_rule}),
            **self.default_header
        )
        self.assertEqual(response.data['rule_status'], 'disabled')

        # Confirm that Second rule is plain 'disabled' for both accounts now
        for account_org in accounts_orgs:
            response = self.client.get(
                reverse('rule-list'), data={'rule_status': 'disabled'},
                **auth_header_for_testing(
                    account=account_org['account'],
                    org_id=account_org['org_id']
                )
            )
            rules = rtc._response_is_good(response)
            self.assertEqual(len(rules), 2)
            self.assertEqual(rules[constants.second_rule]['rule_status'], 'disabled')
            self.assertEqual(rules[constants.acked_rule]['rule_status'], 'disabled')

        # Remove autoack from Active Rule for account 1234567 org id 9876543
        # Shouldn't be any Red Hat disabled rules anymore for that account
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.active_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get(
            reverse('rule-list'), data={'rule_status': 'rhdisabled'},
            **self.default_header
        )
        rules = rtc._response_is_good(response)
        self.assertEqual(len(rules), 0)


class RuleHostTagsTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_rule_list(self):
        response = self.client.get(
            reverse('rule-list'),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIn('data', json_data)
        rules_page = json_data['data']
        self.assertIsInstance(rules_page, list)
        self.assertEqual(len(rules_page), 3)
        self.assertEqual(rules_page[0]['rule_id'], constants.acked_rule)
        self.assertEqual(rules_page[0]['impacted_systems_count'], 0)
        self.assertEqual(rules_page[1]['rule_id'], constants.active_rule)
        self.assertEqual(rules_page[1]['impacted_systems_count'], 4)
        self.assertEqual(rules_page[2]['rule_id'], constants.second_rule)
        self.assertEqual(rules_page[2]['impacted_systems_count'], 3)  # Host ack
        self.assertEqual(rules_page[2]['hosts_acked_count'], 1)  # Host ack

        # Only one system
        response = self.client.get(
            reverse('rule-list'),
            data={'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIn('data', json_data)
        rules_page = json_data['data']
        self.assertIsInstance(rules_page, list)
        self.assertEqual(len(rules_page), 3)
        self.assertEqual(rules_page[0]['rule_id'], constants.acked_rule)
        self.assertEqual(rules_page[0]['impacted_systems_count'], 0)
        self.assertEqual(rules_page[1]['rule_id'], constants.active_rule)
        self.assertEqual(rules_page[1]['impacted_systems_count'], 1)
        self.assertEqual(rules_page[2]['rule_id'], constants.second_rule)
        self.assertEqual(rules_page[2]['impacted_systems_count'], 0)  # Host ack
        self.assertEqual(rules_page[2]['hosts_acked_count'], 1)  # Host ack

        # Two systems, selected with a wildcard
        response = self.client.get(
            reverse('rule-list'),
            data={'tags': 'customer/security=high'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIn('data', json_data)
        rules_page = json_data['data']
        self.assertIsInstance(rules_page, list)
        self.assertEqual(len(rules_page), 3)
        self.assertEqual(rules_page[0]['rule_id'], constants.acked_rule)
        self.assertEqual(rules_page[0]['impacted_systems_count'], 0)
        self.assertEqual(rules_page[1]['rule_id'], constants.active_rule)
        self.assertEqual(rules_page[1]['impacted_systems_count'], 2)
        self.assertEqual(rules_page[2]['rule_id'], constants.second_rule)
        self.assertEqual(rules_page[2]['impacted_systems_count'], 2)
        # No Host ack for either of these systems
        self.assertEqual(rules_page[2]['hosts_acked_count'], 0)

    def test_systems_for_a_rule(self):
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [
            constants.host_ht_01_uuid,
            constants.host_ht_02_uuid,
            constants.host_ht_03_uuid,
            constants.host_ht_04_uuid
        ])

        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [
            constants.host_ht_02_uuid,
            constants.host_ht_03_uuid,
            constants.host_ht_04_uuid
        ])

        # Search on a specific tag
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'tags': 'customer/environment=web'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [
            constants.host_ht_02_uuid,
            constants.host_ht_04_uuid
        ])

        # No matching systems - tag doesn't exist
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'tags': 'elephant/in=the_room'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [])
        # No matching systems - tag intersection has no systems
        response = self.client.get(
            reverse('rule-systems', kwargs={'rule_id': constants.active_rule}),
            data={'tags': 'AWS/location=SLC,customer/environment=web'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIn('host_ids', hosts)
        self.assertIsInstance(hosts['host_ids'], list)
        self.assertEqual(hosts['host_ids'], [])

    def test_systems_details_for_a_rule(self):
        # Confirm we get the same results as /systems
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hosts = response.json()
        self.assertIsInstance(hosts, dict)
        self.assertEqual(sorted(hosts['data'][0].keys()), sorted([
            'system_uuid', 'display_name', 'last_seen', 'stale_at', 'hits',
            'critical_hits', 'important_hits', 'moderate_hits', 'low_hits',
            'incident_hits', 'all_pathway_hits', 'pathway_filter_hits',
            'rhel_version', 'impacted_date'
        ]))
        self.assertEqual(hosts['meta']['count'], 4)
        self.assertEqual(list(map(lambda h: h['display_name'], hosts['data'])), [
            "system01.example.biz", "system02.example.biz", "system03.example.biz", "system04.example.biz"
        ])

        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': '-display_name'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        hosts = response.json()
        self.assertEqual(list(map(lambda h: h['display_name'], hosts['data'])), [
            "system04.example.biz", "system03.example.biz", "system02.example.biz", "system01.example.biz"
        ])

        # Test sorting by system_profile (rhel_version) ascending
        # system01: RHEL7.10, system02: RHEL7.2, system03: RHEL8.3, system04: RHEL6.4
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': 'rhel_version'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        hosts = response.json()
        self.assertEqual(list(map(lambda h: h['display_name'], hosts['data'])), [
            "system04.example.biz", "system02.example.biz", "system01.example.biz", "system03.example.biz"
        ])

        # Sort by system_profile descending
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': '-rhel_version'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertEqual(list(map(lambda h: h['display_name'], hosts['data'])), [
            "system03.example.biz", "system01.example.biz", "system02.example.biz", "system04.example.biz"
        ])

        # Confirm tags get the same results as /systems
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.second_rule}),
            data={'tags': 'customer/environment=database'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertEqual(hosts['meta']['count'], 2)
        self.assertEqual(list(map(lambda h: h['system_uuid'], hosts['data'])), [
            constants.host_ht_03_uuid,
            constants.host_ht_04_uuid
        ])

        # Confirm tags get the same results as /systems, with sorting
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.second_rule}),
            data={'tags': 'customer/environment=database', 'sort': '-display_name'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertEqual(hosts['meta']['count'], 2)
        self.assertEqual(list(map(lambda h: h['system_uuid'], hosts['data'])), [
            constants.host_ht_04_uuid,
            constants.host_ht_03_uuid,
        ])

        # Confirm tags get the same results as /systems, with sorting
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'tags': 'customer/security=low', 'sort': 'hits'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertEqual(hosts['meta']['count'], 2)
        self.assertEqual(list(map(lambda h: [h['display_name'], h['hits']], hosts['data'])), [
            [constants.host_ht_01_name, 1],
            [constants.host_ht_04_name, 2]
        ])

    def test_systems_detail_has_impacted_date(self):
        # Confirm rule-systems-detail includes the impacted_date (and it's correct)
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            **auth_header_for_testing(account='1234567', org_id='9876543')
        )
        self.assertEqual(response.status_code, 200)
        hosts = response.json()
        self.assertEqual(hosts['meta']['count'], 4)

        # Hosts are sorted by display_name
        # Only system01 has an impacted date set via the fixtures
        # The others will have impacted_date set to now(), but just test they have the same date, which is close enough
        today = str(timezone.now().date())
        self.assertEqual(hosts['data'][0]['display_name'], constants.host_06_name)
        self.assertTrue(hosts['data'][0]['impacted_date'].startswith(today))
        self.assertEqual(hosts['data'][1]['display_name'], constants.host_01_name)
        self.assertEqual(hosts['data'][1]['impacted_date'], '2018-12-04T05:10:36Z')
        self.assertEqual(hosts['data'][2]['display_name'], constants.host_03_name)
        self.assertTrue(hosts['data'][2]['impacted_date'].startswith(today))
        self.assertEqual(hosts['data'][3]['display_name'], constants.host_04_name)
        self.assertTrue(hosts['data'][3]['impacted_date'].startswith(today))

    def test_sorting_by_group_name(self):
        def get_hosts(response):
            self.assertEqual(response.status_code, 200)
            hosts = response.json()
            return list(map(lambda h: h['display_name'], hosts['data']))

        # Test sorting by group_name ascending.  Hosts with no groups will be first in the list (sorted by hostname)
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': 'group_name'},
            **auth_header_for_testing(account='1234567', org_id='9876543')
        )
        self.assertEqual(get_hosts(response), [
            "stale-warn.example.com", "system04.example.com", "system01.example.com", "system03.example.com"
        ])

        # Sort by group_name descending.  Hosts with no groups will be at the bottom of the list (sorted by hostname)
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': '-group_name'},
            **auth_header_for_testing(account='1234567', org_id='9876543')
        )
        self.assertEqual(get_hosts(response), [
            "system03.example.com", "system01.example.com", "stale-warn.example.com", "system04.example.com"
        ])

        # Test sorting by group_name ascending, filtering on specific groups
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': 'group_name', 'groups': 'group_1,group_2'},
            **auth_header_for_testing(account='1234567', org_id='9876543')
        )
        self.assertEqual(get_hosts(response), [
            "system01.example.com", "system03.example.com"
        ])

        # Test sorting by group_name descending, filtering on specific groups
        response = self.client.get(
            reverse('rule-systems-detail', kwargs={'rule_id': constants.active_rule}),
            data={'sort': '-group_name', 'groups': 'group_1,group_2'},
            **auth_header_for_testing(account='1234567', org_id='9876543')
        )
        self.assertEqual(get_hosts(response), [
            "system03.example.com", "system01.example.com"
        ])
