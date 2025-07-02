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


class PlaybookViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def test_playbook_list(self):
        response = self.client.get(reverse('playbooks-list'))
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        rules = response.json()

        self.assertIsInstance(rules, dict)
        self.assertIn(constants.active_rule, rules)
        self.assertIsInstance(rules[constants.active_rule], list)
        self.assertEqual(rules[constants.active_rule][0], {
            "resolution_risk": 1,
            "resolution_type": "fixit",
            "play": '- name: Fix for Active_rule on rhel/host\n  become: true',
            "description": "Fix for Active_rule on rhel/host",
            "path": "/tmp/playbooks/Active_rule/fixit.yaml",
            "version": 'f592d01dca6aca063f2c3b2f7f4c261cef9fe114'
        })
        self.assertEqual(len(rules[constants.active_rule]), 1)

    def test_playbook_detail(self):
        response = self.client.get(
            reverse('playbooks-detail', kwargs={'rule_id': constants.active_rule})
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        playbooks = response.json()

        self.assertIsInstance(playbooks, list)
        self.assertEqual(playbooks[0], {
            "resolution_risk": 1,
            "resolution_type": "fixit",
            "play": '- name: Fix for Active_rule on rhel/host\n  become: true',
            "description": "Fix for Active_rule on rhel/host",
            "path": "/tmp/playbooks/Active_rule/fixit.yaml",
            "version": 'f592d01dca6aca063f2c3b2f7f4c261cef9fe114'
        })
        self.assertEqual(len(playbooks), 1)
