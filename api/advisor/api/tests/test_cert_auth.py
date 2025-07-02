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

import base64

from django.test import TestCase
from django.urls import reverse

from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing, auth_header_key


def bad_header(json_str):
    return {auth_header_key: base64.b64encode(json_str.encode())}


class CertAuthTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, 'application/json')
        return response.json()

    def test_auth_failures(self):
        # Test the various ways a header can be mis-constructed to fail cert
        # auth checks.  This doesn't need to check bad header construction,
        # as that's checked by test_view_auth.
        # Note that because the system viewset's permissions classes are ORed
        # together, we do not get the CertAuth permissions class messages.
        bad_start = (
            '{"identity": {"account_number": "1234567", "org_id": "9876543", '
            '"auth_type": "cert-auth", '
        )
        response = self.client.get(
            reverse('system-list'),
            **bad_header(bad_start + '"system": {}}}'),
        )
        self.assertEqual(response.status_code, 403, "System type missing check failed")
        response = self.client.get(
            reverse('system-list'),
            **bad_header(bad_start + '"type": "System"}}'),
        )
        self.assertEqual(response.status_code, 403, "Missing system property check failed")
        response = self.client.get(
            reverse('system-list'),
            **bad_header(bad_start + '"type": "System", "system": "11223344"}}'),
        )
        self.assertEqual(response.status_code, 403, "System property not an object check failed")
        response = self.client.get(
            reverse('system-list'),
            **bad_header(bad_start + '"type": "System", "system": {}}}'),
        )
        self.assertEqual(response.status_code, 403, "System property has no cn check failed")
        response = self.client.get(
            reverse('system-list'),
            **bad_header(bad_start + '"type": "System", "system": {"cn": 3}}}'),
        )
        self.assertEqual(response.status_code, 403, "System property has non-string cn check failed")
        response = self.client.get(
            reverse('system-list'),
            **bad_header(bad_start + '"type": "System", "system": {"cn": "banana"}}}'),
        )
        self.assertEqual(response.status_code, 403, "System property has non-UUID cn check failed")

    def test_list_system_satellite(self):
        # Host 03 is the nominal Satellite, so it should see all the systems
        # it owns.
        response = self.client.get(
            reverse('system-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data),
        )
        json = self._response_is_good(response)
        systems = json['data']

        self.assertIsInstance(systems, list)
        # List sorted by reverse hits order?
        self.assertEqual(systems[0]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(systems[1]['system_uuid'], constants.host_01_uuid)
        self.assertEqual(systems[2]['system_uuid'], constants.host_05_uuid)
        self.assertEqual(len(systems), 3)

    def test_list_system_self_owned(self):
        response = self.client.get(
            reverse('system-list'),
            **auth_header_for_testing(system_opts=constants.host_04_system_data),
        )
        json = self._response_is_good(response)
        systems = json['data']

        self.assertIsInstance(systems, list)
        self.assertEqual(len(systems), 1)
        self.assertEqual(systems[0]['system_uuid'], constants.host_04_uuid)

    def test_get_non_owned_system(self):
        response = self.client.get(
            reverse('system-detail', kwargs={'uuid': constants.host_04_uuid}),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 404)

    def test_get_non_owned_system_reports(self):
        response = self.client.get(
            reverse('system-reports', kwargs={'uuid': constants.host_04_uuid}),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        # Apparently we don't report a 404 here?
        reports = self._response_is_good(response)
        self.assertEqual(len(reports), 0)

    def test_rule_list(self):
        response = self.client.get(
            reverse('rule-list'),
            data={'impacting': 'true'},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        rules = self._response_is_good(response)['data']

        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[0]['rule_id'], constants.acked_rule)
        self.assertEqual(rules[0]['impacted_systems_count'], 1)
        self.assertEqual(rules[1]['rule_id'], constants.active_rule)
        self.assertEqual(rules[1]['impacted_systems_count'], 2)
        self.assertEqual(rules[2]['rule_id'], constants.second_rule)
        self.assertEqual(rules[2]['impacted_systems_count'], 1)

    def test_systems_stats(self):
        response = self.client.get(
            reverse('stats-systems'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        stats = self._response_is_good(response)

        # All hosts managed by Satellite - 1, 3 and 5 (which has no reports)
        self.assertEqual(
            stats,
            {
                'total': 2,
                'category': {
                    'Availability': 2,
                    'Performance': 1,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0}
            }
        )

    def test_topic_list(self):
        response = self.client.get(
            reverse('ruletopic-list'), **auth_header_for_testing(
                system_opts=constants.host_03_system_data,
            )
        )
        topic_list = self._response_is_good(response)

        self.assertIsInstance(topic_list, list)
        self.assertEqual(len(topic_list), 2)

        self.assertEqual(topic_list[0]['impacted_systems_count'], 2)
        self.assertEqual(topic_list[1]['impacted_systems_count'], 0)
