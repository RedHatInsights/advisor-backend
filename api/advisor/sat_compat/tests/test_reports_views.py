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


class ReportsViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertIn('resources', json)
        self.assertIsInstance(json['resources'], list)
        self.assertIn('total', json)
        self.assertIsInstance(json['total'], int)
        return json['resources']

    def test_list_reports(self):
        response = self.client.get(
            reverse('sat-compat-reports-list'), **auth_header_for_testing()
        )
        reports = self._response_is_good(response)
        self.assertIsInstance(reports, list)
        # Test all fields in first row
        self.assertIn('id', reports[0])
        self.assertEqual(reports[0]['id'], 21)
        self.assertIn('rule_id', reports[0])
        self.assertEqual(reports[0]['rule_id'], constants.active_rule)
        self.assertIn('system_id', reports[0])
        self.assertEqual(reports[0]['system_id'], constants.host_06_inid)
        self.assertIn('system', reports[0])
        self.assertIsInstance(reports[0]['system'], dict)
        self.assertEqual(reports[0]['system'], {
            'system_id': constants.host_06_inid,
            'display_name': constants.host_06_name,
            'last_check_in': '2019-04-05T14:30:00Z'
        })
        self.assertIn('account_number', reports[0])
        self.assertEqual(reports[0]['account_number'], constants.standard_acct)
        self.assertIn('org_id', reports[0])
        self.assertEqual(reports[0]['org_id'], constants.standard_org)
        self.assertIn('date', reports[0])
        self.assertEqual(reports[0]['date'], '2019-04-05T14:30:00Z')
        # And then just the data in the important fields in the other rows
        self.assertEqual(reports[1]['rule_id'], constants.active_rule)
        self.assertEqual(reports[1]['system_id'], constants.host_01_inid)
        self.assertEqual(reports[2]['rule_id'], constants.active_rule)
        self.assertEqual(reports[2]['system_id'], constants.host_03_inid)
        self.assertEqual(reports[3]['rule_id'], constants.active_rule)
        self.assertEqual(reports[3]['system_id'], constants.host_04_inid)
        self.assertEqual(reports[4]['rule_id'], constants.second_rule)
        self.assertEqual(reports[4]['system_id'], constants.host_03_inid)
        self.assertEqual(reports[5]['rule_id'], constants.second_rule)
        self.assertEqual(reports[5]['system_id'], constants.host_04_inid)
        self.assertEqual(len(reports), 6)

        # Filter on rule
        response = self.client.get(
            reverse('sat-compat-reports-list'),
            data={'rule': constants.second_rule},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        reports = self._response_is_good(response)
        self.assertEqual(reports[0]['rule_id'], constants.second_rule)
        self.assertEqual(reports[0]['system_id'], constants.host_03_inid)
        self.assertEqual(reports[1]['rule_id'], constants.second_rule)
        self.assertEqual(reports[1]['system_id'], constants.host_04_inid)
        self.assertEqual(len(reports), 2)

    def test_list_reports_cert_auth(self):
        # Satellite certificate authentication should only show us the hosts
        # managed by this Satellite - hosts 1, 3 and 5
        response = self.client.get(
            reverse('sat-compat-reports-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        reports = self._response_is_good(response)
        self.assertIsInstance(reports, list)
        # Test all fields in first row
        self.assertIn('id', reports[0])
        self.assertEqual(reports[0]['id'], 8)
        self.assertIn('rule_id', reports[0])
        self.assertEqual(reports[0]['rule_id'], constants.active_rule)
        self.assertIn('system_id', reports[0])
        self.assertEqual(reports[0]['system_id'], constants.host_01_inid)
        self.assertIn('system', reports[0])
        self.assertIsInstance(reports[0]['system'], dict)
        self.assertEqual(reports[0]['system'], {
            'system_id': constants.host_01_inid,
            'display_name': constants.host_01_name,
            'last_check_in': '2018-12-04T05:15:38Z'
        })
        self.assertIn('account_number', reports[0])
        self.assertEqual(reports[0]['account_number'], constants.standard_acct)
        self.assertIn('org_id', reports[0])
        self.assertEqual(reports[0]['org_id'], constants.standard_org)
        self.assertIn('date', reports[0])
        self.assertEqual(reports[0]['date'], '2018-12-04T05:10:36Z')
        # And then just the data in the important fields in the other rows
        self.assertEqual(reports[1]['rule_id'], constants.active_rule)
        self.assertEqual(reports[1]['system_id'], constants.host_03_inid)
        self.assertEqual(reports[2]['rule_id'], constants.second_rule)
        self.assertEqual(reports[2]['system_id'], constants.host_03_inid)
        self.assertEqual(len(reports), 3)


class ReportsDupInsightsIDViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'sat_dup_insights_id_host',
    ]
    std_header = auth_header_for_testing()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_list_reports(self):
        response = self.client.get(
            reverse('sat-compat-reports-list'), **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertIn('resources', json)
        reports = json['resources']
        # Note no host_11_inid, because reports are linked to Inventory ID
        self.assertEqual(reports[0]['rule_id'], constants.active_rule)
        self.assertEqual(reports[0]['system_id'], constants.host_06_inid)
        self.assertEqual(reports[1]['rule_id'], constants.active_rule)
        self.assertEqual(reports[1]['system_id'], constants.host_01_inid)
        self.assertEqual(reports[2]['rule_id'], constants.active_rule)
        self.assertEqual(reports[2]['system_id'], constants.host_03_inid)
        self.assertEqual(reports[3]['rule_id'], constants.active_rule)
        self.assertEqual(reports[3]['system_id'], constants.host_04_inid)
        self.assertEqual(reports[4]['rule_id'], constants.second_rule)
        self.assertEqual(reports[4]['system_id'], constants.host_03_inid)
        self.assertEqual(reports[5]['rule_id'], constants.second_rule)
        self.assertEqual(reports[5]['system_id'], constants.host_04_inid)
        self.assertEqual(len(reports), 6)
