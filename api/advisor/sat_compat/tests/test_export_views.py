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
from json import loads

from django.test import TestCase
from django.urls import reverse

from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing

reports_header = [
    'System Name', 'System ID', 'Rule', 'Rule ID', 'Category', 'Severity',
    'URL', 'Article', 'Reported Time (UTC)'
]
systems_header = [
    'System Name', 'System ID', 'System Type', 'Registration Date (UTC)',
    'Last Check In (UTC)', 'Stale', 'Actions', 'URL',
]


class SatExportViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'sat_maintenance'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response, header_list=None):
        """
        Try to check that the response is good, handling both accepted media
        types and both the standard and streaming HTTP response classes.
        """
        self.assertEqual(response.status_code, 200)

        # Get content, either from streaming or regular
        if hasattr(response, 'content'):
            content = response.content.decode()
        elif hasattr(response, 'streaming_content'):
            content = ''.join(s.decode() for s in response.streaming_content)
        else:
            self.Fail("Response object has no content/streaming content")

        # Decode the content, whatever it is
        if hasattr(response, 'accepted_media_type') and response.accepted_media_type == constants.csv_mime:
            csv_data = list(csv.reader(content.splitlines()))
            # Header should be first
            self.assertIsInstance(csv_data[0], list)
            if header_list:
                self.assertEqual(csv_data[0], header_list)  # test against given
            else:
                header_list = csv_data[0]  # take from data
            return [{
                header_list[index]: field
                for index, field in enumerate(row)
            } for row in csv_data[1:]]
        elif 'Content-Type' in response.headers and response.headers['Content-Type'] == constants.json_mime:
            return loads(content)
        else:
            self.Fail(f"Don't know how to decode {response} (headers {response.headers}")

    def test_reports_export(self):
        """
        Tests of reports export.
        """
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('sat-compat-export-reports-list'), **headers
        )
        row_data = self._response_is_good(response, reports_header)
        # Test first row for all columns and values
        self.assertIn('System Name', row_data[0])
        self.assertEqual(row_data[0]['System Name'], constants.host_06_name)
        self.assertIn('System ID', row_data[0])
        self.assertEqual(row_data[0]['System ID'], constants.host_06_inid)
        self.assertIn('Rule', row_data[0])
        self.assertEqual(row_data[0]['Rule'], constants.active_title)
        self.assertIn('Rule ID', row_data[0])
        self.assertEqual(row_data[0]['Rule ID'], constants.active_rule)
        self.assertIn('Category', row_data[0])
        self.assertEqual(row_data[0]['Category'], 'Availability')
        self.assertIn('Severity', row_data[0])
        self.assertEqual(row_data[0]['Severity'], 'INFO')
        self.assertIn('URL', row_data[0])
        self.assertEqual(row_data[0]['URL'],
            'https://access.redhat.com/insights/actions/availability/'
            'test|Active_rule?machine=00112233-4455-6677-8899-012345678906')
        self.assertIn('Article', row_data[0])
        self.assertEqual(row_data[0]['Article'], 'https://access.redhat.com/node/1048576')
        self.assertIn('Reported Time (UTC)', row_data[0])
        self.assertEqual(row_data[0]['Reported Time (UTC)'], '2019-04-05 14:30:00+00:00')
        # Then check rest of rows for particular values
        self.assertEqual(row_data[1]['System Name'], constants.host_01_name)
        self.assertEqual(row_data[1]['Rule ID'], constants.active_rule)
        self.assertEqual(row_data[2]['System Name'], constants.host_03_name)
        self.assertEqual(row_data[2]['Rule ID'], constants.active_rule)
        self.assertEqual(row_data[3]['System Name'], constants.host_04_name)
        self.assertEqual(row_data[3]['Rule ID'], constants.active_rule)
        self.assertEqual(row_data[4]['System Name'], constants.host_03_name)
        self.assertEqual(row_data[4]['Rule ID'], constants.second_rule)
        self.assertEqual(row_data[4]['Article'], '')
        self.assertEqual(row_data[5]['System Name'], constants.host_04_name)
        self.assertEqual(row_data[5]['Rule ID'], constants.second_rule)
        self.assertEqual(len(row_data), 6)

    def test_reports_export_cert_auth(self):
        """
        Tests of reports export with Satellite certificate authentication.
        """
        headers = auth_header_for_testing(system_opts=constants.host_03_system_data)
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('sat-compat-export-reports-list'), **headers
        )
        row_data = self._response_is_good(response)
        # Only the systems from this Satellite though...
        # Test first row for all columns and values
        self.assertIn('System Name', row_data[0])
        self.assertEqual(row_data[0]['System Name'], constants.host_01_name)
        self.assertIn('System ID', row_data[0])
        self.assertEqual(row_data[0]['System ID'], constants.host_01_inid)
        self.assertIn('Rule', row_data[0])
        self.assertEqual(row_data[0]['Rule'], constants.active_title)
        self.assertIn('Rule ID', row_data[0])
        self.assertEqual(row_data[0]['Rule ID'], constants.active_rule)
        self.assertIn('Category', row_data[0])
        self.assertEqual(row_data[0]['Category'], 'Availability')
        self.assertIn('Severity', row_data[0])
        self.assertEqual(row_data[0]['Severity'], 'INFO')
        self.assertIn('URL', row_data[0])
        self.assertEqual(row_data[0]['URL'],
            'https://access.redhat.com/insights/actions/availability/'
            'test|Active_rule?machine=00112233-4455-6677-8899-012345678901')
        self.assertIn('Article', row_data[0])
        self.assertEqual(row_data[0]['Article'], 'https://access.redhat.com/node/1048576')
        self.assertIn('Reported Time (UTC)', row_data[0])
        self.assertEqual(row_data[0]['Reported Time (UTC)'], '2018-12-04 05:10:36+00:00')
        # Then check rest of rows for particular values
        self.assertEqual(row_data[1]['System Name'], constants.host_03_name)
        self.assertEqual(row_data[1]['Rule ID'], constants.active_rule)
        self.assertEqual(row_data[2]['System Name'], constants.host_03_name)
        self.assertEqual(row_data[2]['Rule ID'], constants.second_rule)
        self.assertEqual(row_data[2]['Article'], '')
        self.assertEqual(len(row_data), 3)

    def test_systems_export(self):
        """
        Tests of systems export.
        """
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('sat-compat-export-systems-list'), **headers
        )
        row_data = self._response_is_good(response)
        # Test first row for all columns and values
        # All fields are strings, and normally hidden hosts are shown
        self.assertIn('System Name', row_data[0])
        self.assertEqual(row_data[0]['System Name'], constants.host_e1_name)
        self.assertIn('System ID', row_data[0])
        self.assertEqual(row_data[0]['System ID'], constants.host_e1_inid)
        self.assertIn('System Type', row_data[0])
        self.assertEqual(row_data[0]['System Type'], 'RHEL Server')
        self.assertIn('Registration Date (UTC)', row_data[0])
        self.assertEqual(row_data[0]['Registration Date (UTC)'], "2020-06-25 06:00:00+00:00")
        self.assertIn('Last Check In (UTC)', row_data[0])
        self.assertEqual(row_data[0]['Last Check In (UTC)'], "2020-06-25 07:56:27+00:00")
        self.assertIn('Stale', row_data[0])
        self.assertEqual(row_data[0]['Stale'], 'False')
        self.assertIn('Actions', row_data[0])
        self.assertEqual(row_data[0]['Actions'], '0')
        self.assertIn('URL', row_data[0])
        self.assertEqual(row_data[0]['URL'],
            'https://console.redhat.com/insights/advisor/systems/classic/'
            '00112233-4455-6677-8899-0123456789e1')
        # Then test remaining rows for the key fields we expect to change
        self.assertEqual(row_data[1]['System Name'], constants.host_0A_name)
        self.assertEqual(row_data[1]['Stale'], 'True')
        self.assertEqual(row_data[1]['Actions'], '0')
        self.assertEqual(row_data[2]['System Name'], constants.host_08_name)
        self.assertEqual(row_data[2]['Stale'], 'True')
        self.assertEqual(row_data[2]['Actions'], '0')
        self.assertEqual(row_data[3]['System Name'], constants.host_06_name)
        self.assertEqual(row_data[3]['Stale'], 'True')
        self.assertEqual(row_data[3]['Actions'], '0')
        self.assertEqual(row_data[4]['System Name'], constants.host_01_name)
        self.assertEqual(row_data[4]['Stale'], 'False')
        self.assertEqual(row_data[4]['Actions'], '2')
        self.assertEqual(row_data[5]['System Name'], constants.host_03_name)
        self.assertEqual(row_data[6]['System Name'], constants.host_04_name)
        self.assertEqual(row_data[7]['System Name'], constants.host_05_name)
        self.assertEqual(len(row_data), 8)

    def test_systems_export_cert_auth(self):
        """
        Tests of systems export with Satellite certificate authentication.
        """
        headers = auth_header_for_testing(system_opts=constants.host_03_system_data)
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('sat-compat-export-systems-list'), **headers
        )
        row_data = self._response_is_good(response)
        # Only the systems from this Satellite though...
        # Test first row for all columns and values
        # All fields are strings
        self.assertIn('System Name', row_data[0])
        self.assertEqual(row_data[0]['System Name'], constants.host_01_name)
        self.assertIn('System ID', row_data[0])
        self.assertEqual(row_data[0]['System ID'], constants.host_01_inid)
        self.assertIn('System Type', row_data[0])
        self.assertEqual(row_data[0]['System Type'], 'RHEL Server')
        self.assertIn('Registration Date (UTC)', row_data[0])
        self.assertEqual(row_data[0]['Registration Date (UTC)'], "2020-01-01 06:00:00+00:00")
        self.assertIn('Last Check In (UTC)', row_data[0])
        self.assertEqual(row_data[0]['Last Check In (UTC)'], "2018-12-04 05:15:38+00:00")
        self.assertIn('Stale', row_data[0])
        self.assertEqual(row_data[0]['Stale'], 'False')  # ?!
        self.assertIn('Actions', row_data[0])
        self.assertEqual(row_data[0]['Actions'], '2')
        self.assertIn('URL', row_data[0])
        self.assertEqual(row_data[0]['URL'],
            'https://console.redhat.com/insights/advisor/systems/classic/'
            '00112233-4455-6677-8899-012345678901')
        # Then test remaining rows for the key fields we expect to change
        self.assertEqual(row_data[1]['System Name'], constants.host_03_name)
        self.assertEqual(row_data[1]['Actions'], '0')
        self.assertEqual(row_data[2]['System Name'], constants.host_05_name)
        self.assertEqual(row_data[2]['Actions'], '0')
