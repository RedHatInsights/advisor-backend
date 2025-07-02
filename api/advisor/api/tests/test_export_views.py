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
from api.models import Rule, Tag

import csv
from datetime import date
from json import loads


hits_headers = [
    'hostname', 'uuid', 'rhel_version', 'last_seen', 'title',
    'solution_url', 'total_risk', 'likelihood', 'publish_date',
    'stale_at', 'results_url'
]
systems_headers = [
    'system_uuid', 'display_name', 'last_seen', 'stale_at', 'hits',
    'critical_hits', 'important_hits', 'moderate_hits', 'low_hits',
    'rhel_version', 'group_name'
]


class ExportViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
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
            self.assertIsNotNone(header_list, "If CSV, must have header_list= argument")
            csv_data = list(csv.reader(content.splitlines()))
            # Header should be first
            self.assertIsInstance(csv_data[0], list)
            self.assertEqual(csv_data[0], header_list)
            return [{
                header_list[index]: field
                for index, field in enumerate(row)
            } for row in csv_data[1:]]
        elif 'Content-Type' in response.headers and response.headers['Content-Type'] == constants.json_mime:
            return loads(content)
        else:
            self.Fail(f"Don't know how to decode {response} (headers {response.headers}")

    def test_host_and_rule_export(self):
        """
        Tests of host_and_rule export; no Inventory testing yet.
        """

        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._response_is_good(response, hits_headers)
        # Systems: 1, 3, 4, 5 - 5 has no reports
        # Rules: Active rule (1), Second rule (5).
        # Reports: 8 (Active on 1), 17 (Active on 3), 7 (Second on 3),
        # 11 (Active on 4), and 12 (Second on 4).
        # Go through these reports in the above order, since the result set
        # should be in host and rule order.
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['rhel_version'], '7.5')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[1]['rhel_version'], '7.5')
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(row_data[2]['rhel_version'], '7.5')
        self.assertEqual(row_data[3]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['title'], constants.active_title)
        self.assertEqual(row_data[3]['rhel_version'], '7.5')
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.second_title)
        self.assertEqual(row_data[4]['rhel_version'], '7.5')
        self.assertEqual(row_data[5]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[5]['title'], constants.active_title)
        self.assertEqual(row_data[5]['rhel_version'], '7.5')
        self.assertEqual(len(row_data), 6, row_data[6:])
        self.assertTrue(all(['group_name' not in row for row in row_data]))

        # Check that the solution URL is generated correctly - if the rule has
        # a node ID, then it should be a URL, and if not then the URL should
        # be blank.
        self.assertEqual(row_data[0]['solution_url'], 'https://access.redhat.com/node/1048576')
        self.assertEqual(row_data[2]['solution_url'], '')

        # Test that requesting the CSV and JSON files by format extension
        # gets a download with the correct content disposition
        datestr = date.today().strftime('%Y-%m-%d')
        response = self.client.get(
            reverse('export-hits-list', kwargs={'format': 'csv'}), **auth_header_for_testing()
        )
        self.assertEqual(
            response.get('Content-Disposition'),
            f'attachment; filename="hits-{datestr}.csv"'
        )
        self.assertEqual(response.headers['Content-Type'], 'text/csv')
        response = self.client.get(
            reverse('export-hits-list', kwargs={'format': 'json'}), **auth_header_for_testing()
        )
        self.assertEqual(
            response.get('Content-Disposition'),
            f'attachment; filename="hits-{datestr}.json"'
        )
        self.assertEqual(response.headers['Content-Type'], constants.json_mime)

        # Requests without format should get export/hits/ - accept header
        # should then determine content type.
        response = self.client.get(
            reverse('export-hits-list'), HTTP_ACCEPT='text/csv',
            **auth_header_for_testing()
        )
        self.assertEqual(response.accepted_media_type, 'text/csv')
        response = self.client.get(
            reverse('export-hits-list'), HTTP_ACCEPT=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.headers['Content-Type'], constants.json_mime)

    def test_host_and_rule_export_filters(self):
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'

        # Testing incident=true
        # No rules are tagged as incidents so it doesn't match any rules, hence no systems
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'true'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)

        # Testing incident=false
        # With no incident rules the active and second rule are matched, and therefore all their systems
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'false'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[2]['title'], constants.second_title)

        # Tag the active_rule as an incident and re-run the incident tests
        active_rule = Rule.objects.get(rule_id=constants.active_rule)
        incident_tag = Tag.objects.get(name='incident')
        # (Incidental test for code coverage - check tag stringification
        self.assertEqual(str(incident_tag), "incident")
        active_rule.tags.add(incident_tag)
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'true'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'false'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['title'], constants.second_title)

        # Testing has_playbook=true
        # Matches active rule, and therefore its 4 systems
        response = self.client.get(reverse('export-hits-list'), data={'has_playbook': 'true'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['title'], constants.active_title)

        # Testing has_playbook=false
        # Matches second rule, and therefore its 2 systems
        response = self.client.get(reverse('export-hits-list'), data={'has_playbook': 'false'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['title'], constants.second_title)

        # Testing requires_reboot=true
        # Doesn't match any of the active rules, so no systems
        response = self.client.get(reverse('export-hits-list'), data={'reboot': 'true'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)

        # Testing requires_reboot=true
        # Matches active and second rule, and therefore all their systems
        response = self.client.get(reverse('export-hits-list'), data={'reboot': 'false'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[2]['title'], constants.second_title)

        # Testing update_method=dnfyum
        # Matches systems01, 03, 04, and stale-warn
        response = self.client.get(reverse('export-hits-list'), data={'update_method': 'dnfyum'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 6)

        # Test category filter
        # category 4 matches rules 5 & 6.
        # systems01, 03 and 04 have hits for rule 5 (second rule), but system01 is host-acked for rule 5
        response = self.client.get(reverse('export-hits-list'), data={'category': 4}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['title'], constants.second_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)

        # Test resolution_risk (res_risk) filter
        # All active, non-acked rules (1 & 5) have res_risk 1, so there will be 6 hits across 4 systems
        # system01 has a hit on rule 5 as well, but is host-acked for rule 5
        response = self.client.get(reverse('export-hits-list'), data={'res_risk': 1}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['title'], constants.active_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.second_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[5]['title'], constants.active_title)

        # res_risk 2 matches no rules, so no results
        response = self.client.get(reverse('export-hits-list'), data={'res_risk': 2}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)

        # Test text filter
        # Searching for text 'html' matches rule 1 for which systems 01, 03, 04 and 06 have hits
        response = self.client.get(reverse('export-hits-list'), data={'text': 'html'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['hostname'], constants.host_06_name)

        # Test total_risk filter
        # All active, non-acked rules (1 & 5) have total_risk 1, so all systems that match those rules will have hits
        # system01 has a hit on rule 5 as well, but is host-acked for rule 5
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 1}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[5]['title'], constants.active_title)
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 2}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 3}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 4}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)

        # Test total_risk + text filter together
        # All active rules (rules 1 and 5) have total_risk 1, but only rule 5 contains the text 'node_id',
        # Systems 01, 03 and 04 hits for rule 5, but system01 is host-acked
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 1, 'text': 'node_id'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['title'], constants.second_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)

        # Delete the host-ack for rule 5 on account 1234567 and re-run previous test, system01 should appear now
        response = self.client.delete(reverse('hostack-detail', kwargs={'pk': '1'}), **auth_header_for_testing())
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 1, 'text': 'node_id'}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 3)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.second_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)

        # Test likelihood filter
        # Likelihood 1 will match all active non-acked rules
        response = self.client.get(reverse('export-hits-list'), data={'likelihood': 1}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 7)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.active_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[3]['title'], constants.second_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.active_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[5]['title'], constants.second_title)
        self.assertEqual(row_data[6]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[6]['title'], constants.active_title)

        # Delete the ack for rule 3 and re-run the previous test
        # Should now get additional hit for system01 on acked rule
        response = self.client.delete(reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
                                      **auth_header_for_testing())
        response = self.client.get(reverse('export-hits-list'), data={'likelihood': 1}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 8)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.acked_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)

        # Combining likelihood 1 and category 3 should only match the acked rule, so just hit for system01
        response = self.client.get(reverse('export-hits-list'), data={'likelihood': 1, 'category': 3}, **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 1)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.acked_title)

        # Combining likelihood 1, category 3 & text 'act' should result in no matches
        response = self.client.get(reverse('export-hits-list'),
                                   data={'likelihood': 1, 'category': 3, 'text': 'act'},
                                   **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)

        # Testing total_risk=1 & res_risk=1 & impact=1 & likelihood=1 & category=1
        # Will match rule 1 and therefore system01, 03, 04 & 06
        response = self.client.get(reverse('export-hits-list'),
                                   data={'total_risk': 1, 'res_risk': 1, 'impact': 1,
                                         'likelihood': 1, 'category': 1},
                                   **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['hostname'], constants.host_06_name)

        # Testing total_risk=1 & res_risk=1 & impact=1 & likelihood=1 & category=1 & text=Kernel
        # Doesn't match any rule, so no system hits
        response = self.client.get(reverse('export-hits-list'),
                                   data={'total_risk': 1, 'res_risk': 1, 'impact': 1,
                                         'likelihood': 1, 'category': 1, 'text': 'Kernel'},
                                   **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 0)

        # system profile filtering - systems 1, 4, 5, 8, 9 and A are SAP systems
        # Remember at this point we've deleted the ack on Acked_rule.
        response = self.client.get(
            reverse('export-hits-list'),
            data={'filter[system_profile][sap_system]': True},
            **headers
        )
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 5)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.acked_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['title'], constants.active_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.second_title)
        response = self.client.get(
            reverse('export-hits-list'),
            data={'filter[system_profile][sap_system]': False},
            **headers
        )
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 3)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[2]['title'], constants.active_title)

        # testing display_name
        response = self.client.get(reverse('export-hits-list'),
                                   data={'display_name': constants.host_01_name},
                                   **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 3)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[2]['hostname'], constants.host_01_name)

        # testing host id (inventory uuid)
        response = self.client.get(reverse('export-hits-list'),
                                   data={'uuid': constants.host_03_uuid},
                                   **headers)
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['uuid'], constants.host_03_uuid)
        self.assertEqual(row_data[1]['uuid'], constants.host_03_uuid)

    def test_host_and_rule_export_cert_auth(self):
        headers = auth_header_for_testing(
            system_opts=constants.host_03_system_data,
        )
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._response_is_good(response, hits_headers)

        # Data now in list-of-dictionaries format
        self.assertEqual(row_data[0]['uuid'], constants.host_01_uuid)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['uuid'], constants.host_03_uuid)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['uuid'], constants.host_03_uuid)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(len(row_data), 3)

    def test_host_and_rule_export_filters_json(self):
        headers = auth_header_for_testing()

        # Testing incident=true
        # No rules are tagged as incidents so it doesn't match any rules, hence no systems
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'true'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)

        # Testing incident=false
        # With no incident rules the active and second rule are matched, and therefore all their systems
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'false'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[2]['title'], constants.second_title)

        # Tag the active_rule as an incident and re-run the incident tests
        active_rule = Rule.objects.get(rule_id=constants.active_rule)
        incident_tag = Tag.objects.get(name='incident')
        # (Incidental test for code coverage - check tag stringification
        self.assertEqual(str(incident_tag), "incident")
        active_rule.tags.add(incident_tag)
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'true'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        response = self.client.get(reverse('export-hits-list'), data={'incident': 'false'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['title'], constants.second_title)

        # Testing has_playbook=true
        # Matches active rule, and therefore its 4 systems
        response = self.client.get(reverse('export-hits-list'), data={'has_playbook': 'true'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['title'], constants.active_title)

        # Testing has_playbook=false
        # Matches second rule, and therefore its 2 systems
        response = self.client.get(reverse('export-hits-list'), data={'has_playbook': 'false'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['title'], constants.second_title)

        # Testing requires_reboot=true
        # Doesn't match any of the active rules, so no systems
        response = self.client.get(reverse('export-hits-list'), data={'reboot': 'true'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)

        # Testing requires_reboot=true
        # Matches active and second rule, and therefore all their systems
        response = self.client.get(reverse('export-hits-list'), data={'reboot': 'false'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[2]['title'], constants.second_title)

        # Test category filter
        # category 4 matches rules 5 & 6.
        # systems01, 03 and 04 have hits for rule 5 (second rule), but system01 is host-acked for rule 5
        response = self.client.get(reverse('export-hits-list'), data={'category': 4}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['title'], constants.second_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)

        # Test resolution_risk (res_risk) filter
        # All active, non-acked rules (1 & 5) have res_risk 1, so there will be 6 hits across 4 systems
        # system01 has a hit on rule 5 as well, but is host-acked for rule 5
        response = self.client.get(reverse('export-hits-list'), data={'res_risk': 1}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['title'], constants.active_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.second_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[5]['title'], constants.active_title)

        # res_risk 2 matches no rules, so no results
        response = self.client.get(reverse('export-hits-list'), data={'res_risk': 2}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)

        # Test text filter
        # Searching for text 'html' matches rule 1 for which systems 01, 03, 04 and 06 have hits
        response = self.client.get(reverse('export-hits-list'), data={'text': 'html'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['hostname'], constants.host_06_name)

        # Test total_risk filter
        # All active, non-acked rules (1 & 5) have total_risk 1, so all systems that match those rules will have hits
        # system01 has a hit on rule 5 as well, but is host-acked for rule 5
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 1}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 6)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[5]['title'], constants.active_title)
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 2}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 3}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 4}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)

        # Test total_risk + text filter together
        # All active rules (rules 1 and 5) have total_risk 1, but only rule 5 contains the text 'node_id',
        # Systems 01, 03 and 04 hits for rule 5, but system01 is host-acked
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 1, 'text': 'node_id'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['title'], constants.second_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)

        # Delete the host-ack for rule 5 on account 1234567 and re-run previous test, system01 should appear now
        response = self.client.delete(reverse('hostack-detail', kwargs={'pk': '1'}), **auth_header_for_testing())
        response = self.client.get(reverse('export-hits-list'), data={'total_risk': 1, 'text': 'node_id'}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 3)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.second_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)

        # Test likelihood filter
        # Likelihood 1 will match all active non-acked rules
        response = self.client.get(reverse('export-hits-list'), data={'likelihood': 1}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 7)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['title'], constants.active_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[3]['title'], constants.second_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.active_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[5]['title'], constants.second_title)
        self.assertEqual(row_data[6]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[6]['title'], constants.active_title)

        # Delete the ack for rule 3 and re-run the previous test
        # Should now get additional hit for system01 on acked rule
        response = self.client.delete(reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
                                      **auth_header_for_testing())
        response = self.client.get(reverse('export-hits-list'), data={'likelihood': 1}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 8)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.acked_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)

        # Combining likelihood 1 and category 3 should only match the acked rule, so just hit for system01
        response = self.client.get(reverse('export-hits-list'), data={'likelihood': 1, 'category': 3}, **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 1)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.acked_title)

        # Combining likelihood 1, category 3 & text 'act' should result in no matches
        response = self.client.get(reverse('export-hits-list'),
                                   data={'likelihood': 1, 'category': 3, 'text': 'act'},
                                   **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)

        # Testing total_risk=1 & res_risk=1 & impact=1 & likelihood=1 & category=1
        # Will match rule 1 and therefore system01, 03, 04 & 06
        response = self.client.get(reverse('export-hits-list'),
                                   data={'total_risk': 1, 'res_risk': 1, 'impact': 1,
                                         'likelihood': 1, 'category': 1},
                                   **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[2]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['hostname'], constants.host_06_name)

        # Testing total_risk=1 & res_risk=1 & impact=1 & likelihood=1 & category=1 & text=Kernel
        # Doesn't match any rule, so no system hits
        response = self.client.get(reverse('export-hits-list'),
                                   data={'total_risk': 1, 'res_risk': 1, 'impact': 1,
                                         'likelihood': 1, 'category': 1, 'text': 'Kernel'},
                                   **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 0)

        # system profile filtering - systems 1, 4, 5, 8, 9 and A are SAP systems
        # Remember at this point we've deleted the ack on Acked_rule.
        response = self.client.get(
            reverse('export-hits-list'),
            data={'filter[system_profile][sap_system]': True},
            **headers
        )
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 5)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[0]['title'], constants.acked_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[3]['title'], constants.active_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_04_name)
        self.assertEqual(row_data[4]['title'], constants.second_title)
        response = self.client.get(
            reverse('export-hits-list'),
            data={'filter[system_profile][sap_system]': False},
            **headers
        )
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 3)
        self.assertEqual(row_data[0]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_03_name)
        self.assertEqual(row_data[1]['title'], constants.second_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_06_name)
        self.assertEqual(row_data[2]['title'], constants.active_title)

        # test display_name
        response = self.client.get(reverse('export-hits-list'),
                                   data={'display_name': constants.host_01_name},
                                   **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 3)
        self.assertEqual(row_data[0]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[1]['hostname'], constants.host_01_name)
        self.assertEqual(row_data[2]['hostname'], constants.host_01_name)

        # test host id / inventory uuid
        response = self.client.get(reverse('export-hits-list'),
                                   data={'uuid': constants.host_03_uuid},
                                   **headers)
        row_data = self._response_is_good(response)
        self.assertEqual(len(row_data), 2)
        self.assertEqual(row_data[0]['uuid'], constants.host_03_uuid)
        self.assertEqual(row_data[1]['uuid'], constants.host_03_uuid)

    def test_reports_export(self):
        """
        Tests of Reports export - JSON only
        """
        headers = auth_header_for_testing()
        response = self.client.get(
            reverse('export-reports-list'), **headers
        )
        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        report_list = self._response_is_good(response)

        self.assertIsInstance(report_list, list)
        for report in report_list:
            for field in (
                'rule_id', 'host_id', 'reports_url', 'report_time', 'details', 'impacted_date'
            ):
                self.assertIn(field, report)
        # Just a cursory glance here to see we get the right data.
        self.assertEqual(report_list[0]['rule_id'], constants.active_rule)
        self.assertEqual(report_list[0]['host_id'], constants.host_01_uuid)
        self.assertEqual(
            report_list[0]['reports_url'],
            'https://console.redhat.com/insights/advisor/recommendations/' + constants.active_rule.replace('|', '%7C') + '/' + constants.host_01_uuid + '/'
        )
        self.assertEqual(report_list[0]['report_time'], '2018-12-04T05:10:36+00:00')
        self.assertEqual(report_list[0]['details'], {
            'active': 'bar', 'error_key': 'ACTIVE_RULE'
        })
        self.assertEqual(report_list[0]['impacted_date'], '2018-12-04T05:10:36+00:00')

    def test_rules_export(self):
        """
        Tests of Rules export - JSON only
        """
        headers = auth_header_for_testing()
        response = self.client.get(
            reverse('export-rules-list'), **headers
        )
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        rule_list = self._response_is_good(response)

        self.assertIsInstance(rule_list, list)
        for rule in rule_list:
            for field in (
                'rule_id', 'created_at', 'updated_at', 'description',
                'active', 'category', 'impact', 'likelihood', 'node_id',
                'tags', 'playbook_count', 'reboot_required', 'publish_date',
                'summary', 'generic', 'reason', 'more_info', 'rule_status',
                'impacted_systems_count', 'resolution_set', 'total_risk',
                'hosts_acked_count', 'rating', 'reports_shown'
            ):
                self.assertIn(field, rule)
        self.assertEqual(rule_list[0]['rule_id'], constants.active_rule)
        self.assertEqual(rule_list[0]['description'], constants.active_title)
        self.assertEqual(rule_list[0]['impacted_systems_count'], 4)
        self.assertEqual(rule_list[0]['reports_shown'], True)

    def test_systems_export(self):
        """
        Tests of Systems export
        """
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-systems-list'), **headers
        )
        row_data = self._response_is_good(response, systems_headers)

        # We're doing a very simple string decode of the lines, so we get
        # the numbers as strings.  This is not a problem in the export, it's
        # a problem with how simply we're decoding the data.
        self.assertEqual(row_data[0]['system_uuid'], constants.host_03_uuid)
        self.assertEqual(row_data[0]['display_name'], constants.host_03_name)
        self.assertEqual(row_data[0]['hits'], '2')
        self.assertEqual(row_data[0]['last_seen'], '2018-09-22T02:00:51Z')
        self.assertEqual(row_data[0]['critical_hits'], '0')
        self.assertEqual(row_data[0]['important_hits'], '0')
        self.assertEqual(row_data[0]['moderate_hits'], '0')
        self.assertEqual(row_data[0]['low_hits'], '2')
        self.assertEqual(row_data[0]['rhel_version'], '7.5')
        self.assertEqual(row_data[0]['group_name'], 'group_2')
        self.assertEqual(row_data[1]['system_uuid'], constants.host_04_uuid)
        self.assertEqual(row_data[1]['display_name'], constants.host_04_name)
        self.assertEqual(row_data[1]['hits'], '2')
        self.assertEqual(row_data[1]['last_seen'], '2018-12-10T23:32:13Z')
        self.assertEqual(row_data[1]['critical_hits'], '0')
        self.assertEqual(row_data[1]['important_hits'], '0')
        self.assertEqual(row_data[1]['moderate_hits'], '0')
        self.assertEqual(row_data[1]['low_hits'], '2')
        self.assertEqual(row_data[1]['rhel_version'], '7.5')
        self.assertEqual(row_data[1]['group_name'], '')
        self.assertEqual(row_data[2]['system_uuid'], constants.host_01_uuid)
        self.assertEqual(row_data[2]['display_name'], constants.host_01_name)
        self.assertEqual(row_data[2]['hits'], '1')
        self.assertEqual(row_data[2]['last_seen'], '2018-12-04T05:15:38Z')
        self.assertEqual(row_data[2]['critical_hits'], '0')
        self.assertEqual(row_data[2]['important_hits'], '0')
        self.assertEqual(row_data[2]['moderate_hits'], '0')
        self.assertEqual(row_data[2]['low_hits'], '1')
        self.assertEqual(row_data[2]['rhel_version'], '7.5')
        self.assertEqual(row_data[2]['group_name'], 'group_1')
        self.assertEqual(row_data[3]['system_uuid'], constants.host_06_uuid)
        self.assertEqual(row_data[3]['display_name'], constants.host_06_name)
        self.assertEqual(row_data[3]['hits'], '1')
        self.assertEqual(row_data[3]['last_seen'], '2019-04-05T14:30:00Z')
        self.assertEqual(row_data[3]['critical_hits'], '0')
        self.assertEqual(row_data[3]['important_hits'], '0')
        self.assertEqual(row_data[3]['moderate_hits'], '0')
        self.assertEqual(row_data[3]['low_hits'], '1')
        self.assertEqual(row_data[3]['rhel_version'], '7.5')
        self.assertEqual(row_data[3]['group_name'], '')
        self.assertEqual(row_data[4]['system_uuid'], constants.host_05_uuid)
        self.assertEqual(row_data[4]['display_name'], constants.host_05_name)
        self.assertEqual(row_data[4]['hits'], '0')
        self.assertEqual(row_data[4]['last_seen'], '2018-12-10T23:32:15Z')
        self.assertEqual(row_data[4]['critical_hits'], '0')
        self.assertEqual(row_data[4]['important_hits'], '0')
        self.assertEqual(row_data[4]['moderate_hits'], '0')
        self.assertEqual(row_data[4]['low_hits'], '0')
        self.assertEqual(row_data[4]['rhel_version'], '7.1')
        self.assertEqual(row_data[4]['group_name'], '')
        self.assertEqual(len(row_data), 5)
        self.assertTrue(all(['group_name' in row for row in row_data]))

        # Test that requesting the CSV and JSON files by format extension
        # gets a download with the correct content disposition
        datestr = date.today().strftime('%Y-%m-%d')
        response = self.client.get(
            reverse('export-systems-list', kwargs={'format': 'csv'}), **auth_header_for_testing()
        )
        self.assertEqual(
            response.get('Content-Disposition'),
            f'attachment; filename="systems-{datestr}.csv"'
        )
        self.assertEqual(response.accepted_media_type, 'text/csv')
        response = self.client.get(
            reverse('export-systems-list', kwargs={'format': 'json'}), **auth_header_for_testing()
        )
        self.assertEqual(
            response.get('Content-Disposition'),
            f'attachment; filename="systems-{datestr}.json"'
        )
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        row_data = self._response_is_good(response, systems_headers)
        self.assertEqual(len(row_data), 5)

        # Requests without format should get export/hits/ - accept header
        # should then determine content type.
        response = self.client.get(
            reverse('export-systems-list'), HTTP_ACCEPT='text/csv',
            **auth_header_for_testing()
        )
        self.assertEqual(response.accepted_media_type, 'text/csv')
        response = self.client.get(
            reverse('export-systems-list'), HTTP_ACCEPT=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_systems_export_filter(self):
        """
        Tests of Systems export with filter param
        """
        headers = auth_header_for_testing()
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-systems-list'), data={'rule_id': 'test|Second_rule', 'sort': 'display_name'}, **headers
        )
        row_data = self._response_is_good(response, systems_headers)
        self.assertEqual(len(row_data), 2)  # system01 is host_acked, will not generate a row
        self.assertEqual(row_data[0]['display_name'], constants.host_03_name)
        self.assertEqual(row_data[1]['display_name'], constants.host_04_name)

        response = self.client.get(
            reverse('export-systems-list'), data={'display_name': 'system', 'sort': 'display_name'}, **headers
        )
        row_data = self._response_is_good(response, systems_headers)
        self.assertEqual(len(row_data), 4)
        self.assertEqual(row_data[0]['display_name'], constants.host_01_name)
        self.assertEqual(row_data[1]['display_name'], constants.host_03_name)
        self.assertEqual(row_data[2]['display_name'], constants.host_04_name)
        self.assertEqual(row_data[3]['display_name'], constants.host_05_name)


class ExportViewHostTagsTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response, header_list=None):
        self.assertEqual(response.status_code, 200)

        # Get content, either from streaming or regular
        if hasattr(response, 'content'):
            content = response.content.decode()
        elif hasattr(response, 'streaming_content'):
            content = ''.join(s.decode() for s in response.streaming_content)
        else:
            self.Fail("Response object has no content/streaming content")

        if hasattr(response, 'accepted_media_type') and response.accepted_media_type == constants.csv_mime:
            self.assertIsNotNone(header_list, "If CSV, must have header_list= argument")
            csv_data = list(csv.reader(content.splitlines()))
            # Header should be first
            self.assertIsInstance(csv_data[0], list)
            self.assertEqual(csv_data[0], header_list)
            return [{
                header_list[index]: field
                for index, field in enumerate(row)
            } for row in csv_data[1:]]
        elif 'Content-Type' in response.headers and response.headers['Content-Type'] == constants.json_mime:
            return loads(content)
        else:
            self.Fail(f"Don't know how to decode {response} (headers {response.headers}")

    def test_host_and_rule_export(self):
        """
        Tests of host_and_rule export; no Inventory testing yet.
        """

        headers = auth_header_for_testing(account='1000000', org_id='1000000')
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-hits-list'), **headers
        )
        row_data = self._response_is_good(response, hits_headers)
        self.assertEqual(row_data[0]['hostname'], constants.host_ht_01_name)
        self.assertEqual(row_data[0]['uuid'], constants.host_ht_01_uuid)
        self.assertEqual(row_data[0]['rhel_version'], '7.10')
        self.assertEqual(row_data[0]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        self.assertEqual(row_data[1]['hostname'], constants.host_ht_02_name)
        self.assertEqual(row_data[1]['uuid'], constants.host_ht_02_uuid)
        self.assertEqual(row_data[1]['rhel_version'], '7.2')
        self.assertEqual(row_data[1]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[1]['title'], constants.active_title)
        self.assertEqual(row_data[2]['hostname'], constants.host_ht_02_name)
        self.assertEqual(row_data[2]['uuid'], constants.host_ht_02_uuid)
        self.assertEqual(row_data[2]['rhel_version'], '7.2')
        self.assertEqual(row_data[2]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[2]['title'], constants.second_title)
        self.assertEqual(row_data[3]['hostname'], constants.host_ht_03_name)
        self.assertEqual(row_data[3]['uuid'], constants.host_ht_03_uuid)
        self.assertEqual(row_data[3]['rhel_version'], '8.3')
        self.assertEqual(row_data[3]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[3]['title'], constants.active_title)
        self.assertEqual(row_data[4]['hostname'], constants.host_ht_03_name)
        self.assertEqual(row_data[4]['uuid'], constants.host_ht_03_uuid)
        self.assertEqual(row_data[4]['rhel_version'], '8.3')
        self.assertEqual(row_data[4]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[4]['title'], constants.second_title)
        self.assertEqual(row_data[5]['hostname'], constants.host_ht_04_name)
        self.assertEqual(row_data[5]['uuid'], constants.host_ht_04_uuid)
        self.assertEqual(row_data[5]['rhel_version'], '6.4')
        self.assertEqual(row_data[5]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[5]['title'], constants.active_title)
        self.assertEqual(row_data[6]['hostname'], constants.host_ht_04_name)
        self.assertEqual(row_data[6]['uuid'], constants.host_ht_04_uuid)
        self.assertEqual(row_data[6]['rhel_version'], '6.4')
        self.assertEqual(row_data[6]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[6]['title'], constants.second_title)
        self.assertEqual(len(row_data), 7)
        self.assertTrue(all(['group_name' not in row for row in row_data]))

        # A tag belonging to only one host:
        response = self.client.get(
            reverse('export-hits-list'),
            data={'tags': 'AWS/location=SLC'},
            **headers
        )
        row_data = self._response_is_good(response, hits_headers)

        self.assertEqual(row_data[0]['hostname'], constants.host_ht_01_name)
        self.assertEqual(row_data[0]['uuid'], constants.host_ht_01_uuid)
        self.assertEqual(row_data[0]['rhel_version'], '7.10')
        self.assertEqual(row_data[0]['last_seen'], '2019-12-17T02:00:51+00:00')
        self.assertEqual(row_data[0]['title'], constants.active_title)
        # Other rule hit is acked.
        self.assertEqual(len(row_data), 1)

    def test_systems_export(self):
        """
        Tests of Systems export
        """
        headers = auth_header_for_testing(account='1000000', org_id='1000000')
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-systems-list'), data={'sort': 'display_name'},
            **headers
        )
        row_data = self._response_is_good(response, systems_headers)

        # We're doing a very simple string decode of the lines, so we get
        # the numbers as strings.  This is not a problem in the export, it's
        # a problem with how simply we're decoding the data.
        self.assertEqual(row_data[0]['display_name'], constants.host_ht_01_name)
        self.assertEqual(row_data[0]['system_uuid'], constants.host_ht_01_uuid)
        self.assertEqual(row_data[0]['last_seen'], '2019-12-17T02:00:51Z')
        self.assertEqual(row_data[0]['hits'], '1')
        self.assertEqual(row_data[0]['critical_hits'], '0')
        self.assertEqual(row_data[0]['important_hits'], '0')
        self.assertEqual(row_data[0]['moderate_hits'], '0')
        self.assertEqual(row_data[0]['low_hits'], '1')
        self.assertEqual(row_data[0]['rhel_version'], '7.10')
        self.assertEqual(row_data[0]['group_name'], '')
        self.assertEqual(row_data[1]['display_name'], constants.host_ht_02_name)
        self.assertEqual(row_data[1]['system_uuid'], constants.host_ht_02_uuid)
        self.assertEqual(row_data[1]['last_seen'], '2019-12-17T02:00:51Z')
        self.assertEqual(row_data[1]['hits'], '2')
        self.assertEqual(row_data[1]['critical_hits'], '0')
        self.assertEqual(row_data[1]['important_hits'], '0')
        self.assertEqual(row_data[1]['moderate_hits'], '0')
        self.assertEqual(row_data[1]['low_hits'], '2')
        self.assertEqual(row_data[1]['rhel_version'], '7.2')
        self.assertEqual(row_data[1]['group_name'], '')
        self.assertEqual(row_data[2]['display_name'], constants.host_ht_03_name)
        self.assertEqual(row_data[2]['system_uuid'], constants.host_ht_03_uuid)
        self.assertEqual(row_data[2]['last_seen'], '2019-12-17T02:00:51Z')
        self.assertEqual(row_data[2]['hits'], '2')
        self.assertEqual(row_data[2]['critical_hits'], '0')
        self.assertEqual(row_data[2]['important_hits'], '0')
        self.assertEqual(row_data[2]['moderate_hits'], '0')
        self.assertEqual(row_data[2]['low_hits'], '2')
        self.assertEqual(row_data[2]['rhel_version'], '8.3')
        self.assertEqual(row_data[2]['group_name'], '')
        self.assertEqual(row_data[3]['display_name'], constants.host_ht_04_name)
        self.assertEqual(row_data[3]['system_uuid'], constants.host_ht_04_uuid)
        self.assertEqual(row_data[3]['last_seen'], '2019-12-17T02:00:51Z')
        self.assertEqual(row_data[3]['hits'], '2')
        self.assertEqual(row_data[3]['critical_hits'], '0')
        self.assertEqual(row_data[3]['important_hits'], '0')
        self.assertEqual(row_data[3]['moderate_hits'], '0')
        self.assertEqual(row_data[3]['low_hits'], '2')
        self.assertEqual(row_data[3]['rhel_version'], '6.4')
        self.assertEqual(row_data[3]['group_name'], 'group_4')
        self.assertEqual(len(row_data), 4)
        self.assertTrue(all(['group_name' in row for row in row_data]))

        # Intersection of two tags - one system
        headers = auth_header_for_testing(account='1000000', org_id='1000000')
        headers['HTTP_ACCEPT'] = 'text/csv'
        response = self.client.get(
            reverse('export-systems-list'),
            data={'sort': 'display_name', 'tags': 'customer/environment=database,customer/security=high'},
            **headers
        )
        row_data = self._response_is_good(response, systems_headers)

        self.assertEqual(row_data[0]['display_name'], constants.host_ht_03_name)
        self.assertEqual(row_data[0]['system_uuid'], constants.host_ht_03_uuid)
        self.assertEqual(row_data[0]['last_seen'], '2019-12-17T02:00:51Z')
        self.assertEqual(row_data[0]['hits'], '2')
        self.assertEqual(row_data[0]['critical_hits'], '0')
        self.assertEqual(row_data[0]['important_hits'], '0')
        self.assertEqual(row_data[0]['moderate_hits'], '0')
        self.assertEqual(row_data[0]['low_hits'], '2')
        self.assertEqual(row_data[0]['rhel_version'], '8.3')
        self.assertEqual(row_data[0]['group_name'], '')
        self.assertEqual(len(row_data), 1)
