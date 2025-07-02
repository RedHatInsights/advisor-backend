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


class SatAcksTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_ack_list(self):
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {
                'id': 1,
                'rule_id': constants.acked_rule,
                'account_number': '1234567',
                'org_id': '9876543',
            }
        ])

        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_uc, 'include': 'rule'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertIn('id', json_data[0])
        self.assertEqual(json_data[0]['id'], 1)
        self.assertIn('rule_id', json_data[0])
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertIn('account_number', json_data[0])
        self.assertIn('org_id', json_data[0])
        self.assertEqual(json_data[0]['account_number'], '1234567')
        self.assertEqual(json_data[0]['org_id'], '9876543')
        self.assertIn('rule', json_data[0])
        self.assertIsInstance(json_data[0]['rule'], dict)
        self.maxDiff = None
        self.assertEqual(json_data[0]['rule'], {
            'summary_html': '<p>Acked rule</p>',
            'description_html': '<p>Acked rule</p>',
            'generic_html': '<p>Acked rule</p>',
            'more_info_html': '',
            'severity': 'INFO',
            'rule_id': constants.acked_rule,
            'error_key': 'Acked_rule',
            'plugin': 'test',
            'description': constants.acked_title,
            'summary': constants.acked_title,
            'generic': constants.acked_title,
            'reason': 'Acked rule content with {{=pydata.acked}} DoT information',
            # We don't emit type here
            'more_info': '',
            'active': True,
            'node_id': '1048578',
            'category': 'Stability',
            'retired': False,
            'reboot_required': True,
            'publish_date': '2018-05-23T15:38:55Z',
            'rec_impact': 1,
            'rec_likelihood': 1
        })
        self.assertEqual(len(json_data), 1)

        # List with branch ID we don't have (yet) shows acks anyway.
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': '19191919-1919-1919-1919-191919191919'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {
                'id': 1,
                'rule_id': constants.acked_rule,
                'account_number': '1234567',
                'org_id': '9876543',
            }
        ])

        # List with branch ID we have an ack for lists that ack
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {
                'id': 1,
                'rule_id': constants.acked_rule,
                'account_number': '1234567',
                'org_id': '9876543',
            }
        ])

        # Requesting a list of acks with no branch should show us a list of acks too.
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {
                'id': 1,
                'rule_id': constants.acked_rule,
                'account_number': '1234567',
                'org_id': '9876543',
            }
        ])

    def test_ack_list_cert_auth(self):
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data, [
            {
                'id': 1,
                'rule_id': constants.acked_rule,
                'account_number': '1234567',
                'org_id': '9876543',
            }
        ])

    def test_advisor_ack_no_satellite(self):
        # Test that while we've got an ack with a branch ID loaded, it
        # *doesn't* appear in the main API views.
        response = self.client.get(reverse('ack-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], 'Account 1234567 acks test|Acked_rule')
        self.assertEqual(ack_list[0]['created_by'], 'test_data')
        self.assertEqual(len(ack_list), 1)

        # Post with an existing acked rule should return that ack
        response = self.client.post(reverse('ack-list'), data={'rule_id': constants.acked_rule}, **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-acked rule should return a new ack
        response = self.client.post(reverse('ack-list'), data={'rule_id': constants.active_rule,
                                                               'justification': 'Living on the edge'},
                                    **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the ack in the list for this account
        response = self.client.get(reverse('ack-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], '')  # Justification overwritten
        self.assertEqual(ack_list[0]['created_by'], 'testing')  # User overwritten
        self.assertEqual(ack_list[1]['rule'], constants.active_rule)
        self.assertEqual(ack_list[1]['justification'], 'Living on the edge')
        self.assertEqual(ack_list[1]['created_by'], 'testing')
        self.assertEqual(len(ack_list), 2)

        # Delete the original ack just for fun
        response = self.client.delete(reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}), **auth_header_for_testing())
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # And now we should only see the new ack
        response = self.client.get(reverse('ack-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(ack_list[0]['rule'], constants.active_rule)
        self.assertEqual(ack_list[0]['justification'], 'Living on the edge')
        self.assertEqual(ack_list[0]['created_by'], 'testing')
        self.assertEqual(len(ack_list), 1)

    def test_create_destroy(self):
        # Create acks by rule ID
        response = self.client.post(
            reverse('sat-compat-acks-list'),
            data={
                'rule_id': constants.active_rule,
            },
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 201, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        new_ack = response.json()
        # We get the ack back to check its Id
        self.assertIsInstance(new_ack, dict)
        self.assertIn('id', new_ack)
        self.assertIn('rule_id', new_ack)
        self.assertEqual(new_ack['rule_id'], constants.active_rule)
        self.assertIn('account_number', new_ack)
        self.assertIn('org_id', new_ack)
        self.assertEqual(new_ack['account_number'], '1234567')
        self.assertEqual(new_ack['org_id'], '9876543')
        new_ack_id = new_ack['id']

        # List now contains these two acks.
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data[0]['id'], 1)
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertEqual(json_data[1]['id'], new_ack_id)
        self.assertEqual(json_data[1]['rule_id'], constants.active_rule)
        self.assertEqual(len(json_data), 2)

        correct_branch_param = '?branch_id=aabbccdd-eeff-ffee-ddcc-001122334455'
        # Other account cannot delete this ack by ID, even with the branch ID
        response = self.client.delete(
            reverse('sat-compat-acks-detail', kwargs={'pk': new_ack_id}) + correct_branch_param,
            **auth_header_for_testing('9988776'),
        )
        self.assertEqual(response.status_code, 404, response.content.decode())

        # Destroy it by ack Id...
        response = self.client.delete(
            reverse('sat-compat-acks-detail', kwargs={'pk': new_ack_id}) + correct_branch_param,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 204, response.content.decode())

        # And it's gone...
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data[0]['id'], 1)
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertEqual(len(json_data), 1)

    def test_create_destroy_cert_auth(self):
        # Create acks by rule ID
        response = self.client.post(
            reverse('sat-compat-acks-list'),
            data={
                'rule_id': constants.active_rule,
                'branch_id': constants.remote_branch_lc
            },
            **auth_header_for_testing(system_opts=constants.host_03_system_data),
        )
        self.assertEqual(response.status_code, 201, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        new_ack = response.json()
        # We get the ack back to check its Id
        self.assertIsInstance(new_ack, dict)
        self.assertIn('id', new_ack)
        self.assertIn('rule_id', new_ack)
        self.assertEqual(new_ack['rule_id'], constants.active_rule)
        self.assertIn('account_number', new_ack)
        self.assertIn('org_id', new_ack)
        self.assertEqual(new_ack['account_number'], '1234567')
        self.assertEqual(new_ack['org_id'], '9876543')
        new_ack_id = new_ack['id']

        # List now contains these two acks.
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data[0]['id'], 1)
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertEqual(json_data[1]['id'], new_ack_id)
        self.assertEqual(json_data[1]['rule_id'], constants.active_rule)
        self.assertEqual(len(json_data), 2)

        correct_branch_param = '?branch_id=aabbccdd-eeff-ffee-ddcc-001122334455'
        # Other account cannot delete this ack by ID, even with the branch ID
        response = self.client.delete(
            reverse('sat-compat-acks-detail', kwargs={'pk': new_ack_id}) + correct_branch_param,
            **auth_header_for_testing('9988776'),
        )
        self.assertEqual(response.status_code, 404, response.content.decode())

        # Destroy it by ack Id...
        response = self.client.delete(
            reverse('sat-compat-acks-detail', kwargs={'pk': new_ack_id}) + correct_branch_param,
            **auth_header_for_testing(system_opts=constants.host_03_system_data),
        )
        self.assertEqual(response.status_code, 204, response.content.decode())

        # And it's gone...
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data[0]['id'], 1)
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertEqual(len(json_data), 1)

    def test_create_destroy_with_branch_id_param(self):
        correct_branch_param = '?branch_id=19191919-1919-1919-1919-191919191919'
        # Create acks by rule ID
        response = self.client.post(
            # Special construction because post method doesn't separate
            # post data from query data.
            reverse('sat-compat-acks-list') + correct_branch_param,
            data={
                'rule_id': constants.active_rule,
            },
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 201, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        new_ack = response.json()
        # We get the ack back to check its Id
        self.assertIsInstance(new_ack, dict)
        self.assertIn('id', new_ack)
        self.assertIn('rule_id', new_ack)
        self.assertEqual(new_ack['rule_id'], constants.active_rule)
        self.assertIn('account_number', new_ack)
        self.assertIn('org_id', new_ack)
        self.assertEqual(new_ack['account_number'], '1234567')
        self.assertEqual(new_ack['org_id'], '9876543')
        new_ack_id = new_ack['id']

        # Branch ID ignored.
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': '19191919-1919-1919-1919-191919191919'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data[0]['id'], 1)
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertEqual(json_data[1]['id'], new_ack_id)
        self.assertEqual(json_data[1]['rule_id'], constants.active_rule)
        self.assertEqual(len(json_data), 2)

        # Destroy it by ack Id...
        response = self.client.delete(
            reverse('sat-compat-acks-detail', kwargs={'pk': new_ack_id}) + correct_branch_param,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 204, response.content.decode())

        # And it's gone...
        response = self.client.get(
            reverse('sat-compat-acks-list'),
            data={'branch_id': '19191919-1919-1919-1919-191919191919'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(json_data[0]['id'], 1)
        self.assertEqual(json_data[0]['rule_id'], constants.acked_rule)
        self.assertEqual(len(json_data), 1)
