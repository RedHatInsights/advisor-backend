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


class HostAckViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    default_header = auth_header_for_testing()
    other_acct_header = auth_header_for_testing(account='1020304', org_id='1020304')
    internal_user = auth_header_for_testing(user_opts={'is_internal': True})
    cert_auth_header = auth_header_for_testing(system_opts=constants.host_03_system_data)
    svc_acct_header = auth_header_for_testing(service_account=constants.service_account)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_hostack_list(self):
        response = self.client.get(reverse('hostack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        hostack_page = response.json()

        self.assertIn('meta', hostack_page)
        self.assertIsInstance(hostack_page['meta'], dict)
        self.assertIn('links', hostack_page)
        self.assertIsInstance(hostack_page['links'], dict)
        self.assertIn('data', hostack_page)
        self.assertIsInstance(hostack_page['data'], list)
        hostack_list = hostack_page['data']

        self.assertEqual(len(hostack_list), 1)
        # We should see the rule we expect to see,
        self.assertIn('rule', hostack_list[0])
        self.assertEqual(hostack_list[0]['rule'], constants.second_rule)
        self.assertEqual(hostack_list[0]['display_name'], constants.host_01_name)

    def test_hostack_list_filter_rule_ids(self):
        # We only have one rule acked for this account, so if we filter on
        # names other than that, we should get nothing.
        response = self.client.get(
            reverse('hostack-list'),
            data={'rule_id': 'test|Active_rule,test|Acked_rule'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(hostack_list, [])

    def test_hostack_list_filter_system_profile(self):
        # Systems 1, 4, 5, 8, 9, A are SAP systems; host ack is for rule 5
        # on system 1.  We should get one system if sap_system=true, none
        # if sap_system=false.
        response = self.client.get(
            reverse('hostack-list'),
            data={'filter[system_profile][sap_system]': True},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(len(hostack_list), 1)
        response = self.client.get(
            reverse('hostack-list'),
            data={'filter[system_profile][sap_system]': False},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(len(hostack_list), 0)

    def test_hostack_list_other_account(self):
        response = self.client.get(reverse('hostack-list'), **auth_header_for_testing(account='1020304', org_id='1020304'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']

        # But there are no hostacks for this account
        self.assertEqual(hostack_list, [])

    def test_hostack_add(self):
        # Post with an existing hostacked rule for a system should return that hostack
        response = self.client.post(reverse('hostack-list'),
                                    data={
                                        'rule': constants.second_rule,
                                        'system_uuid': constants.host_01_uuid,
                                        'justification': 'Complicated reasons'
                                    },
                                    **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-hostacked rule for a system should return a new hostack
        # Should work with a missing justification field and justification will be set to ''
        response = self.client.post(reverse('hostack-list'),
                                    data={
                                        'rule': constants.active_rule,
                                        'system_uuid': constants.host_01_uuid
                                    },
                                    **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the hostack in the list for this account
        response = self.client.get(reverse('hostack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(hostack_list[0]['rule'], constants.active_rule)
        self.assertEqual(hostack_list[0]['justification'], '')
        self.assertEqual(hostack_list[1]['rule'], constants.second_rule)
        self.assertEqual(hostack_list[1]['justification'], 'Complicated reasons')

        # Create with a very long username and justification
        long_justification = 'really ' * 25 + 'long justification'
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': constants.second_rule,
                'justification': long_justification,
                'system_uuid': constants.host_04_uuid
            },
            **auth_header_for_testing(username='user_name_longer_than_thirty_two_characters')
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        response = self.client.get(reverse('ack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse('hostack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(hostack_list[0]['rule'], constants.active_rule)
        self.assertEqual(hostack_list[0]['justification'], '')
        self.assertEqual(hostack_list[1]['rule'], constants.second_rule)
        self.assertEqual(hostack_list[1]['justification'], 'Complicated reasons')
        self.assertEqual(hostack_list[2]['rule'], constants.second_rule)
        self.assertEqual(hostack_list[2]['justification'], long_justification)
        self.assertEqual(hostack_list[2]['created_by'], 'user_name_longer_than_thirty_two_characters')

    def test_hostack_add_cert_auth(self):
        # Post with an existing hostacked rule for a system should return that hostack
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': constants.second_rule,
                'system_uuid': constants.host_01_uuid,
                'justification': 'Complicated reasons'
            },
            **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-hostacked rule for a system should return a new hostack
        # Should work with a missing justification field and justification will be set to ''
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': constants.active_rule,
                'system_uuid': constants.host_01_uuid
            },
            **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the hostack in the list for this account
        response = self.client.get(reverse('hostack-list'), **self.cert_auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(hostack_list[0]['rule'], constants.active_rule)
        self.assertEqual(hostack_list[0]['justification'], '')
        self.assertEqual(hostack_list[0]['created_by'], 'Certified System')
        self.assertEqual(hostack_list[1]['rule'], constants.second_rule)
        self.assertEqual(hostack_list[1]['justification'], 'Complicated reasons')
        self.assertEqual(hostack_list[1]['created_by'], 'Certified System')

    def test_hostack_add_service_account(self):
        # Post with an existing hostacked rule for a system should return that hostack
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': constants.second_rule,
                'system_uuid': constants.host_01_uuid,
                'justification': 'Time is eternal'
            },
            **self.svc_acct_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-hostacked rule for a system should return a new hostack
        # Should work with a missing justification field and justification will be set to ''
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': constants.active_rule,
                'system_uuid': constants.host_01_uuid,
                'justification': 'Stop, collaborate and listen'
            },
            **self.svc_acct_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the hostack in the list for this account
        response = self.client.get(reverse('hostack-list'), **self.svc_acct_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(hostack_list[0]['rule'], constants.active_rule)
        self.assertEqual(hostack_list[0]['justification'], 'Stop, collaborate and listen')
        self.assertEqual(hostack_list[0]['created_by'], constants.service_account['username'])
        self.assertEqual(hostack_list[1]['rule'], constants.second_rule)
        self.assertEqual(hostack_list[1]['justification'], 'Time is eternal')
        self.assertEqual(hostack_list[1]['created_by'], constants.service_account['username'])

    def test_hostack_add_exceptions(self):
        # POST with a non-existent rule ID should return a 400 (validation
        # error), but missing justification is OK (== '')
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': 'Nonexistent_rule',
                'system_uuid': constants.host_01_uuid
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        error_json = response.json()
        self.assertEqual(sorted(error_json.keys()), ['rule'])
        self.assertIsInstance(error_json['rule'], list)
        self.assertEqual(len(error_json['rule']), 1)
        self.assertEqual(error_json['rule'][0], "Object with rule_id=Nonexistent_rule does not exist.")

        # POST with data that doesn't have a rule ID in it should return 400
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'system_uuid': constants.host_01_uuid,
                'justification': "We just don't like rules",
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        error_json = response.json()
        self.assertEqual(sorted(error_json.keys()), ['rule'])
        self.assertIsInstance(error_json['rule'], list)
        self.assertEqual(len(error_json['rule']), 1)
        self.assertEqual(error_json['rule'][0], 'This field is required.')

        # POST with data that doesn't have a system UUID in it should return 400
        response = self.client.post(
            reverse('hostack-list'),
            data={
                'rule': constants.active_rule,
                'justification': "We just don't like rules",
            },
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)
        error_json = response.json()
        self.assertEqual(sorted(error_json.keys()), ['system_uuid'])
        self.assertIsInstance(error_json['system_uuid'], list)
        self.assertEqual(len(error_json['system_uuid']), 1)
        self.assertEqual(error_json['system_uuid'][0], 'This field is required.')

    def test_hostack_edit_justification(self):
        response = self.client.put(
            reverse('hostack-detail', kwargs={'pk': '1'}),
            data={'justification': 'This rule is dangerous'},
            content_type=constants.json_mime,
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        result = response.json()
        self.assertIn('id', result)
        self.assertEqual(result['id'], 1)
        self.assertIn('justification', result)
        self.assertEqual(result['justification'], 'This rule is dangerous')

        # Missing justification field
        response = self.client.put(
            reverse('hostack-detail', kwargs={'pk': '1'}),
            data={},
            content_type=constants.json_mime,
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result['justification'], '')
        # Edits don't include the created_by username

    def test_hostack_edit_justification_cert_auth(self):
        response = self.client.put(
            reverse('hostack-detail', kwargs={'pk': '1'}),
            data={'justification': 'This rule is dangerous'},
            content_type=constants.json_mime,
            **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        result = response.json()
        self.assertIn('id', result)
        self.assertEqual(result['id'], 1)
        self.assertIn('justification', result)
        self.assertEqual(result['justification'], 'This rule is dangerous')

        # Missing justification field
        response = self.client.put(
            reverse('hostack-detail', kwargs={'pk': '1'}),
            data={},
            content_type=constants.json_mime,
            **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result['justification'], '')
        # Edits don't include the created_by username

    def test_hostack_update_justification_exceptions(self):
        # Try to set/update the justification for a rule with no hostack should fail with 404
        response = self.client.put(reverse('hostack-detail', kwargs={'pk': '-1'}),
                                   content_type=constants.json_mime, **self.default_header)
        self.assertEqual(response.status_code, 404)

    def test_hostack_delete(self):
        # Delete the hostack for rule 5 on account 1234567
        response = self.client.delete(
            reverse('hostack-detail', kwargs={'pk': '1'}), **self.default_header
        )
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # List now shows no hostacks for this account
        response = self.client.get(reverse('hostack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(len(hostack_list), 0)

    def test_hostack_delete_cert_auth(self):
        # Delete the hostack for rule 5 on account 1234567
        response = self.client.delete(
            reverse('hostack-detail', kwargs={'pk': '1'}), **self.cert_auth_header
        )
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # List now shows no hostacks for this account
        response = self.client.get(reverse('hostack-list'), **self.cert_auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(len(hostack_list), 0)

    def test_hostack_delete_service_account(self):
        # Delete the hostack for rule 5 on account 1234567
        response = self.client.delete(
            reverse('hostack-detail', kwargs={'pk': '1'}), **self.svc_acct_header
        )
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # List now shows no hostacks for this account
        response = self.client.get(reverse('hostack-list'), **self.svc_acct_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        hostack_list = hostack_page['data']
        self.assertEqual(len(hostack_list), 0)

    def test_hostack_delete_errors(self):
        # Can't delete an hostack for a rule that we haven't acked should fail with 404
        response = self.client.delete(
            reverse('hostack-detail', kwargs={'pk': '-1'}), **self.default_header
        )
        self.assertEqual(response.status_code, 404)


class HostAckViewHostTagsTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_hostack_list(self):
        response = self.client.get(
            reverse('hostack-list'),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        hostack_page = response.json()
        self.assertIn('data', hostack_page)
        hostack_list = hostack_page['data']
        self.assertIsInstance(hostack_list, list)

        self.assertEqual(len(hostack_list), 1)
        # We should see the rule we expect to see
        self.assertIn('rule', hostack_list[0])
        self.assertEqual(hostack_list[0]['rule'], constants.second_rule)
        self.assertIn('display_name', hostack_list[0])
        self.assertEqual(hostack_list[0]['display_name'], constants.host_ht_01_name)

        # Likewise that host should turn up if we filter on a tag that includes
        # that system:
        response = self.client.get(
            reverse('hostack-list'),
            data={'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        self.assertIn('data', hostack_page)
        hostack_list = hostack_page['data']
        self.assertIsInstance(hostack_list, list)
        self.assertEqual(len(hostack_list), 1)
        self.assertIn('rule', hostack_list[0])
        self.assertEqual(hostack_list[0]['rule'], constants.second_rule)
        self.assertIn('display_name', hostack_list[0])
        self.assertEqual(hostack_list[0]['display_name'], constants.host_ht_01_name)

        # But if we filter on a tag that does not include that system, then
        # we see no acks
        response = self.client.get(
            reverse('hostack-list'),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        hostack_page = response.json()
        self.assertIn('data', hostack_page)
        hostack_list = hostack_page['data']
        self.assertIsInstance(hostack_list, list)
        self.assertEqual(len(hostack_list), 0)
