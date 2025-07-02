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

from django.test import TestCase, override_settings
from django.urls import reverse

from api import kessel
# from api.models import sync_kessel_with_model
from api.permissions import auth_header_for_testing
from api.tests import constants


class AckViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    default_header = auth_header_for_testing()
    other_acct_header = auth_header_for_testing(account='1020304', org_id='1020304')
    internal_user = auth_header_for_testing(user_opts={'is_internal': True})
    cert_auth_header = auth_header_for_testing(system_opts=constants.host_03_system_data)
    svc_acct_header = auth_header_for_testing(service_account=constants.service_account)

    def test_ack_list(self):
        response = self.client.get(reverse('ack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        ack_page = response.json()

        self.assertIn('meta', ack_page)
        self.assertIsInstance(ack_page['meta'], dict)
        self.assertIn('links', ack_page)
        self.assertIsInstance(ack_page['links'], dict)
        self.assertIn('data', ack_page)
        self.assertIsInstance(ack_page['data'], list)
        ack_list = ack_page['data']

        self.assertEqual(len(ack_list), 1)
        # We should see the rule we expect to see,
        self.assertIn('rule', ack_list[0])
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], 'Account 1234567 acks test|Acked_rule')
        self.assertEqual(ack_list[0]['created_by'], 'test_data')

    def test_ack_list_other_account(self):
        response = self.client.get(reverse('ack-list'), **self.other_acct_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']

        # But there are no acks for this account
        self.assertEqual(ack_list, [])

    def test_ack_list_all(self):
        # Normal users get permission denied
        response = self.client.get(reverse('ack-all'), **self.default_header)
        self.assertEqual(response.status_code, 403)

        # Internal users see all acks
        response = self.client.get(reverse('ack-all'), **self.internal_user)
        self.assertEqual(response.status_code, 200)
        acks_list = response.json()
        self.assertIsInstance(acks_list, list)
        self.assertIsInstance(acks_list[0], dict)
        self.assertEqual(acks_list[0]['account'], constants.standard_acct)
        self.assertEqual(acks_list[0]['org_id'], constants.standard_org)
        self.assertEqual(acks_list[0]['rule'], constants.acked_rule)
        self.assertEqual(acks_list[1]['account'], constants.alternate_acct)
        self.assertEqual(acks_list[1]['org_id'], constants.alternate_org)
        self.assertEqual(acks_list[1]['rule'], constants.acked_rule)
        self.assertEqual(acks_list[2]['account'], constants.alternate_acct)
        self.assertEqual(acks_list[2]['org_id'], constants.alternate_org)
        self.assertEqual(acks_list[2]['rule'], constants.second_rule)
        self.assertEqual(len(acks_list), 3)

    def test_ack_add(self):
        # Post with an existing acked rule should return that ack
        response = self.client.post(
            reverse('ack-list'), data={'rule_id': constants.acked_rule},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-acked rule should return a new ack
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.active_rule, 'justification': 'Living on the edge'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the ack in the list for this account
        response = self.client.get(reverse('ack-list'), **self.default_header)
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

        # Create with a very long username and justification
        long_justification = 'really ' * 25 + 'long justification'
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.second_rule, 'justification': long_justification},
            **auth_header_for_testing(username='user_name_longer_than_thirty_two_characters')
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        response = self.client.get(reverse('ack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        ack_list = response.json()['data']
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], '')  # Justification overwritten
        self.assertEqual(ack_list[0]['created_by'], 'testing')  # User overwritten
        self.assertEqual(ack_list[1]['rule'], constants.active_rule)
        self.assertEqual(ack_list[1]['justification'], 'Living on the edge')
        self.assertEqual(ack_list[1]['created_by'], 'testing')
        self.assertEqual(ack_list[2]['rule'], constants.second_rule)
        self.assertEqual(ack_list[2]['justification'], long_justification)
        self.assertEqual(ack_list[2]['created_by'], 'user_name_longer_than_thirty_two_characters')

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True)
    # Our Test Zed client doesn't allow us to explicitly specify wildcards,
    # because it has no idea what these things are.  It just matches exactly.
    @kessel.add_zed_response(
        permission_checks=constants.kessel_zedrsp_allow_disable_recom_rw
    )
    def test_ack_add_kessel_enabled_full_write(self):
        # These currently don't work because we don't actually use a Kessel
        # server in tests.  Keeping them here temporarily because maybe we
        # can implement something similar?
        # sync_kessel_with_model()
        # kessel.client.grant_access_to_org(constants.standard_user_id, "advisor:*:*", [constants.standard_org])

        # Post with an existing acked rule should return that ack
        response = self.client.post(
            reverse('ack-list'), data={'rule_id': constants.acked_rule},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-acked rule should return a new ack
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.active_rule, 'justification': 'Living on the edge'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the ack in the list for this account
        response = self.client.get(reverse('ack-list'), **self.default_header)
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

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True)
    # Our Test Zed client doesn't allow us to explicitly specify wildcards,
    # because it has no idea what these things are.  It just matches exactly.
    @kessel.add_zed_response(
        permission_checks=constants.kessel_zedrsp_allow_disable_recom_ro
    )
    def test_ack_add_kessel_enabled_only_read(self):
        # We should be able to see the ack in the list for this account
        response = self.client.get(reverse('ack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], 'Account 1234567 acks test|Acked_rule')
        self.assertEqual(ack_list[0]['created_by'], 'test_data')
        self.assertEqual(len(ack_list), 1)

        # But writes should be denied
        response = self.client.post(
            reverse('ack-list'), data={'rule_id': constants.acked_rule},
            **self.default_header
        )
        self.assertEqual(response.status_code, 403)

    def test_ack_add_cert_auth(self):
        # Post with an existing acked rule should return that ack
        response = self.client.post(
            reverse('ack-list'), data={'rule_id': constants.acked_rule},
            **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-acked rule should return a new ack
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.active_rule, 'justification': 'Living on the edge'},
            **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)  # Still 200?
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the ack in the list for this account
        response = self.client.get(reverse('ack-list'), **self.cert_auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], '')  # Justification overwritten
        self.assertEqual(ack_list[0]['created_by'], 'Certified System')  # User overwritten
        self.assertEqual(ack_list[1]['rule'], constants.active_rule)
        self.assertEqual(ack_list[1]['justification'], 'Living on the edge')
        self.assertEqual(ack_list[1]['created_by'], 'Certified System')

    def test_ack_add_service_account(self):
        # Post with an existing acked rule should update justification and
        # return that ack
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.acked_rule, 'justification': 'Justified and Ancient'},
            **self.svc_acct_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Post with an as-yet-un-acked rule should return a new ack
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.active_rule, 'justification': 'Bound for muu-muu land'},
            **self.svc_acct_header
        )
        self.assertEqual(response.status_code, 200)  # Still 200?
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # And we should be able to see the ack in the list for this account,
        # with a different account.
        response = self.client.get(reverse('ack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(ack_list[0]['rule'], constants.acked_rule)
        self.assertEqual(ack_list[0]['justification'], 'Justified and Ancient')
        self.assertEqual(ack_list[0]['created_by'], constants.service_account['username'])
        self.assertEqual(ack_list[1]['rule'], constants.active_rule)
        self.assertEqual(ack_list[1]['justification'], 'Bound for muu-muu land')
        self.assertEqual(ack_list[1]['created_by'], constants.service_account['username'])

    def test_ack_add_exceptions(self):
        # POST with a non-existent rule ID should return a 400 (validation
        # error)
        response = self.client.post(
            reverse('ack-list'), data={'rule_id': 'Nonexistent_rule'},
            **self.default_header
        )
        self.assertEqual(response.status_code, 400)

        # POST with data that doesn't have a rule ID in it should return 400
        response = self.client.post(
            reverse('ack-list'), data={'foo': 'bar'}, **self.default_header
        )
        self.assertEqual(response.status_code, 400)

    def test_ack_update_justification(self):
        response = self.client.put(
            reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
            data={'justification': 'Modified justification'},
            content_type=constants.json_mime, **self.default_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        result = response.json()
        self.assertIn('justification', result)
        self.assertEqual(result['justification'], 'Modified justification')
        self.assertEqual(result['created_by'], 'testing')

    def test_ack_update_justification_cert_auth(self):
        response = self.client.put(
            reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
            data={'justification': 'Modified justification'},
            content_type=constants.json_mime, **self.cert_auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        result = response.json()
        self.assertIn('justification', result)
        self.assertEqual(result['justification'], 'Modified justification')
        self.assertEqual(result['created_by'], 'Certified System')

    def test_ack_update_justification_exceptions(self):
        # Try to set/update the justification for a rule with no ack - should fail with 404 coz no ack found
        response = self.client.put(
            reverse('ack-detail', kwargs={'rule_id': constants.second_rule}),
            data={'justification': 'Just coz'},
            content_type=constants.json_mime, **self.default_header
        )
        self.assertEqual(response.status_code, 404)

    def test_ack_delete(self):
        # Delete the ack for rule 3 on account 1234567
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
            **self.default_header
        )
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # List now shows no acks for this account
        response = self.client.get(reverse('ack-list'), **self.default_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(len(ack_list), 0)

    def test_ack_delete_cert_auth(self):
        # Delete the ack for rule 3 on account 1234567
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
            **self.cert_auth_header
        )
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # List now shows no acks for this account
        response = self.client.get(reverse('ack-list'), **self.cert_auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(len(ack_list), 0)

    def test_ack_delete_service_account(self):
        # Delete the ack for rule 3 on account 1234567
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.acked_rule}),
            **self.svc_acct_header
        )
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)
        # List now shows no acks for this account
        response = self.client.get(reverse('ack-list'), **self.svc_acct_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ack_page = response.json()
        ack_list = ack_page['data']
        self.assertEqual(len(ack_list), 0)

    def test_ack_delete_errors(self):
        # Can't delete an ack for a rule that we haven't acked.
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.second_rule}),
            **self.default_header
        )
        self.assertEqual(response.status_code, 404)
        # We can't request to delete an ack for a different account, since we
        # filter on account in looking up the ack.


class AckCountViewTestCase(TestCase):
    fixtures = ['rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data']

    ack_table = {'acked_rule': {'rule_id': constants.acked_rule, 'ack_count': 2},
                 'second_rule': {'rule_id': constants.second_rule, 'ack_count': 1},
                 'active_rule': {'rule_id': constants.active_rule, 'ack_count': 0}}

    default_header = auth_header_for_testing()
    other_acct_header = auth_header_for_testing(account='1020304', org_id='1020304')
    internal_user = auth_header_for_testing(user_opts={'is_internal': True})

    def test_ackcount_list(self):
        # Standard user gets denied
        response = self.client.get(reverse('ackcount-list'), **self.default_header)
        self.assertEqual(response.status_code, 403)
        # Get list of rule_ids with their ack counts with a valid (internal) user
        response = self.client.get(reverse('ackcount-list'), **self.internal_user)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        ackcount_list = response.json()
        self.assertIsInstance(ackcount_list, list)
        self.assertEqual(len(ackcount_list), 3)
        self.assertIn(self.ack_table['acked_rule'], ackcount_list)
        self.assertIn(self.ack_table['second_rule'], ackcount_list)
        self.assertIn(self.ack_table['active_rule'], ackcount_list)

    def test_ackcount_detail(self):
        # Get a single rule_id with its ack count for a valid user
        response = self.client.get(
            reverse('ackcount-detail', kwargs={'rule_id': constants.acked_rule}),
            **self.internal_user
        )
        self.assertEqual(response.status_code, 200)
        ackcount = response.json()
        self.assertIsInstance(ackcount, dict)
        self.assertEqual(self.ack_table['acked_rule'], ackcount)

    def test_add_deleting_acks_to_modify_ack_counts(self):
        # Add a new ack on test|Acked_rule and expect its ack_count to now = 3
        self.ack_table['acked_rule']['ack_count'] = 3
        response = self.client.post(
            reverse('ack-list'),
            data={'rule_id': constants.acked_rule, 'justification': 'This is fine'},
            **self.other_acct_header
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse('ackcount-list'), **self.internal_user)
        self.assertEqual(response.status_code, 200)
        ackcount_list = response.json()
        self.assertIn(self.ack_table['acked_rule'], ackcount_list)

        # Delete ack from test|Second_rule and expect its ack_count to now = 0
        self.ack_table['second_rule']['ack_count'] = 0
        response = self.client.delete(
            reverse('ack-detail', kwargs={'rule_id': constants.second_rule}),
            **auth_header_for_testing(account='1122334', org_id='9988776')
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get(reverse('ackcount-list'), **self.internal_user)
        self.assertEqual(response.status_code, 200)
        ackcount_list = response.json()
        self.assertIn(self.ack_table['second_rule'], ackcount_list)

    def test_ackcount_detail_invalid_rule_id(self):
        # Get a 404 for an inactive rule
        response = self.client.get(
            reverse('ackcount-detail', kwargs={'rule_id': constants.inactive_rule}),
            **self.internal_user
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'No Rule matches the given query.'})

        # Get a 404 for a non-existent rule_id
        response = self.client.get(
            reverse('ackcount-detail', kwargs={'rule_id': 'Nonexistent_rule'}),
            **self.internal_user
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'No Rule matches the given query.'})

    def test_ackcount_endpoint_access_fails_for_non_internal_user(self):
        # Get a 403 for a non-internal user attempting to get the ack count list
        response = self.client.get(reverse('ackcount-list'), **self.default_header)
        self.assertEqual(response.status_code, 403)

        # Get a 403 for a non-internal user attempting to get the ack count for a particular rule_id
        response = self.client.get(reverse('ackcount-detail', kwargs={'rule_id': constants.acked_rule}),
                                   **self.default_header)
        self.assertEqual(response.status_code, 403)
