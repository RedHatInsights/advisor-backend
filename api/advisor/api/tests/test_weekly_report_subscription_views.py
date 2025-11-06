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

import responses

from django.core import mail
from django.test import TestCase
from django.urls import reverse

from api.tests import constants
from api.tests.test_weekly_report_command import count_posted_emails
from api.permissions import auth_header_for_testing, make_rbac_url
from api.wrs_utils import update_wrs

test_user_identity_header = auth_header_for_testing(username='test-user')
test_user2_identity_header = auth_header_for_testing(username='test-user2')
subscribed = {'is_subscribed': True}
not_subscribed = {'is_subscribed': False}
test_middleware_url = 'https://middleware.svc/'
TEST_RBAC_URL = 'http://rbac.svc/'
TEST_RBAC_V1_ACCESS = make_rbac_url(
    "access/?application=advisor,tasks,inventory&limit=1000",
    rbac_base=TEST_RBAC_URL
)


class WeeklyReportSubscriptionTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources', 'basic_test_data'
    ]

    def _response_is_good(self, response, status_code=200):
        # Good response status is 200
        self.assertEqual(response.status_code, status_code)
        # Standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Test content is decodable as JSON
        self.assertTrue(response.json, "Response cannot be decoded as json")
        return response.json()

    def _check_subscription_confirmation_sent(self, username):
        """
        When we subscribe, we expect that an email has been sent out.
        """
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0]['subject'], 'Subscription Confirmation - Red Hat Lightspeed Advisor Weekly Report')
        self.assertEqual(mail.outbox[0]['recipients'], [username])
        body = mail.outbox[0]['body']
        self.assertIn('You have successfully subscribed to the <span style="font-weight: bold;">Red Hat Lightspeed Advisor Weekly Report</span>.', body)
        # Clear the outbox for more tests
        mail.outbox = []

    def _check_no_subscription_confirmation_sent(self):
        """
        At other times, we want to make sure that no (extra) email was sent.
        """
        self.assertEqual(len(mail.outbox), 0)

    @responses.activate
    def test_create_list_remove_subscriptions(self):
        # add our fake mail sender
        responses.add_callback(
            responses.POST, test_middleware_url + '/sendEmails',
            callback=count_posted_emails, content_type=constants.json_mime,
        )

        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            # Check test-user subscription status - expected is subscribed
            response = self.client.get(reverse('weeklyreportsubscription-list'), **test_user_identity_header)
            self.assertEqual(self._response_is_good(response), subscribed)
            self._check_no_subscription_confirmation_sent()

            # Remove test-user subscription - expected not subscribed
            response = self.client.post(reverse('weeklyreportsubscription-list'),
                                        data=not_subscribed, **test_user_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # Check test-user subscription status - expected not subscribed
            response = self.client.get(reverse('weeklyreportsubscription-list'), **test_user_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # Post not_subscribed for test-user - expected still not subscribed
            response = self.client.post(reverse('weeklyreportsubscription-list'),
                                        data=not_subscribed, **test_user_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # Check test-user subscription status again - expected still not subscribed
            response = self.client.get(reverse('weeklyreportsubscription-list'), **test_user_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # Check test-user2 subscription status - expected not subscribed
            response = self.client.get(reverse('weeklyreportsubscription-list'), **test_user2_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # Post not_subscribed for test-user2 - expected not subscribed
            response = self.client.post(reverse('weeklyreportsubscription-list'),
                                        data=not_subscribed, **test_user2_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # Check test-user2 subscription status - expected still not subscribed
            response = self.client.get(reverse('weeklyreportsubscription-list'), **test_user2_identity_header)
            self.assertEqual(self._response_is_good(response), not_subscribed)
            self._check_no_subscription_confirmation_sent()

            # test-user1 and test-user2 tests
            # Add test-user and test-user2 subscriptions - expected is subscribed
            for username, identity_header in [
                ('test-user', test_user_identity_header),
                ('test-user2', test_user2_identity_header)
            ]:
                response = self.client.post(reverse('weeklyreportsubscription-list'),
                                            data=subscribed, **identity_header)
                self.assertEqual(self._response_is_good(response), subscribed)
                self._check_subscription_confirmation_sent(username)

            # Try adding test-user and test-user2 subscriptions again - expected still is subscribed
            for identity_header in [test_user_identity_header, test_user2_identity_header]:
                response = self.client.post(reverse('weeklyreportsubscription-list'),
                                            data=subscribed, **identity_header)
                self.assertEqual(self._response_is_good(response), subscribed)
                self._check_no_subscription_confirmation_sent()

            # Check test-user and test-user2 subscription statuses - expected is subscribed
            for identity_header in [test_user_identity_header, test_user2_identity_header]:
                response = self.client.get(reverse('weeklyreportsubscription-list'), **identity_header)
                self.assertEqual(self._response_is_good(response), subscribed)
                self._check_no_subscription_confirmation_sent()

            # Remove test-user and test-user2 subscriptions - expected not subscribed
            for identity_header in [test_user_identity_header, test_user2_identity_header]:
                response = self.client.post(reverse('weeklyreportsubscription-list'),
                                            data=not_subscribed, **identity_header)
                self.assertEqual(self._response_is_good(response), not_subscribed)
                self._check_no_subscription_confirmation_sent()

            # Remove test-user and test-user2 subscriptions again - expected still not subscribed
            for identity_header in [test_user_identity_header, test_user2_identity_header]:
                response = self.client.post(reverse('weeklyreportsubscription-list'),
                                            data=not_subscribed, **identity_header)
                self.assertEqual(self._response_is_good(response), not_subscribed)
                self._check_no_subscription_confirmation_sent()

            # Check test-user and test-user2 subscription statuses - expected not subscribed
            for identity_header in [test_user_identity_header, test_user2_identity_header]:
                response = self.client.post(reverse('weeklyreportsubscription-list'), **identity_header)
                self.assertEqual(self._response_is_good(response), not_subscribed)
                self._check_no_subscription_confirmation_sent()

    @responses.activate
    def test_rbac_enabled_and_user_denied(self):
        # Test that if the user is denied access to weekly emails by RBAC
        # then they get denied both listing and updating
        responses.get(
            TEST_RBAC_V1_ACCESS,
            json={'data': [{'permission': 'advisor:recommendation-results:*'}]},
            status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            # Check test-user subscription status - expected is subscribed
            response = self.client.get(
                reverse('weeklyreportsubscription-list'), **test_user_identity_header
            )
            self.assertEqual(response.status_code, 403)
            self._check_no_subscription_confirmation_sent()
            response = self.client.post(
                reverse('weeklyreportsubscription-list'),
                data=not_subscribed, **test_user_identity_header
            )
            self.assertEqual(response.status_code, 403)
            self._check_no_subscription_confirmation_sent()

            # Test utils functions directly...
            self.assertIsNone(update_wrs('test-user', '1234567', False, '9876543'))
            self._check_no_subscription_confirmation_sent()

    @responses.activate
    def test_middleware_failure_on_send_email(self):
        # add our fake mail sender
        responses.add(
            responses.POST, test_middleware_url + '/sendEmails',
            status=403
        )
        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            # Post subscribed for test-user2 - expected subscribed
            response = self.client.post(reverse('weeklyreportsubscription-list'),
                                        data=subscribed, **test_user2_identity_header)
            self.assertEqual(self._response_is_good(response), subscribed)
            # However, no email sent because of Middleware 403
            self._check_no_subscription_confirmation_sent()

    @responses.activate
    def test_same_username_in_two_accounts(self):
        # add our fake mail sender
        responses.add_callback(
            responses.POST, test_middleware_url + '/sendEmails',
            callback=count_posted_emails, content_type=constants.json_mime,
        )

        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            admin_1 = auth_header_for_testing(username='admin', account='1010101', org_id='1010101')
            admin_2 = auth_header_for_testing(username='admin', account='2020202', org_id='2020202')
            # Both should currently be unsubscribed
            for user in (admin_1, admin_2):
                response = self.client.get(
                    reverse('weeklyreportsubscription-list'),
                    **user
                )
                self.assertEqual(self._response_is_good(response), not_subscribed)
            # Subscribe one:
            response = self.client.post(
                reverse('weeklyreportsubscription-list'),
                data=subscribed,
                **admin_1
            )
            self._check_subscription_confirmation_sent('admin')
            # The other remains unsubscribed
            response = self.client.get(
                reverse('weeklyreportsubscription-list'),
                **admin_2
            )
            self.assertEqual(self._response_is_good(response), not_subscribed)

    def test_missing_post_request_parameter(self):
        # Post request with no parameters - expected behaviour is this in the response data:
        #   {"is_subscribed": ["This field is required."]}
        # However the Django.test.Client is defaulting to {'is_subscribed': False} in the request
        #   so the user is being unsubscribed.  This is unexpected behaviour for the API
        #   but just how the unittest client works for some reason.  Not sure why.
        response = self.client.post(reverse('weeklyreportsubscription-list'), **test_user_identity_header)
        self.assertEqual(response.data, not_subscribed)  # WRONG! Unexpected response
        self.assertNotEqual(response.data, {"is_subscribed": ["This field is required."]})  # WRONG! Should be equal

    def test_missing_headers(self):
        # Missing username in header
        response = self.client.post(reverse('weeklyreportsubscription-list'), **auth_header_for_testing(username=None))
        self.assertEqual(response.status_code, 403)
        self.assertIn("Red Hat RBAC has denied you permission", response.content.decode())

        # Missing identity header altogether
        response = self.client.post(reverse('weeklyreportsubscription-list'))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'detail': 'Authentication credentials were not provided.'})
