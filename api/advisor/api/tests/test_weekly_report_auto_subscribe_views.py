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
from api.permissions import auth_header_for_testing
from api.wrs_utils import update_wrs

test_user_identity_header = auth_header_for_testing(username="test-user")
test_user2_identity_header = auth_header_for_testing(username="test-user2")
auto_subscribed = {"is_auto_subscribed": True}
not_auto_subscribed = {"is_auto_subscribed": False}
test_middleware_url = "https://middleware.svc/"
TEST_RBAC_URL = "http://rbac.svc/"


class WeeklyReportAutoSubscribeTestCase(TestCase):
    fixtures = [
        "rule_categories",
        "rulesets",
        "system_types",
        "upload_sources",
        "basic_test_data",
        "autosub_exclusion_account_list.json",
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
        self.assertEqual(
            mail.outbox[0]["subject"],
            "Subscription Confirmation - Insights Advisor Weekly Report",
        )
        self.assertEqual(mail.outbox[0]["recipients"], [username])
        body = mail.outbox[0]["body"]
        self.assertIn(
            'You have successfully subscribed to the <span style="font-weight: bold;">Insights Advisor Weekly Report</span>.',
            body,
        )
        # Clear the outbox for more tests
        mail.outbox = []

    def _check_no_subscription_confirmation_sent(self):
        """
        At other times, we want to make sure that no (extra) email was sent.
        """
        self.assertEqual(len(mail.outbox), 0)

    @responses.activate
    def test_rbac_enabled_and_user_denied(self):
        # Test that if the user is denied access to weekly emails by RBAC
        # then they get denied both listing and updating
        responses.add(
            responses.GET,
            TEST_RBAC_URL,
            json={"data": [{"permission": "advisor:recommendation-results:*"}]},
            status=200,
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            # Check test-user subscription status - expected is auto_subscribed
            response = self.client.get(
                reverse("weeklyreportautosubscribe-list"), **test_user_identity_header
            )
            self.assertEqual(response.status_code, 403)
            self._check_no_subscription_confirmation_sent()
            response = self.client.post(
                reverse("weeklyreportautosubscribe-list"),
                data=not_auto_subscribed,
                **test_user_identity_header
            )
            self.assertEqual(response.status_code, 403)
            self._check_no_subscription_confirmation_sent()

            # Test utils functions directly...
            self.assertIsNone(update_wrs("test-user", "1234567", False, "9876543"))
            self._check_no_subscription_confirmation_sent()

    def test_missing_post_request_parameter(self):
        # Post request with no parameters - expected behaviour is this in the response data:
        #   {"org_id": ["This field is required."]}
        with self.settings(ENABLE_AUTOSUB=True):
            response = self.client.post(
                reverse("weeklyreportautosubscribe-list"), **test_user_identity_header
            )
            self.assertEqual(str(response.data["org_id"][0]), "This field is required.")

    def test_missing_headers(self):
        # Missing username in header
        response = self.client.post(
            reverse("weeklyreportautosubscribe-list"),
            **auth_header_for_testing(username=None)
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn(
            "Red Hat RBAC has denied you permission", response.content.decode()
        )

        # Missing identity header altogether
        response = self.client.post(reverse("weeklyreportautosubscribe-list"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(), {"detail": "Authentication credentials were not provided."}
        )

    def test_auto_subscribe_env_var_disabled(self):
        # Post request with no parameters - expected behaviour is this in the response data:
        #   {"message": "Auto-subscription is not enabled on this enviroment"}
        # since the endpoint isn't enabled
        with self.settings(ENABLE_AUTOSUB=False):
            expected_msg = {
                "message": "Auto-subscription is not enabled on this enviroment"
            }
            response = self.client.post(
                reverse("weeklyreportautosubscribe-list"), **test_user_identity_header
            )
            self.assertEqual(response.data, expected_msg)

    def test_autosub_exclusion_account(self):
        # Post request with is_auto_subscribe parameters using org_id = 16658728
        # this org_id number was grab from the initial fixture of autosub_exclusion_account_list
        with self.settings(ENABLE_AUTOSUB=True):
            user_identity = auth_header_for_testing(username="test-user", org_id=16658728)
            response = self.client.post(
                reverse("weeklyreportautosubscribe-list"),
                data=auto_subscribed,
                **user_identity
            )
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response.data['message'], "Auto-subscription is excluded for this Org Id")

    def test_autosub_crud(self):
        # Test data
        org_id = "999999999"
        user_identity = auth_header_for_testing(username="autosub-user", org_id=org_id)
        create_data = {'org_id': org_id, 'is_auto_subscribed': True}
        delete_data = {'org_id': org_id, 'is_auto_subscribed': False}

        # Create an autosub
        # Check that it exists
        with self.settings(ENABLE_AUTOSUB=True):
            # Create the autosub
            response = self.client.post(
                reverse("weeklyreportautosubscribe-list"),
                data=create_data,
                **user_identity
            )

            # Validate response
            self.assertEqual(response.status_code, 200)
            autosub_json = response.json()
            self.assertEqual(create_data, autosub_json)

            # Check list endpoint for valid creation
            response = self.client.get(
                reverse("weeklyreportautosubscribe-list"), **user_identity
            )

            self.assertEqual(response.status_code, 200)
            autosub_json = response.json()
            self.assertEqual([create_data], autosub_json)

        # Update an autosub to false
        # This will delete the entry
        with self.settings(ENABLE_AUTOSUB=True):
            # Update the autosub to false (delete)
            response = self.client.post(
                reverse("weeklyreportautosubscribe-list"),
                data=delete_data,
                **user_identity
            )

            # Validate response
            self.assertEqual(response.status_code, 200)
            autosub_json = response.json()
            self.assertEqual(delete_data, autosub_json)

            # Check list endpoint for valid deletion
            response = self.client.get(
                reverse("weeklyreportautosubscribe-list"), **user_identity
            )

            self.assertEqual(response.status_code, 200)
            autosub_json = response.json()
            self.assertEqual([delete_data], autosub_json)
