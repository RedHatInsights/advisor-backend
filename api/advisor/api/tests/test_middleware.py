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
import json
from requests.exceptions import HTTPError, Timeout

from django.test import TestCase, override_settings
from django.core.exceptions import ValidationError

from api.management.commands.weekly_report_emails import (
    MiddlewareClient, get_users_to_email, send_emails,
)
from api.utils import user_account_details
from api.tests import constants

test_middleware_url = 'https://foo.svc'


class MiddlewareTests(TestCase):
    """
    Test exception handling in Middleware (user account details and email
    sending).
    """

    def test_user_account_details_middleware_not_set(self):
        # MIDDLEWARE_HOST_URL not set
        with self.assertRaisesRegex(ValidationError, 'Middleware host URL not defined'):
            user_account_details('username')
        with self.assertRaisesRegex(ValidationError, 'Middleware host URL not defined'):
            get_users_to_email('1234567', '9876543', '2020-10-06T04:36:27Z')

    @responses.activate
    def test_user_account_details_middleware_not_200(self):
        # Response not a 200 response code
        responses.add(
            responses.POST, test_middleware_url + '/users', status=500
        )
        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            with self.assertRaisesRegex(ValidationError, 'Connection error retrieving account details'):
                user_account_details('username')
            with self.assertRaisesRegex(ValidationError, 'Connection error retrieving account details'):
                get_users_to_email('1234567', '9876543', '2010-10-06T04:36:27Z')

    @responses.activate
    def test_middleware_response_failure(self):
        # Response not a 200 response code
        responses.add(
            responses.POST, test_middleware_url + '/sendEmails', status=500
        )
        client = MiddlewareClient()
        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            # Test the actual client
            with self.assertRaisesRegex(HTTPError, '500 Server Error: Internal Server Error'):
                client.send_email('subject', 'from_email', 'recipient', 'body')
            # And the function that calls it
            success, to_email = send_emails(
                'org_id', 'account', {'reports': True},
                [{'username': 'user', 'address': 'user@example.com'}],
                'subject', 'subscription_confirmation.html', client
            )
            self.assertEqual(success, [], [])
            self.assertEqual(to_email, [{'username': 'user', 'address': 'user@example.com'}])

    @responses.activate
    @override_settings(MIDDLEWARE_HOST_URL=test_middleware_url)
    def test_middleware_send_email_includes_email_sender(self):
        # Verify that the emailSender field is included in the request
        from project_settings import settings

        def check_email_sender_field(request):
            data = json.loads(request.body)
            assert 'emailSender' in data
            assert data['emailSender'] == constants.default_from_email
            assert 'emails' in data
            return (200, {}, json.dumps({'message': 'success'}))

        responses.add_callback(
            responses.POST, test_middleware_url + '/sendEmails',
            callback=check_email_sender_field, content_type=constants.json_mime
        )
        client = MiddlewareClient()
        client.send_email('subject', settings.DEFAULT_FROM_EMAIL, 'recipient@example.com', 'body')

    @responses.activate
    def test_user_account_details_request_timeout(self):
        # Test the kwargs passed to request from retry_request from user_account_details contains a timeout value
        def check_request_timeout(request):
            req_kwargs = request.req_kwargs
            assert 'timeout' in req_kwargs
            assert req_kwargs['timeout'] == 10
            return 200, {}, '{"answer": 42}'

        responses.add_callback(
            responses.POST, test_middleware_url + '/users',
            callback=check_request_timeout, content_type=constants.json_mime
        )
        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            user_account_details('username')

    @responses.activate
    @override_settings(MIDDLEWARE_HOST_URL=test_middleware_url)
    def test_retry_request_timeout_error(self):
        # Assert that user_account_details timeouts are retried but ultimately raise a ValidationError when all retries fail
        responses.add(
            responses.POST, test_middleware_url + '/users', body=Timeout('Read timed out')
        )

        with self.assertLogs(logger='advisor-log') as logs:
            with self.assertRaisesRegex(ValidationError, 'Connection error retrieving account details'):
                user_account_details('username')

            # Assert the timeout error occurred 3 times
            assert len(responses.calls) == 3
            self.assertIn(constants.read_timeout_errmsg, logs.output[0])
            self.assertIn(constants.read_timeout_errmsg, logs.output[1])
            self.assertIn(constants.read_timeout_errmsg, logs.output[2])
            self.assertIn("ERROR:advisor-log:Request to middleware failed after 3 tries.", logs.output)

    @responses.activate
    @override_settings(MIDDLEWARE_HOST_URL=test_middleware_url)
    def test_retry_request_timeout_then_success(self):
        """
        Assert that when initial attempts time out but a later retry succeeds,
        user_account_details returns the expected data without raising ValidationError.
        """
        # First N calls time out…
        responses.add(
            responses.POST,
            test_middleware_url + '/users',
            body=Timeout('Read timed out'),
        )
        responses.add(
            responses.POST,
            test_middleware_url + '/users',
            body=Timeout('Read timed out'),
        )
        # …then a successful response with valid account details
        expected_payload = {
            'username': 'username',
            'email': 'user@example.com',
            'first_name': 'Test',
            'last_name': 'User',
        }
        responses.add(
            responses.POST,
            test_middleware_url + '/users',
            json=expected_payload,
            status=200,
        )

        with self.assertLogs(logger='advisor-log') as logs:
            result = user_account_details('username')

            # Assert that timeouts were logged (i.e., we actually retried)
            assert len(responses.calls) == 3  # 2 timeouts + 1 success
            assert len(logs.output) == 2  # 2 timeout log entries
            self.assertIn(constants.read_timeout_errmsg, logs.output[0])
            self.assertIn(constants.read_timeout_errmsg, logs.output[1])

            # Assert we stopped retrying after the successful response and returned the expected data
            self.assertEqual(result, expected_payload)
