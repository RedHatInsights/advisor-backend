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
from requests.exceptions import HTTPError

from django.test import TestCase
from rest_framework.serializers import ValidationError

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
