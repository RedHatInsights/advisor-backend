# Copyright 2016-2026 the Advisor Backend team at Red Hat.
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

from unittest.mock import patch, MagicMock

import responses

from django.test import TestCase, override_settings

from api.rbac_oidc_token import get_rbac_oidc_access_token, clear_credentials
from api.permissions import (
    make_rbac_request, make_rbac_url,
    request_object_for_testing, RHIdentityAuthentication,
    _add_username_query_param,
)
from api.tests import constants

TEST_OIDC_ISSUER = 'https://sso.example.com/auth/realms/test'
TEST_TOKEN_URL = 'https://sso.example.com/auth/realms/test/protocol/openid-connect/token'
TEST_RBAC_URL = 'http://rbac.svc/'
TEST_RBAC_V1_ACCESS = make_rbac_url(
    "access/?application=advisor,tasks,inventory&limit=1000",
    rbac_base=TEST_RBAC_URL
)

OIDC_SETTINGS = {
    'RBAC_OIDC_ENABLED': True,
    'KESSEL_AUTH_OIDC_ISSUER': TEST_OIDC_ISSUER,
    'KESSEL_AUTH_CLIENT_ID': 'test-client-id',
    'KESSEL_AUTH_CLIENT_SECRET': 'test-client-secret',
    'RBAC_URL': TEST_RBAC_URL,
    'RBAC_ENABLED': True,
    'RBAC_PSK': None,
}


def _mock_token_response(access_token='test-jwt-token'):
    """Create a mock RefreshTokenResponse from the kessel SDK."""
    mock_response = MagicMock()
    mock_response.access_token = access_token
    return mock_response


def _mock_discovery():
    """Create a mock OIDCDiscoveryMetadata."""
    mock_disc = MagicMock()
    mock_disc.token_endpoint = TEST_TOKEN_URL
    return mock_disc


class OidcTokenTestCase(TestCase):
    """Tests for the OIDC token acquisition via kessel SDK."""

    def setUp(self):
        clear_credentials()

    def tearDown(self):
        clear_credentials()

    @override_settings(**OIDC_SETTINGS)
    @patch('api.rbac_oidc_token.fetch_oidc_discovery',
           return_value=_mock_discovery())
    @patch('api.rbac_oidc_token.OAuth2ClientCredentials')
    def test_get_oidc_access_token(
        self, mock_creds_class, mock_discovery
    ):
        """Token is acquired via OAuth2ClientCredentials.get_token()."""
        mock_instance = MagicMock()
        mock_instance.get_token.return_value = _mock_token_response('my-jwt')
        mock_creds_class.return_value = mock_instance

        token = get_rbac_oidc_access_token()

        self.assertEqual(token, 'my-jwt')
        mock_discovery.assert_called_once_with(TEST_OIDC_ISSUER)
        mock_creds_class.assert_called_once_with(
            client_id='test-client-id',
            client_secret='test-client-secret',
            token_endpoint=TEST_TOKEN_URL,
        )
        mock_instance.get_token.assert_called_once()

    @override_settings(**OIDC_SETTINGS)
    @patch('api.rbac_oidc_token.fetch_oidc_discovery',
           return_value=_mock_discovery())
    @patch('api.rbac_oidc_token.OAuth2ClientCredentials')
    def test_credentials_created_once(
        self, mock_creds_class, mock_discovery
    ):
        """OAuth2ClientCredentials is created only once (lazy singleton)."""
        mock_instance = MagicMock()
        mock_instance.get_token.return_value = _mock_token_response('jwt-1')
        mock_creds_class.return_value = mock_instance

        get_rbac_oidc_access_token()
        get_rbac_oidc_access_token()

        # Class instantiated only once
        mock_creds_class.assert_called_once()
        # Discovery called only once
        mock_discovery.assert_called_once()
        # But get_token called twice (caching is internal to the SDK)
        self.assertEqual(mock_instance.get_token.call_count, 2)

    @override_settings(
        RBAC_OIDC_ENABLED=True,
        KESSEL_AUTH_OIDC_ISSUER='',
        KESSEL_AUTH_CLIENT_ID='test',
        KESSEL_AUTH_CLIENT_SECRET='test',
    )
    def test_missing_token_url_raises(self):
        """Error raised when token URL is not configured."""
        from requests.exceptions import MissingSchema
        with self.assertRaises(MissingSchema):
            get_rbac_oidc_access_token()

    @override_settings(
        RBAC_OIDC_ENABLED=True,
        KESSEL_AUTH_OIDC_ISSUER=TEST_TOKEN_URL,
        KESSEL_AUTH_CLIENT_ID='',
        KESSEL_AUTH_CLIENT_SECRET='test',
    )
    @patch('api.rbac_oidc_token.fetch_oidc_discovery',
           return_value=_mock_discovery())
    @patch('api.rbac_oidc_token.OAuth2ClientCredentials')
    def test_missing_client_id_passes_empty_string(
        self, mock_creds_class, mock_discovery
    ):
        """Empty client ID is passed through to OAuth2ClientCredentials."""
        mock_instance = MagicMock()
        mock_instance.get_token.return_value = _mock_token_response('jwt')
        mock_creds_class.return_value = mock_instance

        get_rbac_oidc_access_token()

        mock_creds_class.assert_called_once_with(
            client_id='',
            client_secret='test',
            token_endpoint=TEST_TOKEN_URL,
        )

    @override_settings(
        RBAC_OIDC_ENABLED=True,
        KESSEL_AUTH_OIDC_ISSUER=TEST_TOKEN_URL,
        KESSEL_AUTH_CLIENT_ID='test',
        KESSEL_AUTH_CLIENT_SECRET='',
    )
    @patch('api.rbac_oidc_token.fetch_oidc_discovery',
           return_value=_mock_discovery())
    @patch('api.rbac_oidc_token.OAuth2ClientCredentials')
    def test_missing_client_secret_passes_empty_string(
        self, mock_creds_class, mock_discovery
    ):
        """Empty client secret is passed through to OAuth2ClientCredentials."""
        mock_instance = MagicMock()
        mock_instance.get_token.return_value = _mock_token_response('jwt')
        mock_creds_class.return_value = mock_instance

        get_rbac_oidc_access_token()

        mock_creds_class.assert_called_once_with(
            client_id='test',
            client_secret='',
            token_endpoint=TEST_TOKEN_URL,
        )

    def test_clear_credentials(self):
        """clear_credentials resets the module-level instance."""
        # After clearing, the next call should create a new instance
        clear_credentials()
        from api import rbac_oidc_token
        self.assertIsNone(rbac_oidc_token._credentials)


class OidcMakeRbacRequestTestCase(TestCase):
    """Tests for the OIDC path in make_rbac_request."""

    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def setUp(self):
        clear_credentials()

    def tearDown(self):
        clear_credentials()

    @responses.activate
    @override_settings(**OIDC_SETTINGS)
    @patch('api.rbac_oidc_token.fetch_oidc_discovery',
           return_value=_mock_discovery())
    @patch('api.rbac_oidc_token.OAuth2ClientCredentials')
    def test_make_rbac_request_oidc_sends_bearer_token(
        self, mock_creds_class, mock_discovery
    ):
        """
        When RBAC_OIDC_ENABLED is True, make_rbac_request sends an
        Authorization: Bearer header and x-rh-rbac-org-id.
        """
        mock_instance = MagicMock()
        mock_instance.get_token.return_value = _mock_token_response('my-jwt')
        mock_creds_class.return_value = mock_instance

        # Mock the RBAC endpoint
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': [{'permission': 'advisor:*:*', 'resourceDefinitions': []}]},
            status=200,
            match_querystring=False,
        )

        request = request_object_for_testing(auth_by=RHIdentityAuthentication)
        rbac_url = make_rbac_url(
            "access/?application=advisor,tasks,inventory&limit=1000",
            rbac_base=TEST_RBAC_URL,
        )
        response, elapsed = make_rbac_request(rbac_url, request)

        self.assertEqual(response.status_code, 200)
        rbac_call = responses.calls[0]
        self.assertEqual(
            rbac_call.request.headers['Authorization'], 'Bearer my-jwt'
        )
        self.assertEqual(
            rbac_call.request.headers['x-rh-rbac-org-id'],
            constants.standard_org,
        )
        self.assertIn('username=', rbac_call.request.url)

    @responses.activate
    @override_settings(**OIDC_SETTINGS)
    @patch('api.rbac_oidc_token.fetch_oidc_discovery',
           return_value=_mock_discovery())
    @patch('api.rbac_oidc_token.OAuth2ClientCredentials')
    def test_make_rbac_request_oidc_caches_credentials(
        self, mock_creds_class, mock_discovery
    ):
        """
        The OAuth2ClientCredentials instance is reused across calls.
        """
        mock_instance = MagicMock()
        mock_instance.get_token.return_value = _mock_token_response('cached-jwt')
        mock_creds_class.return_value = mock_instance

        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': []},
            status=200,
            match_querystring=False,
        )
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': []},
            status=200,
            match_querystring=False,
        )

        request = request_object_for_testing(auth_by=RHIdentityAuthentication)
        rbac_url = make_rbac_url(
            "access/?application=advisor,tasks,inventory&limit=1000",
            rbac_base=TEST_RBAC_URL,
        )

        make_rbac_request(rbac_url, request)
        make_rbac_request(rbac_url, request)

        # Credentials class instantiated only once
        mock_creds_class.assert_called_once()

    @override_settings(
        RBAC_OIDC_ENABLED=True,
        KESSEL_AUTH_OIDC_ISSUER=TEST_OIDC_ISSUER,
        KESSEL_AUTH_CLIENT_ID='test-client-id',
        KESSEL_AUTH_CLIENT_SECRET='test-client-secret',
        RBAC_URL=TEST_RBAC_URL,
        RBAC_ENABLED=True,
        RBAC_PSK='fallback-psk',
        RBAC_CLIENT_ID='advisor',
    )
    @patch('api.rbac_oidc_token.fetch_oidc_discovery')
    def test_make_rbac_request_oidc_failure_raises(
        self, mock_discovery
    ):
        """
        When RBAC_OIDC_ENABLED is True but token acquisition fails,
        the exception propagates from make_rbac_request.
        """
        mock_discovery.side_effect = Exception("OIDC discovery failed")

        request = request_object_for_testing(
            auth_by=RHIdentityAuthentication
        )
        rbac_url = make_rbac_url(
            "access/?application=advisor,tasks,inventory&limit=1000",
            rbac_base=TEST_RBAC_URL,
        )
        with self.assertRaises(Exception) as ctx:
            make_rbac_request(rbac_url, request)
        self.assertIn('OIDC discovery failed', str(ctx.exception))

    @override_settings(
        RBAC_OIDC_ENABLED=True,
        KESSEL_AUTH_OIDC_ISSUER=TEST_OIDC_ISSUER,
        KESSEL_AUTH_CLIENT_ID='test-client-id',
        KESSEL_AUTH_CLIENT_SECRET='test-client-secret',
        RBAC_URL=TEST_RBAC_URL,
        RBAC_ENABLED=True,
        RBAC_PSK=None,
    )
    @patch('api.rbac_oidc_token.fetch_oidc_discovery')
    def test_make_rbac_request_oidc_failure_no_psk_raises(
        self, mock_discovery
    ):
        """
        When OIDC fails and no PSK is set, the exception propagates.
        """
        mock_discovery.side_effect = Exception("OIDC discovery failed")

        request = request_object_for_testing(
            auth_by=RHIdentityAuthentication
        )
        rbac_url = make_rbac_url(
            "access/?application=advisor,tasks,inventory&limit=1000",
            rbac_base=TEST_RBAC_URL,
        )
        with self.assertRaises(Exception) as ctx:
            make_rbac_request(rbac_url, request)
        self.assertIn('OIDC discovery failed', str(ctx.exception))

    @responses.activate
    def test_make_rbac_request_falls_back_to_psk(self):
        """
        When RBAC_OIDC_ENABLED is False and RBAC_PSK is set,
        make_rbac_request uses PSK headers.
        """
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': []},
            status=200,
            match_querystring=False,
        )

        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            RBAC_OIDC_ENABLED=False,
            RBAC_PSK='test-psk', RBAC_CLIENT_ID='advisor',
        ):
            request = request_object_for_testing(
                auth_by=RHIdentityAuthentication
            )
            rbac_url = make_rbac_url(
                "access/?application=advisor,tasks,inventory&limit=1000",
                rbac_base=TEST_RBAC_URL,
            )
            response, elapsed = make_rbac_request(rbac_url, request)

            self.assertEqual(response.status_code, 200)
            rbac_call = responses.calls[0]
            self.assertEqual(
                rbac_call.request.headers['x-rh-rbac-psk'], 'test-psk'
            )
            self.assertEqual(
                rbac_call.request.headers['x-rh-rbac-client-id'], 'advisor'
            )
            self.assertNotIn('Authorization', rbac_call.request.headers)

    @responses.activate
    def test_make_rbac_request_falls_back_to_identity_header(self):
        """
        When RBAC_OIDC_ENABLED is False and RBAC_PSK is not set,
        make_rbac_request forwards the x-rh-identity header.
        """
        responses.add(
            responses.GET, TEST_RBAC_V1_ACCESS,
            json={'data': []},
            status=200,
        )

        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            RBAC_OIDC_ENABLED=False, RBAC_PSK=None,
        ):
            request = request_object_for_testing(
                auth_by=RHIdentityAuthentication
            )
            rbac_url = make_rbac_url(
                "access/?application=advisor,tasks,inventory&limit=1000",
                rbac_base=TEST_RBAC_URL,
            )
            response, elapsed = make_rbac_request(rbac_url, request)

            self.assertEqual(response.status_code, 200)
            rbac_call = responses.calls[0]
            self.assertIn('x-rh-identity', rbac_call.request.headers)
            self.assertNotIn('Authorization', rbac_call.request.headers)
            self.assertNotIn('x-rh-rbac-psk', rbac_call.request.headers)


class AddUsernameQueryParamTestCase(TestCase):
    """Tests for the _add_username_query_param helper."""

    def test_user_identity(self):
        """Username extracted from User identity type."""
        identity = {
            'type': 'User',
            'org_id': '123',
            'user': {'username': 'testuser', 'user_id': '456'},
        }
        result = _add_username_query_param(
            'http://rbac/api/v1/access/', identity
        )
        self.assertIn('username=testuser', result)

    def test_service_account_identity(self):
        """Username extracted from ServiceAccount identity type."""
        identity = {
            'type': 'ServiceAccount',
            'org_id': '123',
            'service_account': {
                'username': 'service-account-abc',
                'client_id': 'abc',
            },
        }
        result = _add_username_query_param(
            'http://rbac/api/v1/access/', identity
        )
        self.assertIn('username=service-account-abc', result)

    def test_preserves_existing_query_params(self):
        """Existing query parameters are preserved."""
        identity = {
            'type': 'User',
            'org_id': '123',
            'user': {'username': 'testuser'},
        }
        result = _add_username_query_param(
            'http://rbac/api/v1/access/?application=advisor&limit=1000',
            identity,
        )
        self.assertIn('username=testuser', result)
        self.assertIn('application=advisor', result)
        self.assertIn('limit=1000', result)

    def test_fallback_for_unknown_identity_type(self):
        """Falls back to identity.user.username for unknown types."""
        identity = {
            'type': 'Unknown',
            'user': {'username': 'fallback-user'},
        }
        result = _add_username_query_param(
            'http://rbac/api/v1/access/', identity
        )
        self.assertIn('username=fallback-user', result)
