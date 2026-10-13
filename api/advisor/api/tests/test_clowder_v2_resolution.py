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

"""Tests for Clowder V2 dependency endpoint resolution.

Covers the _resolve_v2_endpoint helper and build_endpoint_url from
project_settings.settings, verifying V2-only resolution (no V1 fallback)
for RBAC and Sources migration, including CA certificate and
authentication flag propagation.
"""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from project_settings.settings import _resolve_v2_endpoint, build_endpoint_url


def _make_v1_endpoint(app, hostname, port, tls_port=None):
    """Create a mock V1 Clowder endpoint object."""
    return SimpleNamespace(
        app=app,
        hostname=hostname,
        port=port,
        tlsPort=tls_port or port,
    )


def _make_v2_endpoint(uri, authenticated=True, ca_certificate=None):
    """Create a mock V2 Clowder endpoint object."""
    return SimpleNamespace(
        uri=uri,
        authenticated=authenticated,
        ca_certificate=ca_certificate,
    )


class ResolveV2EndpointTests(SimpleTestCase):
    """Tests for _resolve_v2_endpoint: V2-only resolution (no V1 fallback)."""

    # --- V2 URI resolution ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_endpoint_with_uri_and_ca(self, mock_get_v2):
        """V2 endpoint present with URI and CA → returns V2 URI, V2 CA, source='v2'."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            authenticated=False,
            ca_certificate='/tmp/ca.crt',
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertEqual(result.url, 'https://rbac.clowder.svc:8443')
        self.assertEqual(result.ca_certificate, '/tmp/ca.crt')
        self.assertFalse(result.authenticated)
        self.assertEqual(result.source, 'v2')
        mock_get_v2.assert_called_once_with('rbac', 'service')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_endpoint_with_uri_no_ca(self, mock_get_v2):
        """V2 endpoint present with URI but no CA → V2 URI, ca_certificate=None (system trust)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://sources.clowder.svc:8443',
            authenticated=False,
            ca_certificate=None,
        )
        result = _resolve_v2_endpoint('sources-api', 'svc')
        self.assertEqual(result.url, 'https://sources.clowder.svc:8443')
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'v2')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_endpoint_empty_ca_normalised_to_none(self, mock_get_v2):
        """V2 endpoint with empty string CA → normalised to None (system trust)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            ca_certificate='',
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'v2')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_endpoint_authenticated_true(self, mock_get_v2):
        """V2 endpoint with authenticated=True is propagated."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            authenticated=True,
            ca_certificate='/tmp/ca.crt',
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertTrue(result.authenticated)

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_endpoint_authenticated_false(self, mock_get_v2):
        """V2 endpoint with authenticated=False is propagated."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            authenticated=False,
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertFalse(result.authenticated)

    # --- V2 absent → fallback (no V1 intermediate) ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_returns_none_falls_back_to_env(self, mock_get_v2):
        """V2 returns None → env/default fallback URL, system trust, warning logged."""
        mock_get_v2.return_value = None
        with self.assertLogs('project_settings.settings', level='WARNING') as cm:
            result = _resolve_v2_endpoint('rbac', 'service', fallback_url='http://rbac-env.example.com')
        self.assertEqual(result.url, 'http://rbac-env.example.com')
        self.assertIsNone(result.ca_certificate)
        self.assertFalse(result.authenticated)
        self.assertEqual(result.source, 'fallback')
        self.assertIn('V2 dependency endpoint not found for rbac/service', cm.output[0])

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_empty_uri_falls_back_to_env(self, mock_get_v2):
        """V2 endpoint exists but URI is empty → env/default fallback, warning logged."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='')
        with self.assertLogs('project_settings.settings', level='WARNING') as cm:
            result = _resolve_v2_endpoint('sources-api', 'svc', fallback_url='http://localhost')
        self.assertEqual(result.url, 'http://localhost')
        self.assertEqual(result.source, 'fallback')
        self.assertIn('V2 dependency endpoint not found for sources-api/svc', cm.output[0])

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_absent_no_fallback_returns_none(self, mock_get_v2):
        """V2 returns None, no fallback → URL is None."""
        mock_get_v2.return_value = None
        with self.assertLogs('project_settings.settings', level='WARNING'):
            result = _resolve_v2_endpoint('sources-api', 'svc')
        self.assertIsNone(result.url)
        self.assertEqual(result.source, 'fallback')

    # --- Key verification ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_rbac_v2_keys(self, mock_get_v2):
        """RBAC uses app='rbac', deployment='service'."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://rbac-v2.svc:443')
        _resolve_v2_endpoint('rbac', 'service')
        mock_get_v2.assert_called_once_with('rbac', 'service')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_sources_v2_keys(self, mock_get_v2):
        """Sources uses app='sources-api', deployment='svc'."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://sources-v2.svc:443')
        _resolve_v2_endpoint('sources-api', 'svc')
        mock_get_v2.assert_called_once_with('sources-api', 'svc')

    # --- Required Behavior Matrix ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_matrix_v2_with_ca_uses_v2_ca(self, mock_get_v2):
        """V2 with CA → V2 CA filesystem path used for TLS verification."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac-v2.svc:8443',
            ca_certificate='/v2/specific/ca.crt',
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertEqual(result.ca_certificate, '/v2/specific/ca.crt')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_matrix_v2_without_ca_uses_system_trust(self, mock_get_v2):
        """V2 without CA → system trust (None)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac-v2.svc:8443',
            ca_certificate=None,
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertIsNone(result.ca_certificate)

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_matrix_fallback_uses_system_trust(self, mock_get_v2):
        """Env/default fallback → system trust (None)."""
        mock_get_v2.return_value = None
        with self.assertLogs('project_settings.settings', level='WARNING'):
            result = _resolve_v2_endpoint('rbac', 'service', fallback_url='http://rbac-local')
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'fallback')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_matrix_v2_auth_flag_propagated(self, mock_get_v2):
        """V2 authenticated flag is propagated to ResolvedEndpoint."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac-v2.svc:8443',
            authenticated=True,
            ca_certificate='/v2/ca.crt',
        )
        result = _resolve_v2_endpoint('rbac', 'service')
        self.assertTrue(result.authenticated)
        self.assertEqual(result.source, 'v2')


class BuildEndpointUrlTests(SimpleTestCase):
    """Tests for the V1 build_endpoint_url helper (used by host-inventory and playbook-dispatcher)."""

    @patch('project_settings.settings.LoadedConfig')
    def test_with_tls(self, mock_config):
        """TLS CA path present → https with tlsPort."""
        mock_config.tlsCAPath = '/etc/pki/tls/ca.crt'
        ep = _make_v1_endpoint('rbac', 'rbac-host.svc', 8000, tls_port=8443)
        self.assertEqual(build_endpoint_url(ep), 'https://rbac-host.svc:8443')

    @patch('project_settings.settings.LoadedConfig')
    def test_without_tls(self, mock_config):
        """No TLS CA path → http with regular port."""
        mock_config.tlsCAPath = None
        ep = _make_v1_endpoint('sources-api', 'sources.svc', 8000)
        self.assertEqual(build_endpoint_url(ep), 'http://sources.svc:8000')
