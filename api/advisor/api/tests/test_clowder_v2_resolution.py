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
project_settings.settings, verifying the V2 → V1 → fallback chain
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
    """Tests for _resolve_v2_endpoint: V2 → V1 → fallback resolution chain."""

    def setUp(self):
        self.v1_endpoints = {
            'rbac': _make_v1_endpoint('rbac', 'rbac-service.svc', 8000, tls_port=8443),
            'sources-api': _make_v1_endpoint('sources-api', 'sources.svc', 8000, tls_port=8443),
        }

    # --- V2 URI resolution ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_with_uri_and_ca(self, mock_config, mock_get_v2):
        """V2 endpoint present with URI and CA → returns V2 URI, V2 CA, source='v2'."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            authenticated=False,
            ca_certificate='/tmp/ca.crt',
        )
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result.url, 'https://rbac.clowder.svc:8443')
        self.assertEqual(result.ca_certificate, '/tmp/ca.crt')
        self.assertFalse(result.authenticated)
        self.assertEqual(result.source, 'v2')
        mock_get_v2.assert_called_once_with('rbac', 'service')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_with_uri_no_ca(self, mock_config, mock_get_v2):
        """V2 endpoint present with URI but no CA → V2 URI, ca_certificate=None (system trust)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://sources.clowder.svc:8443',
            authenticated=False,
            ca_certificate=None,
        )
        result = _resolve_v2_endpoint('sources-api', 'svc', self.v1_endpoints)
        self.assertEqual(result.url, 'https://sources.clowder.svc:8443')
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'v2')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_empty_ca_normalised_to_none(self, mock_config, mock_get_v2):
        """V2 endpoint with empty string CA → normalised to None (system trust)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            ca_certificate='',
        )
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'v2')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_authenticated_true(self, mock_config, mock_get_v2):
        """V2 endpoint with authenticated=True is propagated."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            authenticated=True,
            ca_certificate='/tmp/ca.crt',
        )
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertTrue(result.authenticated)

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_authenticated_false(self, mock_config, mock_get_v2):
        """V2 endpoint with authenticated=False is propagated."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            authenticated=False,
        )
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertFalse(result.authenticated)

    # --- V1 fallback ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_returns_none_falls_back_to_v1_with_tls(self, mock_config, mock_get_v2):
        """V2 returns None → V1 endpoint with TLS, CA from LoadedConfig.tlsCAPath."""
        mock_get_v2.return_value = None
        mock_config.tlsCAPath = '/etc/pki/tls/ca.crt'
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result.url, 'https://rbac-service.svc:8443')
        self.assertEqual(result.ca_certificate, '/etc/pki/tls/ca.crt')
        self.assertFalse(result.authenticated)
        self.assertEqual(result.source, 'v1')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_returns_none_falls_back_to_v1_no_tls(self, mock_config, mock_get_v2):
        """V2 returns None → V1 endpoint without TLS, ca_certificate=None."""
        mock_get_v2.return_value = None
        mock_config.tlsCAPath = None
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result.url, 'http://rbac-service.svc:8000')
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'v1')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_empty_uri_falls_back_to_v1(self, mock_config, mock_get_v2):
        """V2 endpoint exists but URI is empty → falls back to V1."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='')
        mock_config.tlsCAPath = None
        result = _resolve_v2_endpoint('sources-api', 'svc', self.v1_endpoints)
        self.assertEqual(result.url, 'http://sources.svc:8000')
        self.assertEqual(result.source, 'v1')

    # --- Fallback ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_and_v1_absent_returns_fallback(self, mock_get_v2):
        """V2 returns None and V1 key missing → fallback URL, system trust."""
        mock_get_v2.return_value = None
        result = _resolve_v2_endpoint('rbac', 'service', {}, fallback_url='http://rbac-env.example.com')
        self.assertEqual(result.url, 'http://rbac-env.example.com')
        self.assertIsNone(result.ca_certificate)
        self.assertFalse(result.authenticated)
        self.assertEqual(result.source, 'fallback')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_and_v1_absent_no_fallback_returns_none(self, mock_get_v2):
        """V2 returns None, V1 missing, no fallback → URL is None."""
        mock_get_v2.return_value = None
        result = _resolve_v2_endpoint('sources-api', 'svc', {})
        self.assertIsNone(result.url)
        self.assertEqual(result.source, 'fallback')

    # --- Key verification ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_rbac_v2_keys(self, mock_config, mock_get_v2):
        """RBAC uses app='rbac', deployment='service'."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://rbac-v2.svc:443')
        _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        mock_get_v2.assert_called_once_with('rbac', 'service')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_sources_v2_keys(self, mock_config, mock_get_v2):
        """Sources uses app='sources-api', deployment='svc'."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://sources-v2.svc:443')
        _resolve_v2_endpoint('sources-api', 'svc', self.v1_endpoints)
        mock_get_v2.assert_called_once_with('sources-api', 'svc')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_preferred_over_v1(self, mock_config, mock_get_v2):
        """When both V2 and V1 are available, V2 takes precedence."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac-v2.clowder.svc:443',
            ca_certificate='/v2/ca.crt',
        )
        mock_config.tlsCAPath = '/etc/pki/tls/ca.crt'
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result.url, 'https://rbac-v2.clowder.svc:443')
        self.assertEqual(result.ca_certificate, '/v2/ca.crt')
        self.assertEqual(result.source, 'v2')

    # --- Required Behavior Matrix ---

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_matrix_v2_with_ca_does_not_use_v1_ca(self, mock_config, mock_get_v2):
        """V2 with CA must NOT fall back to LoadedConfig.tlsCAPath (no cross-source mixing)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac-v2.svc:8443',
            ca_certificate='/v2/specific/ca.crt',
        )
        mock_config.tlsCAPath = '/v1/global/ca.crt'
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result.ca_certificate, '/v2/specific/ca.crt')
        self.assertNotEqual(result.ca_certificate, '/v1/global/ca.crt')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_matrix_v2_without_ca_uses_system_trust(self, mock_config, mock_get_v2):
        """V2 without CA → system trust (None), NOT LoadedConfig.tlsCAPath."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac-v2.svc:8443',
            ca_certificate=None,
        )
        mock_config.tlsCAPath = '/v1/global/ca.crt'
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertIsNone(result.ca_certificate)

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_matrix_v1_fallback_uses_loaded_config_ca(self, mock_config, mock_get_v2):
        """V1 fallback → LoadedConfig.tlsCAPath (V1 CA behaviour preserved)."""
        mock_get_v2.return_value = None
        mock_config.tlsCAPath = '/v1/global/ca.crt'
        result = _resolve_v2_endpoint('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result.ca_certificate, '/v1/global/ca.crt')
        self.assertEqual(result.source, 'v1')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_matrix_fallback_uses_system_trust(self, mock_get_v2):
        """Env/default fallback → system trust (None)."""
        mock_get_v2.return_value = None
        result = _resolve_v2_endpoint('rbac', 'service', {}, fallback_url='http://rbac-local')
        self.assertIsNone(result.ca_certificate)
        self.assertEqual(result.source, 'fallback')


class BuildEndpointUrlTests(SimpleTestCase):
    """Tests for the V1 build_endpoint_url helper (unchanged, regression guard)."""

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
