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

Covers the _resolve_v2_url helper and build_endpoint_url from
project_settings.settings, verifying the V2 → V1 → fallback chain
for RBAC and Sources migration.
"""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from project_settings.settings import _resolve_v2_url, build_endpoint_url


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


class ResolveV2UrlTests(SimpleTestCase):
    """Tests for _resolve_v2_url: V2 → V1 → fallback resolution chain."""

    def setUp(self):
        self.v1_endpoints = {
            'rbac': _make_v1_endpoint('rbac', 'rbac-service.svc', 8000, tls_port=8443),
            'sources-api': _make_v1_endpoint('sources-api', 'sources.svc', 8000, tls_port=8443),
        }

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_with_uri_and_ca(self, mock_config, mock_get_v2):
        """V2 endpoint present with URI and CA → returns V2 URI directly."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://rbac.clowder.svc:8443',
            ca_certificate='/tmp/ca.crt',
        )
        result = _resolve_v2_url('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result, 'https://rbac.clowder.svc:8443')
        mock_get_v2.assert_called_once_with('rbac', 'service')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_endpoint_with_uri_no_ca(self, mock_config, mock_get_v2):
        """V2 endpoint present with URI but no CA → returns V2 URI (system trust)."""
        mock_get_v2.return_value = _make_v2_endpoint(
            uri='https://sources.clowder.svc:8443',
            ca_certificate=None,
        )
        result = _resolve_v2_url('sources-api', 'svc', self.v1_endpoints)
        self.assertEqual(result, 'https://sources.clowder.svc:8443')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_returns_none_falls_back_to_v1_with_tls(self, mock_config, mock_get_v2):
        """V2 returns None → falls back to V1 endpoint with TLS."""
        mock_get_v2.return_value = None
        mock_config.tlsCAPath = '/etc/pki/tls/ca.crt'
        result = _resolve_v2_url('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result, 'https://rbac-service.svc:8443')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_returns_none_falls_back_to_v1_no_tls(self, mock_config, mock_get_v2):
        """V2 returns None → falls back to V1 endpoint without TLS."""
        mock_get_v2.return_value = None
        mock_config.tlsCAPath = None
        result = _resolve_v2_url('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result, 'http://rbac-service.svc:8000')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_empty_uri_falls_back_to_v1(self, mock_config, mock_get_v2):
        """V2 endpoint exists but URI is empty → falls back to V1."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='')
        mock_config.tlsCAPath = None
        result = _resolve_v2_url('sources-api', 'svc', self.v1_endpoints)
        self.assertEqual(result, 'http://sources.svc:8000')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_and_v1_absent_returns_fallback(self, mock_get_v2):
        """V2 returns None and V1 key missing → returns fallback URL."""
        mock_get_v2.return_value = None
        result = _resolve_v2_url('rbac', 'service', {}, fallback_url='http://rbac-env.example.com')
        self.assertEqual(result, 'http://rbac-env.example.com')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    def test_v2_and_v1_absent_no_fallback_returns_none(self, mock_get_v2):
        """V2 returns None, V1 missing, no fallback → returns None."""
        mock_get_v2.return_value = None
        result = _resolve_v2_url('sources-api', 'svc', {})
        self.assertIsNone(result)

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_rbac_v2_keys(self, mock_config, mock_get_v2):
        """RBAC uses app='rbac', deployment='service' (platform-dependency-v2-keys.md)."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://rbac-v2.svc:443')
        _resolve_v2_url('rbac', 'service', self.v1_endpoints)
        mock_get_v2.assert_called_once_with('rbac', 'service')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_sources_v2_keys(self, mock_config, mock_get_v2):
        """Sources uses app='sources-api', deployment='svc' (platform-dependency-v2-keys.md)."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://sources-v2.svc:443')
        _resolve_v2_url('sources-api', 'svc', self.v1_endpoints)
        mock_get_v2.assert_called_once_with('sources-api', 'svc')

    @patch('project_settings.settings.get_v2_dependency_endpoint')
    @patch('project_settings.settings.LoadedConfig')
    def test_v2_preferred_over_v1(self, mock_config, mock_get_v2):
        """When both V2 and V1 are available, V2 takes precedence."""
        mock_get_v2.return_value = _make_v2_endpoint(uri='https://rbac-v2.clowder.svc:443')
        mock_config.tlsCAPath = '/etc/pki/tls/ca.crt'
        result = _resolve_v2_url('rbac', 'service', self.v1_endpoints)
        self.assertEqual(result, 'https://rbac-v2.clowder.svc:443')
        # V1 build_endpoint_url should NOT have been called via the function
        # (V2 short-circuits)


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
