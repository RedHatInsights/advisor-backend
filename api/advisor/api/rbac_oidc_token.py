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

"""
OIDC client credentials token acquisition for service-to-service
communication with RBAC.

Uses the kessel SDK's OAuth2ClientCredentials class, which handles token
acquisition, caching, and automatic refresh via the OAuth2 client
credentials grant.  This is the same mechanism Kessel itself uses for
its gRPC authentication (see api/kessel.py).
"""
from kessel.auth import OAuth2ClientCredentials, fetch_oidc_discovery

from django.conf import settings

from advisor_logging import logger

# Module-level credentials instance, created lazily on first use.
_credentials = None


def _get_credentials() -> OAuth2ClientCredentials:
    """
    Return the module-level OAuth2ClientCredentials instance, creating
    it on first use.  The kessel SDK handles token caching and refresh
    internally (with a 5-minute expiry buffer).
    """
    global _credentials
    if _credentials is not None:
        return _credentials

    logger.info(
        "Creating RBAC OIDC credentials for Client ID %s and OIDC issuer %s",
        settings.KESSEL_AUTH_CLIENT_ID, settings.KESSEL_AUTH_OIDC_ISSUER,
    )
    discovery = fetch_oidc_discovery(settings.KESSEL_AUTH_OIDC_ISSUER)
    _credentials = OAuth2ClientCredentials(
        client_id=settings.KESSEL_AUTH_CLIENT_ID,
        client_secret=settings.KESSEL_AUTH_CLIENT_SECRET,
        token_endpoint=discovery.token_endpoint,
    )
    return _credentials


def get_rbac_oidc_access_token() -> str:
    """
    Return a valid OIDC access token for RBAC service-to-service
    communication.

    The kessel SDK's OAuth2ClientCredentials.get_token() handles:
    - Acquiring a new token via client_credentials grant
    - Caching the token in memory
    - Refreshing automatically when the token is within 5 minutes of
      expiry
    """
    credentials = _get_credentials()
    token_response = credentials.get_token()
    return token_response.access_token


def clear_credentials():
    """
    Reset the module-level credentials instance.  Primarily for use
    in tests to ensure a clean state between test cases.
    """
    global _credentials
    _credentials = None
