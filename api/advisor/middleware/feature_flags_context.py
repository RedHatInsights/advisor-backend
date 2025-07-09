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

import json
from base64 import b64decode

from feature_flags import unleash_client


def feature_flags_context(get_response):
    """
    Injects the user org_id into the unleash static context
    """
    def middleware(request):
        context = {"orgId": _get_user_org_id(request)}
        client = unleash_client()
        client.unleash_static_context.update(context)
        response = get_response(request)
        return response

    return middleware


def _get_user_org_id(request):
    # Sometimes we get HTTP_X_RH_IDENTITY, sometimes we get X-RH-IDENTITY,
    # so we need to get this header in one consistent format.
    identity_b64 = request.META.get("HTTP_X_RH_IDENTITY") or request.META.get("X-RH-IDENTITY")
    if not identity_b64:
        return None

    try:
        identity = json.loads(b64decode(identity_b64))
        return identity.get("identity", {}).get("org_id")
    except Exception:
        return None
