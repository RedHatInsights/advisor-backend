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

from rest_framework.permissions import AllowAny
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from project_settings import settings

from api.permissions import (
    RHIdentityAuthentication, TurnpikeIdentityAuthentication
)


def filter_sat_compat_api_paths(endpoints):
    api_prefix = '/' + settings.SAT_COMPAT_PATH_PREFIX_V3
    for endpoint in endpoints:
        # endpoint = (path, path_regex, method, callback)
        path = endpoint[0]
        if path.startswith(api_prefix):
            yield endpoint


sat_compat_api_settings = {
    'TITLE': 'Advisor Satellite Compatibility API',
    'DESCRIPTION': 'The Satellite Compatibility API of the Advisor project in Insights',
    'PREPROCESSING_HOOKS': ['sat_compat.views.swagger.filter_sat_compat_api_paths'],
}


spectactular_view = SpectacularAPIView.as_view(
    custom_settings=sat_compat_api_settings,
    authentication_classes=[RHIdentityAuthentication, TurnpikeIdentityAuthentication],
    permission_classes=[AllowAny],
)
spectactular_ui_view = SpectacularSwaggerView.as_view(
    url_name='sat-compat-openapi-spec'
)
