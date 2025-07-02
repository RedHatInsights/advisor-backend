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

from project_settings.settings import SAT_COMPAT_BASE_PATH, API_PATH_PREFIX


def satellite_compatibility_api_deprecated(get_response):
    """
    Put 'X-Deprecated' headers in the response, if we're in the Satellite
    compatibility path.
    """
    def middleware(request):
        response = get_response(request)
        if request.path.startswith('/' + SAT_COMPAT_BASE_PATH):
            response['X-Deprecated-Message'] = 'This API is deprecated.'
            response['X-Deprecated-Successor-Path'] = '/' + API_PATH_PREFIX
            response['X-Deprecated-Sunset-Date'] = '2021-12-31T23:59:59Z'
        return response

    return middleware
