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

from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django_prometheus import exports

from project_settings import settings

from api.urls import router, urlpatterns
from tasks.urls import urlpatterns as tasks_urlpatterns
from sat_compat.urls import v1router, v2router, v3urlpatterns
from sat_compat.views.me import MeView
from sat_compat.views.ping import PingViewSet

urlpatterns = [
    # Regular path for Advisor API:
    path(settings.API_PATH_PREFIX, include(urlpatterns)),

    # Regular path for Tasks API:
    path(settings.TASKS_PATH_PREFIX, include(tasks_urlpatterns)),

    # Satellite compatibility paths:
    # NB: For paths that aren't included in the routers, the basename field
    # needs to be supplied but isn't used; set name= on the path().
    path(settings.SAT_COMPAT_BASE_PATH,
        PingViewSet.as_view({'get': 'list'}, basename='sat-compat-ping')),
    path(settings.SAT_COMPAT_BASE_PATH + '/',
        PingViewSet.as_view({'get': 'list'}, basename='sat-compat-ping')),
    # Just in case...
    path(settings.SAT_COMPAT_BASE_PATH + '//',
        PingViewSet.as_view({'get': 'list'}, basename='sat-compat-ping')),
    path(settings.SAT_COMPAT_BASE_PATH + '/me',
        MeView.as_view({'get': 'list'}, basename='sat-compat-me')),
    path(settings.SAT_COMPAT_PATH_PREFIX_V1, include(v1router.urls)),
    path(settings.SAT_COMPAT_PATH_PREFIX_V2, include(v2router.urls)),
    path(settings.SAT_COMPAT_PATH_PREFIX_V3, include(v3urlpatterns)),
    # Special path for platform to cope with Satellite proxy path restrictions
    path(settings.PLATFORM_PATH_PREFIX, include(router.urls)),

    # Other paths
    path(settings.PROMETHEUS_PATH, exports.ExportToDjangoView, name="prometheus-django-metrics"),
    path('internal/' + settings.API_PATH_PREFIX, include('api.internal_urls')),
    path('internal/' + settings.TASKS_PATH_PREFIX, include('tasks.internal_urls')),
    path('private/', include('api.private_urls')),
]

if settings.DEBUG:
    urlpatterns += staticfiles_urlpatterns()
