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

from api.urls import urlpatterns
from tasks.urls import urlpatterns as tasks_urlpatterns

urlpatterns = [
    # Regular path for Advisor API:
    path(settings.API_PATH_PREFIX, include(urlpatterns)),

    # Regular path for Tasks API:
    path(settings.TASKS_PATH_PREFIX, include(tasks_urlpatterns)),

    # Other paths
    path(settings.PROMETHEUS_PATH, exports.ExportToDjangoView, name="prometheus-django-metrics"),
    path('internal/' + settings.API_PATH_PREFIX, include('api.internal_urls')),
    path('internal/' + settings.TASKS_PATH_PREFIX, include('tasks.internal_urls')),
    path('private/', include('api.private_urls')),
]

if settings.DEBUG:
    urlpatterns += staticfiles_urlpatterns()
