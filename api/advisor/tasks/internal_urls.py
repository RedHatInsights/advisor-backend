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

from django.conf import settings
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from tasks.urls import TasksRouter
from tasks.views import task  # executed_task, system,


def internal_tasks_schema_filter(endpoints):
    for endpoint in endpoints:
        # endpoint = (path, path_regex, method, callback);
        # 'path' would shadow our import of path from django.urls
        if endpoint[0].startswith('/internal/' + settings.TASKS_PATH_PREFIX):
            yield endpoint


internal_router = TasksRouter(trailing_slash=False)
internal_router.register(r'task', task.InternalTaskViewSet, basename='internal-tasks-task')

internal_tasks_schema_settings = {
    'TITLE': 'Insights Internal Tasks API',
    'DESCRIPTION': "The API for managing the Tasks content",
    'SCHEMA_PATH_PREFIX': '/internal/' + settings.TASKS_PATH_PREFIX,
    'PREPROCESSING_HOOKS': ['tasks.internal_urls.internal_tasks_schema_filter']
}

urlpatterns = [
    path(r'', include(internal_router.urls)),
    # Swagger schema
    path(
        'schema/',
        SpectacularAPIView.as_view(custom_settings=internal_tasks_schema_settings),
        name='internal-tasks-schema'
    ),
    # Swagger UI via DRF-Spectacular-Sidecar
    path(
        'schema/swagger-ui/',
        SpectacularSwaggerView.as_view(url_name='internal-tasks-schema'),
        name='tasks-swagger-ui'
    ),
]
