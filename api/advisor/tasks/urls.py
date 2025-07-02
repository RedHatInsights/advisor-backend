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
from rest_framework.routers import APIRootView, DefaultRouter
from drf_spectacular.views import (
    SpectacularAPIView, SpectacularJSONAPIView, SpectacularSwaggerView
)

from api import permissions  # for rbac_perm_cache
from tasks.views import executed_task, job, system, task


class TasksRootView(APIRootView):
    """
    The Insights Tasks API root view.
    """
    pass


class TasksRouter(DefaultRouter):
    """
    Use our own root view to provide a nicer schema description.
    """
    APIRootView = TasksRootView
    route_name = 'tasks'

    def get_default_basename(self, viewset):
        """
        Add our route_name to any basename we determine.  This is not a path.
        """
        return self.route_name + '-' + super().get_default_basename(viewset)


router = TasksRouter(trailing_slash=False)
router.register(r'executed_task', executed_task.ExecutedTaskViewSet)
router.register(r'job', job.JobViewSet)
# for system, from model: basename='host', but when we set basename here we
# do not go through get_default_basename above... :-(
router.register(r'system', system.SystemViewSet, basename='tasks-system')
router.register(r'task', task.TaskViewSet)


def tasks_schema_filter(endpoints):
    for endpoint in endpoints:
        # endpoint = (path, path_regex, method, callback);
        # 'path' would shadow our import of path from django.urls
        if endpoint[0].startswith('/' + settings.TASKS_PATH_PREFIX):
            yield endpoint


tasks_description = "The API for managing and issuing Red Hat generated tasks on your infrastructure"
tasks_schema_settings = {
    'TITLE': 'Insights Tasks API',
    'DESCRIPTION': tasks_description,
    # This doesn't just focus on our path, it specifically adds it - so don't!
    # 'SCHEMA_PATH_PREFIX': '/' + settings.TASKS_PATH_PREFIX,
    # uncomment this if you don't want the path prefix in the path
    # 'SCHEMA_PATH_PREFIX_TRIM': True,
    'PREPROCESSING_HOOKS': ['tasks.urls.tasks_schema_filter'],
}


def spectacular_view(*args, **kwargs):
    """
    drf-spectacular makes up a new request object for every view it tests
    permissions on (for reasons I don't yet comprehend).  So we'd like to
    cache the permission response we got from RBAC while we generate the
    schema, and then go back to not caching it.
    """
    permissions.rbac_perm_cache = dict()
    rtn = SpectacularAPIView.as_view(
        custom_settings=tasks_schema_settings,
    )(*args, **kwargs)
    permissions.rbac_perm_cache = None
    return rtn


def spectacular_json_view(*args, **kwargs):
    """
    drf-spectacular makes up a new request object for every view it tests
    permissions on (for reasons I don't yet comprehend).  So we'd like to
    cache the permission response we got from RBAC while we generate the
    schema, and then go back to not caching it.
    """
    permissions.rbac_perm_cache = dict()
    rtn = SpectacularJSONAPIView.as_view(
        custom_settings=tasks_schema_settings,
    )(*args, **kwargs)
    permissions.rbac_perm_cache = None
    return rtn


urlpatterns = [
    path(r'', include(router.urls)),
    # Swagger schema
    path('schema/', spectacular_view, name='tasks-schema'),
    # Support Front End API view, which is restricted to the 'openapi.json'
    # file name and format.
    path('openapi.json', spectacular_json_view, name='tasks-openapi-spec-json'),
    # Swagger UI via DRF-Spectacular-Sidecar
    path(
        'schema/swagger-ui/',
        SpectacularSwaggerView.as_view(url_name='tasks-schema'),
        name='tasks-swagger-ui'
    ),
]
