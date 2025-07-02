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

from django.urls import path, re_path, include

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter

from rest_framework.routers import (
    APIRootView, DefaultRouter, format_suffix_patterns
)

# Flake8 doesn't like star imports, and we can't seem to do 'from api import
# views' and then use views.acks.AckViewSet.  Better solutions welcomed!
from api.views import system_types
from sat_compat.views import (
    account, acks, articles, branch_info, cves, evaluation, exports, groups,
    maintenance, plugins, reports, rules, stats, swagger, systems,
    topics,
)


def param_to_regex(param):
    """
    Provide the regex pattern that matches parameters of a particular type.
    This is then delimited by / or end of line.

    Only works on basic types; does not match objects, arrays or files.
    """
    assert param.location == OpenApiParameter.PATH, f"Param {param.name} not a path parameter"
    if param.type == OpenApiTypes.STR:
        pattern = getattr(param, 'pattern', None)
        if pattern:
            return pattern
        # Note: I don't think we want to match spaces here...
        return r'\w+'
    elif param.type == OpenApiTypes.NUMBER:
        # Simplistic
        return r'[+-]?\d+(?:\.\d+)?'
    elif param.type == OpenApiTypes.INT:
        return r'[+-]?\d+'
    elif param.type == OpenApiTypes.BOOL:
        return r'(?i:y|n|yes|no|t|f|true|false)'
    else:
        raise AttributeError(f"Param {param.name} must be string, number, integer or boolean")


class SatCompatRootView(APIRootView):
    """
    The Insights Advisor Satellite compatibility API view.
    """
    pass


class SatCompatRouter(DefaultRouter):
    """
    Use our own root view to provide a nicer schema description, and to allow
    extra path params in very specific circumstances.
    """
    APIRootView = SatCompatRootView

    def get_urls(self):
        """
        Use the registered viewsets to generate a list of URL patterns.
        """
        # This part from SimpleRouter
        urls = []

        for prefix, viewset, basename in self.registry:
            lookup = self.get_lookup_regex(viewset)
            routes = self.get_routes(viewset)

            for route in routes:

                # Only actions which actually exist on the viewset will be bound
                mapping = self.get_method_map(viewset, route.mapping)
                if not mapping:
                    continue

                url = route.url
                if 'extra_path_params' in route.initkwargs and route.initkwargs['extra_path_params']:
                    # Shove extra path params before trailing slash.
                    url = url.replace(
                        '{trailing_slash}',
                        '/' + '/'.join(
                            f"(?P<{param.name}>{param_to_regex(param)})"
                            for param in route.initkwargs['extra_path_params']
                        ) + '{trailing_slash}'
                    )
                # Build the url pattern
                regex = url.format(
                    prefix=prefix,
                    lookup=lookup,
                    trailing_slash=self.trailing_slash
                )

                # If there is no prefix, the first part of the url is probably
                #   controlled by project's urls.py and the router is in an app,
                #   so a slash in the beginning will (A) cause Django to give
                #   warnings and (B) generate URLS that will require using '//'.
                if not prefix and regex[:2] == '^/':
                    regex = '^' + regex[2:]

                initkwargs = route.initkwargs.copy()
                initkwargs.update({
                    'basename': basename,
                    'detail': route.detail,
                })

                view = viewset.as_view(mapping, **initkwargs)
                name = route.name.format(basename=basename)
                urls.append(re_path(regex, view, name=name))

        # This part from DefaultRouter
        if self.include_root_view:
            view = self.get_api_root_view(api_urls=urls)
            root_url = re_path(r'^$', view, name=self.root_view_name)
            urls.append(root_url)

        if self.include_format_suffixes:
            urls = format_suffix_patterns(urls)

        return urls


# /r/insights/v1/ routes
v1router = SatCompatRouter(trailing_slash=False)
# Just copy the v3 view at this stage
v1router.register(r'branch_info', branch_info.BranchInfoViewSet, basename='sat-compat-v1-branch-info')
v1router.register(r'systems', systems.V1SystemViewSet, basename='sat-compat-v1-systems')
v1router.register(r'system_types', system_types.SystemTypeViewSet, basename='sat-compat-v1-system-types')
v1router.register(r'groups', groups.GroupsViewSet, basename='sat-compat-v1-groups')

# /r/insights/v2/ routes
v2router = SatCompatRouter(trailing_slash=False)
v2router.register(r'account', account.AccountViewSet, basename='sat-compat-v2-account')

# /r/insights/v3/ routes
v3router = SatCompatRouter(trailing_slash=False)
v3router.register(r'account', account.AccountViewSet, basename='sat-compat-account')
v3router.register(r'acks', acks.AckViewSet, basename='sat-compat-acks')
v3router.register(r'articles', articles.ArticlesViewSet, basename='sat-compat-articles')
v3router.register(r'cves', cves.CVEViewSet, basename='sat-compat-cves')
v3router.register(r'evaluation', evaluation.EvaluationViewSet, basename='sat-compat-evaluation')
# exports is an include of another router
v3router.register(r'groups', groups.GroupsViewSet, basename='sat-compat-v3-groups')
v3router.register(r'maintenance', maintenance.MaintenanceViewSet, basename='sat-compat-maintenance')
v3router.register(r'plugins', plugins.PluginViewset, basename='sat-compat-plugins')
v3router.register(r'reports', reports.ReportsViewSet, basename='sat-compat-reports')
v3router.register(r'rules', rules.RuleViewSet, basename='sat-compat-rules')
v3router.register(r'stats', stats.StatsViewSet, basename='sat-compat-stats')
v3router.register(r'systems', systems.SystemViewSet, basename='sat-compat-systems')
v3router.register(r'system_types', system_types.SystemTypeViewSet, basename='sat-compat-system-types')
v3router.register(r'topics', topics.TopicsViewSet, basename='sat-compat-topics')

v3urlpatterns = [
    path(r'', include(v3router.urls)),
    path(r'exports/', include(exports.router.urls), name='sat-compat-export-list'),
    path('openapi/', swagger.spectactular_view, name='sat-compat-openapi-spec'),
    path('openapi/swagger/', swagger.spectactular_ui_view, name='sat-compat-openapi-ui'),
]
