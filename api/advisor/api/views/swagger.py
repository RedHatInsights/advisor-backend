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

import re

from django.conf import settings
from django.core.exceptions import BadRequest
from rest_framework.permissions import AllowAny
from drf_spectacular.plumbing import build_basic_type, build_array_type, build_parameter_type
from drf_spectacular.views import (
    SpectacularAPIView, SpectacularJSONAPIView, SpectacularSwaggerView
)

from api.permissions import (
    RHIdentityAuthentication, TurnpikeIdentityAuthentication,
)
# module import so we can manipulate rbac_perm_cache
from api import permissions
# from project_settings import settings


def sanitise_param_pattern_regex(pattern):
    """
    Make sure that if the parameter has a 'pattern' attribute, then it is
    ECMA-262 compliant.  This involves:
    * Removing any named subexpressions
    """
    return re.sub(r'\?P<\w+>', '', pattern)


def check_schema_for_regex(schema):
    if schema['type'] == 'str' and 'format' in schema and schema['format'] == 'regex' and 'pattern' in schema:
        schema['pattern'] = sanitise_param_pattern_regex(schema['pattern'])


def sanitise_regex_patterns(result, generator, request, public):
    """
    Make sure any parameters that have regex patterns are sanitised to
    ECMA-262 compliance, as per the helper above.
    """
    for path, methods in result['paths'].items():
        for method, operation_schema in methods.items():
            if 'parameters' not in operation_schema:
                continue
            for param in operation_schema['parameters']:
                schema = param['schema']
                # Single items:
                check_schema_for_regex(schema)
                # Array items:
                if schema['type'] == 'array':
                    check_schema_for_regex(schema['items'])
    return result


def build_parameter_schema_pattern(pattern=None, **kwargs):
    schema = build_parameter_type(**kwargs)
    # For some reason the IQE API code generator does not expect to see a
    # pattern for a regex, even though OpenAPI 3 defines them:
    # https://swagger.io/docs/specification/data-models/data-types/#pattern
    # if pattern:
    #     schema['pattern'] = pattern
    return schema


def maybe_build_array_type(parameter):
    schema = build_basic_type(parameter.type)
    return build_array_type(schema) if parameter.many else schema


def fix_stats_views_parameters(result, generator, request, public):
    """
    Make sure stats views have their parameters described.
    """
    from api.views.stats import standard_parameters
    parameter_schemas = [
        build_parameter_schema_pattern(
            name=parameter.name, location=parameter.location,
            schema=maybe_build_array_type(parameter), required=parameter.required,
            description=parameter.description, enum=parameter.enum,
            style=parameter.style, default=parameter.default,
            pattern=parameter.pattern,
        )
        for parameter in standard_parameters
    ]
    for path, methods in result['paths'].items():
        if '/stats/' not in path:
            continue
        if path.endswith('/stats/'):
            continue
        for method, operation_schema in methods.items():
            if 'parameters' in operation_schema:
                raise BadRequest(
                    f"Path {path} {method} has parameters: "
                    f"{operation_schema['parameters']} - override not necessary"
                )
            operation_schema['parameters'] = parameter_schemas
    return result


def filter_advisor_api_paths(endpoints):
    api_prefix = '/' + settings.API_PATH_PREFIX
    for endpoint in endpoints:
        # endpoint = (path, path_regex, method, callback)
        path = endpoint[0]
        if path.startswith(api_prefix):
            yield endpoint


advisor_api_settings = {
    # The other settings are correct for Advisor.  Just filter the paths
    'PREPROCESSING_HOOKS': ['api.views.swagger.filter_advisor_api_paths'],
    # Not sure why 'SCHEMA_PATH_PREFIX': '/' + settings.API_PATH_PREFIX, doesn't work here
    'POSTPROCESSING_HOOKS': [
        'api.views.swagger.sanitise_regex_patterns',
        'api.views.swagger.fix_stats_views_parameters',
    ],
}


def make_spectacular_view(view_class):
    """
    drf-spectacular makes up a new request object for every view it tests
    permissions on (for reasons I don't yet comprehend).  So we'd like to
    cache the permission response we got from RBAC while we generate the
    schema, and then go back to not caching it.
    """
    # In order to base this in a different view class, we generate a different
    # function based on that class argument.
    def spectacular_view(*args, **kwargs):
        permissions.rbac_perm_cache = dict()
        rtn = view_class.as_view(
            custom_settings=advisor_api_settings,
            authentication_classes=[RHIdentityAuthentication, TurnpikeIdentityAuthentication],
            permission_classes=[AllowAny],
        )(*args, **kwargs)
        permissions.rbac_perm_cache = None
        return rtn
    return spectacular_view


spectacular_view = make_spectacular_view(SpectacularAPIView)
spectacular_json_view = make_spectacular_view(SpectacularJSONAPIView)

spectacular_ui_view = SpectacularSwaggerView.as_view(
    url_name='advisor-openapi-spec'
)
