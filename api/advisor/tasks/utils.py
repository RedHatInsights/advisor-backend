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

import uuid
from copy import deepcopy
from django.contrib.postgres.fields import ArrayField
from django.db.models import Case, CharField, Exists, Q, UUIDField, Value, When
from django.db.models.functions import Cast
from rest_framework.serializers import ValidationError
from drf_spectacular.types import OpenApiTypes

from api.filters import (
    value_of_param, rhel_version_query_param, sort_param_enum, OpenApiParameter
)
from tasks.models import ArrayNoNull, Host, SatelliteRhc


playbook_dispatcher_connection_status_path = '/internal/v2/connection_status'

#######################################################
# System filter common parameters and filter functions
#######################################################

os_version_query_param = deepcopy(rhel_version_query_param)
os_version_query_param.name = 'os_version'
os_version_query_param.description = 'Display only systems with these OS versions'

os_name_query_param = OpenApiParameter(
    name='os_name', location=OpenApiParameter.QUERY, type=OpenApiTypes.STR,
    required=False, many=True, style='form',
    description="Filter on these (short) operating system names"
)

os_query_param = OpenApiParameter(
    name='operating_system', location=OpenApiParameter.QUERY, type=OpenApiTypes.STR,
    required=False, many=True, style='form', pattern=r'\w+\\|\d+\.\d+',
    description="Filter on both operating system name and version. A pipe separates the values. For Example: RHEL|7.9"
)

system_sort_fields = [
    'display_name', 'os', 'os_version', 'os_name', 'last_seen', 'group_name',
    'last_check_in'
]
system_sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY, type=OpenApiTypes.STR,
    required=False, many=False,
    description='Sort systems by this field',
    enum=sort_param_enum(system_sort_fields), default='display_name',
)


def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def choices_obj_value_map(enum_obj):
    """
    Turn the given enum object into a map from label to value, for searches.
    """
    return dict(zip(enum_obj.labels, enum_obj.values))


def filter_on_os_version(request, relation=None):
    versions = value_of_param(os_version_query_param, request)
    # Based on Host so look up directly
    version_filter = Q()
    if versions is None:
        return version_filter

    base_parameter = 'system_profile__operating_system'
    if relation:
        base_parameter = relation + '__' + base_parameter
    for version in versions:
        # Assertion: our parameters always have 'major.minor', and those are
        # always ints.
        major, minor = map(int, version.split('.'))
        version_filter |= Q(**{
            base_parameter + '__major': major, base_parameter + '__minor': minor,
        })
    return version_filter


def filter_on_os_name(request, relation=None):
    os_names = value_of_param(os_name_query_param, request)
    os_name_filter = Q()
    if not os_names:
        return os_name_filter

    parameter = 'system_profile__operating_system__name__iexact'
    if relation:
        parameter = relation + '__' + parameter
    for os_name in os_names:
        os_name_filter |= Q(**{parameter: os_name})

    return os_name_filter


def filter_on_os(request, relation=None):
    os_values = value_of_param(os_query_param, request)

    os_filter = Q()
    if not os_values:
        return os_filter

    # Validation should be taken care of by regex, but we check just in case.
    for os in os_values:
        if os.count('|') != 1:
            raise ValidationError(
                {os_query_param.name: 'Badly formatted operating_system '
                'filter.  Must be of the form <NAME>|<VERSION>'}
            )
        tokens = os.split('|')
        request.query_params._mutable = True
        request.query_params['os_name'] = tokens[0]
        request.query_params['os_version'] = tokens[1]
        os_filter |= filter_on_os_name(request, relation) & filter_on_os_version(request, relation)

    return os_filter

#######################################################
# System requirements builder functions
#######################################################


centos_filter = Q(system_profile__operating_system__name__startswith="CentOS")
rhel_filter = Q(system_profile__operating_system__name="RHEL")
# known_os_filter handles both the OS name missing in the OS field, and the whole OS field itself missing
known_os_filter = Q(system_profile__operating_system__name__isnull=False)
os_v7_filter = Q(system_profile__operating_system__major=7)
os_v8_filter = Q(system_profile__operating_system__major=8)
os_v7_v8_filter = Q(system_profile__operating_system__major__in=(7, 8))
direct_connect_filter = Q(system_profile__rhc_client_id__isnull=False)
satellite_rhc_filter = Exists(
    SatelliteRhc.objects.filter(
        instance_id=Cast(Host.tag_query('satellite_instance_id'), output_field=UUIDField()),
        rhc_client_id__isnull=False
    )
)
system_connected_filter = Q(direct_connect_filter | satellite_rhc_filter)
bootc_image_filter = Q(system_profile__bootc_status__booted__image_digest__isnull=False)
# Using 'regex' instead of 'contains' because it automagically casts image to text and matches the given string,
# whereas 'contains' is overridden when working with jsonb objects and treats image as jsonb instead of text
rhelai_image_filter = Q(system_profile__bootc_status__booted__image__regex='/rhelai[0-9]*/')

requirements = {
    'direct_connect': {
        "alert": "System must be directly connected to RHC",
        "filter": direct_connect_filter
    },
    'satellite_rhc': {
        "alert": "System must be connected via Satellite",
        "filter": satellite_rhc_filter
    },
    'system_connected': {
        "alert": "System must be connected via RHC or Satellite",
        "filter": system_connected_filter
    },
    'known_os': {
        "alert": "System must have a known OS",
        "filter": known_os_filter
    },
    'centos': {
        "alert": "System must be CentOS",
        "filter": centos_filter
    },
    'rhel': {
        "alert": "System must be RHEL",
        "filter": rhel_filter
    },
    'os_v7': {
        "alert": "System must be OS version 7",
        "filter": os_v7_filter
    },
    'os_v8': {
        "alert": "System must be OS version 8",
        "filter": os_v8_filter
    },
    'os_v7_v8': {
        "alert": "System must be OS version 7 or 8",
        "filter": os_v7_v8_filter
    },
    'bootc_image': {
        "alert": "System must be a bootc image",
        "filter": bootc_image_filter
    },
    'rhelai_image': {
        "alert": "System must be a RHEL AI image",
        "filter": rhelai_image_filter
    },
    'not_rhelai_image': {
        "alert": "System must not be a RHEL AI image",
        "filter": ~rhelai_image_filter  # needed to make RHEL AI systems ineligible for the bootc_upgrade task
    },
}


def build_task_system_requirements(task):
    # Add the known_os filter if a task has existing (OS) filters because systems cannot have an unknown OS either
    # And add the system_connected filter to all tasks because eligible systems must be connected via RHC / Satellite
    if task.filters:
        task.filters += ['known_os']
    task.filters += ['system_connected']
    return ArrayNoNull(*[
        Case(When(~requirements[req]['filter'], then=Value(requirements[req]['alert'])))
        for req in task.filters
        if req in requirements  # just in case
    ], output_field=ArrayField(base_field=CharField))


all_systems_query_param = OpenApiParameter(
    name='all_systems', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.BOOL, required=False, many=False, default=False
)


def system_requirements_filter(request, task):
    all_systems_flag = value_of_param(all_systems_query_param, request)
    if all_systems_flag:
        return Q()
    else:
        return Q(*[
            requirements[req]['filter']
            for req in task.filters
            if req in requirements
        ])


def apply_system_connected_filter(request):
    # Don't apply the system_connected_filter if the all_systems parameter is used
    # Instead we will add requirements later for systems to be connected if all_systems parameter is used
    all_systems_flag = value_of_param(all_systems_query_param, request)
    return Q() if all_systems_flag else system_connected_filter
