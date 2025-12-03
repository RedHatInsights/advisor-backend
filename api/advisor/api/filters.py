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

from copy import deepcopy
from datetime import datetime
from functools import reduce
from itertools import chain, product
import re
from typing import Optional
from uuid import UUID

from django.apps import apps
from django.db.models import Exists, F, Q, OuterRef, Subquery
from django.utils.dateparse import parse_date, parse_datetime
from django.utils.timezone import make_aware, is_naive
from rest_framework.serializers import ValidationError

from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes


def flatten(list_of_lists):
    """Flatten one level of nesting"""
    return list(chain.from_iterable(list_of_lists))


##############################################################################
# OpenAPI parameter handling
##############################################################################


def validate_param_part(param, value):
    """
    Validate the value of a parameter, or part of a parameter, against the
    OpenAPI type definition.  This allows values in arrays to be checked.
    """
    name = param.name
    # print(f"validating {value} against {param} for {name}")
    if param.many:
        # param always has style attribute, but defaults to None
        if param.style is None:
            raise ValidationError(
                {name: "Coding error: parameter has many=True but no 'style' set"}
            )
        # Parameters in different locations are split in different ways - ugh
        splitter_for = {
            OpenApiParameter.PATH: {'simple': ',', 'label': '.', 'matrix': ';'},
            OpenApiParameter.QUERY: {'form': ',', 'spaceDelimited': ' ', 'pipeDelimited': '|'}
        }
        if param.location not in splitter_for:
            raise ValidationError(
                f"Coding error: We do not know how to split parameters in the '{param.location}'"
            )
        if param.style not in splitter_for[param.location]:
            raise ValidationError(
                f"Coding error: Invalid {param.location} array parameter style '{param.style}'"
            )
        split_chr = splitter_for[param.location][param.style]
        if isinstance(value, str):
            values = value.split(split_chr)
        elif isinstance(value, list):
            values = flatten(map(lambda s: s.split(split_chr), value))
        else:
            values = [value]
        # Check the list with the basic type of this variable
        basic_param = deepcopy(param)
        basic_param.many = False
        basic_param.style = None
        return [validate_param_part(basic_param, v) for v in values]
    else:
        if param.style:
            # Parameters with 'many=False' probably shouldn't have their style
            # property set.  Will the warning be read though?
            raise ValidationError(
                f"Coding error: parameter has many=False but style={param.style}"
            )

    # Handle any Pythonic type conversions first
    if param.type == OpenApiTypes.BOOL:
        # Booleans don't do any further processing, so exit now
        return str(value).lower() in ('true', '1', 'yes')
    elif param.type in (OpenApiTypes.INT, OpenApiTypes.INT32, OpenApiTypes.INT64):
        try:
            value = int(value)
        except ValueError:
            raise ValidationError(
                {name: "The value must be an integer"}
            )
    elif param.type in (OpenApiTypes.NUMBER, OpenApiTypes.DOUBLE, OpenApiTypes.FLOAT):
        # Should this check for FORMAT_FLOAT and FORMAT_DOUBLE?
        try:
            value = float(value)
        except ValueError:
            raise ValidationError(
                {name: "The value must be a floating point number"}
            )
    elif param.type == OpenApiTypes.REGEX:
        if not re.match(param.pattern, value):
            raise ValidationError(
                {name: f"The value did not match the pattern '{param.pattern}'"}
            )
    elif param.type == OpenApiTypes.DATE:
        try:
            # datetime.date objects cannot be timezone aware, so they
            # have to be converted into datetimes.  Haven't found a better
            # way of doing this:
            value = make_aware(datetime.fromordinal(parse_date(value).toordinal()))
        except (ValueError, AttributeError):
            raise ValidationError(
                {name: "The value did not look like a date"}
            )
    elif param.type == OpenApiTypes.DATETIME:
        value = parse_datetime(value)
        if value is None:
            raise ValidationError(
                {name: "The value did not look like a datetime"}
            )
        if is_naive(value):
            value = make_aware(value)
    elif param.type == OpenApiTypes.UUID:
        try:
            value = UUID(value)
        except ValueError:
            raise ValidationError(
                {name: "The value must be a UUID"}
            )
    # The other param types don't need value conversion

    # Check enumeration
    if hasattr(param, 'enum') and param.enum:
        if value not in param.enum:
            raise ValidationError(
                {name: f"The value is required to be "
                f"one of the following values: {', '.join(map(str, param.enum))}"}
            )

    # OK, validation has passed, return the value here
    return value


def value_of_param(param, request):
    """
    Return the value of the given parameter in the request.

    If the parameter is not found in the request, this returns the
    parameter's default value, if it has one, or None.

    Otherwise, the parameter is converted to the correct Python type, its
    value is validated, and arrays are parsed.
    """
    if param.name not in request.query_params:
        if param.required:
            raise ValidationError(
                {param.name: "Required parameter"}
            )
        # Parameter not supplied, return the default or None - but
        # param may not have default attribute, so...
        default = getattr(param, 'default', None)
        if default is None:
            return None
        # The parameter default value must be in the format specified by the
        # parameter - e.g. if a CSV list, then `value,value`.
        try:
            return validate_param_part(param, default)
        except TypeError:
            raise TypeError(
                f"Parameter {param.name} default parameter {param.default} "
                f"needs to be in serialized format"
            )

    values = request.query_params.getlist(param.name)
    # ADVISOR-3047 - need to rely on whether the parameter takes many values
    # rather than whether the value was given.
    if len(values) > 1 and not param.many:
        raise ValidationError(
            {param.name: "Parameter must only be given a single value"}
        )
    if not param.many:
        return validate_param_part(param, values[0])
    return flatten([validate_param_part(param, v) for v in values])


def filter_on_param(query_field, param, request, value_map=None):
    """
    Provide a Django Q object to filter on a field matching a given parameter,
    if it's found in the request.  If the parameter is not specified in the
    request, an empty Q object is returned (which does not change the filter).

    Parameters:
        - query_field: the field in the filtered queryset which will match
          the parameter's value (including through relations)
        - param: an OpenAPI parameter definition of the parameter
        - request: the Django request object

    Returns:
        - a Q object to use in a filter on a queryset.

    Examples:

        # A simple filter on the name field
        qs = Model.objects.filter(
            filter_on_param('name', name_param, request)
        )
    """
    param_value = value_of_param(param, request)
    # If no parameter in request, and no default value, then no changes to
    # queryset.
    if param_value is None:
        return Q()
    if value_map:
        # Note: if you want to have a mapping here, then make sure you use an
        # enum in your parameter definition to validate the incoming value as
        # one of your map entries.  That's a much better way of reporting
        # errors to the user than throwing a KeyError here!
        if param.many:
            param_value = [value_map[v] for v in param_value]
        else:
            param_value = value_map[param_value]

    if isinstance(param_value, list):
        # Queries such as 'tags__contains' can't use '__in', so we have to
        # OR a list of Q objects together.  Theoretically this isn't much
        # slower.
        return Q(reduce(lambda l, r: l | r, (
            Q(**{query_field: v})
            for v in param_value
        )))
    return Q(**{query_field: param_value})


def filter_multi_param(
    request, filter_prefix, param_name='filter', field_prefix=None,
    use_contains_for_eq=True
):
    """
    Find a parameter starting with the given param_name (= 'filter') and
    subsequent square-bracketed filter parts, and return a Q() expression
    that filters on that structured value within that field (or the parameter
    name as a field if no field is given).  All parts within square brackets
    must be word-characters - i.e. `[A-Za-z0-9_]+`.

    As an example, this will match query parameters like:

    1. `system_profile[sap_system]=true`
    2. `system_profile[cpu_flags][contains]=clzero`
    3. `system_profile[system_memory_bytes][gt]=4000000000`

    And produce a filter equivalent to:

    1. `system_profile__sap_system=True`
    2. `system_profile__cpu_flags__contains='clzero'`
    3. `system_profile__system_memory_bytes__gt=4000000000`

    Note that for the `gt`, `gte`, `lt` and `lte` operators the value is
    converted to a number, and the special values '`true`', '`True`',
    '`false`' and '`False`' are converted to Python `True` and `False`
    boolean values respectively. Numbers do not match strings in JSON value
    introspection, so `system_profile[number_of_sockets]=1` will convert to
    the filter `system_profile__number_of_sockets='1'` and will not match a
    record where number of sockets is the number `1`.  A value that is wholly
    digits will be converted to an integer if the 'eq' or 'ne' operators are
    given, so `system_profile[number_of_sockets][eq]=1` will match an integer
    number of sockets value.

    All these would be matched by an OpenApiParameter with the name
    `system_profile`.  If more than one of these parameter constructions
    appears in the parameters supplied, these will be ANDed together in the
    returned filter.

    The operators supported are based on:

    https://github.com/RedHatInsights/insights-api-common-rails#usage

    NOTE: also, because we don't attempt to bar any other comparator, because
    they might also be a key in a dictionary, this also allows us to accept
    all standard Django filter operators.  E.g. we accept both 'starts_with'
    and 'startswith'.

    There's a particular caveat with the `ne` operator querying JSON objects:
    the equality comparator will not return False if the field does not exist
    in the JSON object.  So a filter [system_profile][host_type][eq]=edge
    (which translates to the SQL `system_profile -> 'host_type' = 'edge')
    will work, but [host_type][ne]=edge (which translates to the SQL
    `NOT (system_profile -> 'host_type' = 'edge')` will not return the systems
    with no 'host_type' record.

    To achieve this, we have to do a more subtle comparison that uses
    PostgreSQL's JSON '@>' operator, which tests that the JSON field contains
    a given structure.  This rephrases the `eq` and `ne` operators into
    variations of the `field__contains={'key': 'value'}` query expression.
    Since this works for both equality and inequality, and it may be faster,
    we use this when either of those operators is invoked specifically.  If
    you _don't_ want this behaviour and simply want to use the `field__key=value`
    construction, set the **`use_contains_for_eq`** option to `False`.

    This is roughly compliant with OpenAPI 3's 'deepObject' object parameter
    style, but OpenAPI 2 does not recognise them at all and there is no way
    to express such a parameter in OpenAPI 2.  Therefore, we do not use or
    provide an OpenAPI 'Parameter' object to include in the parameter spec.
    """
    end_filter = Q()
    # Prefix, one or more square-bracketed words, and an optional '[]'
    fre = re.compile(r'^(?P<prefix>\w+)(?P<brackets>(?:\[\w+\])+)(?:\[\])?$')
    comparator_translations = {
        'eq_i': 'iexact', 'contains_i': 'icontains',
        'starts_with_i': 'istartswith', 'ends_with_i': 'iendswith',
        'starts_with': 'startswith', 'ends_with': 'endswith'
    }

    def csv_list(l):
        return [
            value
            for item in l
            for value in item.split(',')
        ]

    param_prefix = param_name + '[' + filter_prefix + ']['
    for this_param, param_list in request.query_params.lists():
        # We only want to report invalid parameters for ones we care about.
        # Other filter parameters may have some new weird syntax we don't
        # understand.  So we're specific as possible with this direct match.
        if not this_param.startswith(param_prefix):
            continue
        m = fre.match(this_param)
        # We matched the param_prefix but not the regex - parameter is mangled
        if not m:
            raise ValidationError(
                {param_name: "The parameter is incorrectly formatted"}
            )
        filter_parts = m.group('brackets')[1:-1].split('][')

        # Handle workloads field redirection for schema compatibility
        if filter_prefix == 'system_profile' and len(filter_parts) >= 2:
            field_name = filter_parts[1]
            if field_name == 'sap_system':
                filter_parts = [filter_prefix, 'workloads', 'sap'] + filter_parts[1:]
            elif field_name == 'sap_sids':
                filter_parts = [filter_prefix, 'workloads', 'sap', 'sids'] + filter_parts[2:]
            elif field_name in ('ansible', 'mssql'):
                filter_parts = [filter_prefix, 'workloads'] + filter_parts[1:]

        # Keep the filter prefix here though
        operator = filter_parts[-1]
        # Convert comparator if necessary
        filter_not_equal = False
        filter_contains_field = None
        if operator == 'eq':
            filter_parts.pop()  # remove 'eq'
        elif operator == 'ne':
            filter_not_equal = True
            filter_parts.pop()  # remove 'ne'
        if use_contains_for_eq and operator in ('eq', 'ne'):
            # The new filter is: contains {the last filter field: value}
            filter_contains_field = filter_parts.pop()
            filter_parts.append('contains')
        if operator in {'nil', 'not_nil'}:
            # Now replace the actual last filter part
            filter_parts[-1] = 'isnull'
        if operator in comparator_translations:
            filter_parts[-1] = comparator_translations[operator]
            # Join it all together in a filter with (field_prefix__)filter_parts=value
        if field_prefix is not None:
            filter_parts.insert(0, field_prefix)
        # Operator 'in' needs the whole list of values
        if operator == 'in':
            # Also convert multiple comma-separated values into a flat list.
            this_filter = Q(**{'__'.join(filter_parts): csv_list(param_list)})
            end_filter = end_filter & this_filter
            continue
        # Iterate through values of this parameter
        for param_value in param_list:
            # Convert value type if necessary
            if param_value in {'true', 'True', 'false', 'False'}:
                param_value = param_value in {'true', 'True'}
            if operator in ('gt', 'gte', 'lt', 'lte'):
                if param_value.isdigit():
                    param_value = int(param_value)
                else:
                    raise ValidationError(
                        {param_name: "Value must be an integer when "
                        "given the 'gt', 'gte', 'lt' or 'lte' operators"}
                    )
            elif operator in ('eq', 'ne') and param_value.isdigit():
                # Special case to support direct numeric comparisons
                param_value = int(param_value)
            if filter_contains_field:  # set above
                # The new filter is: contains {the last filter field: value}
                param_value = {filter_contains_field: param_value}
            if operator in {'nil', 'not_nil'}:
                # If we haven't been given true or false, just assume true.
                if not isinstance(param_value, bool):
                    param_value = True
                if operator == 'not_nil':
                    param_value = not param_value
            this_filter = Q(**{'__'.join(filter_parts): param_value})
            # Invert Q sense if `__ne`.
            if filter_not_equal:
                this_filter = ~this_filter
            # Add it to the expression
            end_filter = end_filter & this_filter

    return end_filter


##############################################################################
# Commonly used parameters
##############################################################################

# Note: it's best to keep parameters defined locally.  These parameters and
# their associated filters are used across several parts of the API, so they
# need to be common.  Then, consider importing that parameter and filter from
# the main view that defines them.  Once you get a parameter that is used in
# too many places, or is used in models.py, then put it in here.

# Also: these should be kept in alphabetical order to make them easy to find.

branch_id_param = OpenApiParameter(
    name='branch_id', type=OpenApiTypes.UUID, location=OpenApiParameter.QUERY,
    description="Select hosts owned by this Satellite ID",
    required=False,
)


category_query_param = OpenApiParameter(
    name='category', location=OpenApiParameter.QUERY,
    description="Filter rules of this category (number)",
    required=False,
    # When Django is doing testing, the database is new and the fixtures
    # haven't been loaded, so trying to use a query to get these values
    # fails at that point.  Is there a way to resolve these at parameter
    # check time rather than during declaration?
    many=True, type=OpenApiTypes.INT, enum=(1, 2, 3, 4), style='form',
)

display_name_query_param = OpenApiParameter(
    name='display_name', location=OpenApiParameter.QUERY,
    description="Display systems with this text in their display_name",
    required=False, type=OpenApiTypes.STR,
)


filter_system_profile_sap_system_query_param = OpenApiParameter(
    name='filter[system_profile][sap_system]', location=OpenApiParameter.QUERY,
    description='Is this a SAP system?',
    required=False, type=OpenApiTypes.BOOL,
)


filter_system_profile_ansible_query_param = OpenApiParameter(
    name='filter[system_profile][ansible]', location=OpenApiParameter.QUERY,
    description='Is this an Ansible system?',
    required=False, type=OpenApiTypes.BOOL,
)


filter_system_profile_mssql_query_param = OpenApiParameter(
    name='filter[system_profile][mssql]', location=OpenApiParameter.QUERY,
    description='Is this a Microsoft SQL system?',
    required=False, type=OpenApiTypes.BOOL,
)


filter_system_profile_sap_sids_contains_query_param = OpenApiParameter(
    name='filter[system_profile][sap_sids][contains]',
    location=OpenApiParameter.QUERY,
    description='Are there systems which contain these SAP SIDs?',
    required=False,
    # According to https://answers.sap.com/questions/3161029/sid.html
    # SAP SIDs are three character codes, starting with a letter.
    # I'm not going to try and exclude the keywords...
    style='form', many=True, type=OpenApiTypes.REGEX, pattern=r'^[A-Z]..$',
)


has_disabled_recommendation_query_param = OpenApiParameter(
    name='has_disabled_recommendation', location=OpenApiParameter.QUERY,
    description="Display systems which has at least one disabled recommendation",
    required=False, type=OpenApiTypes.BOOL,
)


hits_query_param = OpenApiParameter(
    name='hits', location=OpenApiParameter.QUERY,
    description="Display systems with hits of the given total_risk value (1..4), or 0 to display all systems",
    required=False, style='form', many=True,
    type=OpenApiTypes.STR, enum=('all', 'yes', 'no', '1', '2', '3', '4'),
)


host_group_name_query_param = OpenApiParameter(
    name='groups', location=OpenApiParameter.QUERY, required=False,
    description='List of Inventory host group names',
    style='form', many=True, type=OpenApiTypes.STR
)


host_id_query_param = OpenApiParameter(
    name='uuid', location=OpenApiParameter.QUERY,
    description="Display a system with this uuid",
    required=False, type=OpenApiTypes.STR,
)


host_tags_query_param = OpenApiParameter(
    name='tags', type=OpenApiTypes.REGEX, location=OpenApiParameter.QUERY,
    pattern=r'^[^/=]+/[^/=]+=[^/=]+$',
    description="Tags have a namespace, key and value in the form namespace/key=value",
    required=False, many=True, style='form',
)


incident_query_param = OpenApiParameter(
    name='incident', location=OpenApiParameter.QUERY,
    description="Display only systems reporting an incident",
    required=False, type=OpenApiTypes.BOOL,
)


pathway_query_param = OpenApiParameter(
    name='pathway', location=OpenApiParameter.QUERY,
    description="Display systems with rule hits for this Pathway",
    required=False, type=OpenApiTypes.STR,
)


required_branch_id_param = OpenApiParameter(
    name='branch_id', type=OpenApiTypes.UUID, location=OpenApiParameter.QUERY,
    description="Select hosts owned by this Satellite ID",
    required=True,
)


rhel_version_query_param = OpenApiParameter(
    name='rhel_version', location=OpenApiParameter.QUERY,
    description='Display only systems with these versions of RHEL',
    required=False, many=True, type=OpenApiTypes.STR, style='form',
    enum=(
        '10.0', '10.1', '10.2',
        '9.0', '9.1', '9.2', '9.3', '9.4', '9.5', '9.6', '9.7', '9.8',
        '8.0', '8.1', '8.2', '8.3', '8.4', '8.5', '8.6', '8.7', '8.8', '8.9', '8.10',
        '7.0', '7.1', '7.2', '7.3', '7.4', '7.5', '7.6', '7.7', '7.8', '7.9', '7.10',
        '6.0', '6.1', '6.2', '6.3', '6.4', '6.5', '6.6', '6.7', '6.8', '6.9', '6.10',
    )
)


rule_id_query_param = OpenApiParameter(
    name='rule_id', location=OpenApiParameter.QUERY,
    description="Display systems with this text in their rule_id",
    required=False, type=OpenApiTypes.STR,
)


system_type_query_param = OpenApiParameter(
    name='system_type', location=OpenApiParameter.QUERY,
    description="Display only systems with this type ('all' = both types)",
    required=False, type=OpenApiTypes.STR, enum=('all', 'edge', 'conventional', 'bootc'),
)


systems_detail_name_query_param = OpenApiParameter(
    name='name', location=OpenApiParameter.QUERY,
    required=False, type=OpenApiTypes.STR,
    description="Search for systems that include this in their display name",
)


topic_query_param = OpenApiParameter(
    name='topic', location=OpenApiParameter.QUERY,
    description="Display rules in this topic (slug)",
    required=False,
    type=OpenApiTypes.REGEX, pattern=r'[\w-]+',
    # See note for enums in category list as to why we can't populate the
    # topics with a query.
)


update_method_query_param = OpenApiParameter(
    name='update_method', location=OpenApiParameter.QUERY,
    required=False, many=True, style='form', type=OpenApiTypes.STR,
    description="Search for systems with this updater type",
    enum=('ostree', 'dnfyum')
)


##############################################################################
# Commonly used filters
##############################################################################

def filter_on_branch_id(request, relation=''):
    """
    Respond with a Q object which will filter a queryset based on a relation
    to the Host model and it's `branch_id` field.
    """
    branch_id_value = value_of_param(branch_id_param, request)
    if relation:
        relation += '__'
    if branch_id_value:
        return Q(**{relation + 'branch_id': branch_id_value})
    else:
        return Q()


def filter_on_display_name(request, relation='', param=display_name_query_param):
    """
    Filter systems on display name.  If the queryset has the 'display_name'
    field, leave the relation blank; otherwise supply the Django relation
    to that queryset.
    """
    display_name = value_of_param(param, request)
    if not display_name:
        return Q()
    if relation:
        relation += '__'
    return Q(**{relation + 'display_name__icontains': display_name})


def filter_on_has_disabled_recommendation(request, param=has_disabled_recommendation_query_param):
    """
    Filter systems which has at least one disabled recommendation.
    """
    param_value = value_of_param(param, request)
    if param_value is None:
        return Q()

    # Need to import this here to avoid circular import error
    from api.permissions import request_to_org

    # Getting HostAck using apps.get_model to avoid circular import error
    HostAck = apps.get_model('api', 'HostAck')
    # Small extra note here: we're relying on the inventory UUID being unique
    # to avoid having to check the org_id of HostAcks here.
    hostacks = HostAck.objects.filter(host__inventory=OuterRef('pk'))
    # To find whether this host has any system-wide Acks, we need to ask
    # 'are there any current reports of acked rules for this host?'.  So for
    # that we _do_ need the org_id...
    CurrentReport = apps.get_model('api', 'CurrentReport')
    org_id = request_to_org(request)
    acks = CurrentReport.objects.filter(
        inventory=OuterRef('pk'), rule__ack__org_id=org_id
    )

    condition = Q(Exists(hostacks) | Exists(acks))
    return condition if param_value else ~condition


hit_types = {
    'all': Q(),  # Display all systems - with and without hits
    'yes': Q(hits__gt=0),  # Only display systems with hits
    'no': Q(hits__exact=0),  # Only display systems without hits
    '4': Q(critical_hits__gt=0),  # Display systems with critical risk hits
    '3': Q(important_hits__gt=0),  # Display systems with important risk hits
    '2': Q(moderate_hits__gt=0),  # Display systems with moderate risk hits
    '1': Q(low_hits__gt=0),  # Display systems with low risk hits
}


def filter_on_hits(request):
    """
    if hits == 'all' or no param: show all systems (with or without hits)
    if hits == 'yes': only show systems with hits
    if hits == 'no': show systems with no hits
    if hits == '4'..'1': show systems with critical, important, moderate, low hits (or'ed together if multiple)
    """
    hits = value_of_param(hits_query_param, request)
    if hits:
        # Look for either 'all', 'yes' or 'no' first and if found return that filter by itself
        special_type = [i for i in ('all', 'yes', 'no') if i in hits]
        if special_type:
            return hit_types[special_type[0]]

        # otherwise build a query filter from the specified hit_type number(s)
        query = None
        for hit_type in hits:
            query = query | hit_types[hit_type] if query else hit_types[hit_type]
        return query
    else:
        return Q()


def filter_on_host_id(request, relation='', param=host_id_query_param):
    """
    Filter systems on inventory host uuid.  If the queryset has the 'uuid'
    field, leave the relation blank; otherwise supply the Django relation
    to that queryset.
    """
    host_id = value_of_param(param, request)
    if not host_id:
        return Q()
    if relation:
        relation += '__'
    return Q(**{relation + 'host': host_id})


def filter_on_host_tags(request, field_name='host_id'):
    host_tags = value_of_param(host_tags_query_param, request)

    if not host_tags:
        return Q()

    def unescape(token):
        return token.replace('%2F', '/').replace('%3D', '=')

    tag_query = Q()
    for tag in host_tags:

        namespace, key_and_value = tag.split('/')
        key, value = key_and_value.split('=')

        namespace = unescape(namespace)
        key = unescape(key)
        value = unescape(value)

        tag_query &= Q(tags__contains=[{"namespace": namespace, "key": key, "value": value}])

    # Add org_id to the filter for partition pruning
    # Need to import this here to avoid circular import error
    from api.permissions import request_to_org

    org_id = request_to_org(request)

    if org_id:
        tag_query &= Q(org_id=org_id)

    # Getting InventoryHost via apps to avoid circular import on models
    InventoryHost = apps.get_model('api', 'InventoryHost')
    return Q(**{field_name + '__in': Subquery(
         InventoryHost.objects.filter(tag_query).values('id')
    )})


def filter_on_system_type(request):
    """
    Filter on the host_type field (currently within system_profile).
    """
    system_type = value_of_param(system_type_query_param, request)
    # relation='' ?
    if system_type is None or system_type == 'all':
        return Q()
    elif system_type == 'edge':
        return Q(system_profile__host_type='edge')
    elif system_type == 'bootc':
        return Q(system_profile__bootc_status__isnull=False)
    elif system_type == 'conventional':
        return Q(system_profile__host_type__isnull=True)


def filter_on_incident(request):
    # Filter for just a specific 'incident' tag (or absence thereof)
    incident_param = value_of_param(incident_query_param, request)
    if incident_param is None:
        return Q()
    elif incident_param:
        return Q(incident_hits__gt=0)
    else:
        return Q(incident_hits=0)


def filter_on_rhel_version(request, relation: Optional[str] = None):
    versions = value_of_param(rhel_version_query_param, request)
    # Based on InventoryHost so look up directly
    version_filter = Q()
    if versions is None:
        return version_filter

    base_parameter = 'system_profile__operating_system'
    if relation:
        base_parameter = f"{relation}__{base_parameter}"
    for version in versions:
        # Assertion: our parameters always have 'major.minor', and those are
        # always ints.
        major, minor = map(int, version.split('.'))
        major_param = f"{base_parameter}__major"
        minor_param = f"{base_parameter}__minor"
        version_filter |= Q(**{
            major_param: major, minor_param: minor,
        })
    return version_filter


def filter_on_topic(request, relation: Optional[str] = None):
    topic_param = value_of_param(topic_query_param, request)
    if topic_param:
        # Note: this will produce duplicates if a topic has more than one
        # tag, and a rule has more than one of those tags.
        base_parameter = 'tags__topic__slug'
        if relation is not None:
            base_parameter = f"{relation}__{base_parameter}"
        return Q(**{base_parameter: topic_param})
    else:
        return Q()


def filter_on_update_method(request, relation: Optional[str] = None):
    update_methods = value_of_param(update_method_query_param, request)
    if not update_methods:
        return Q()
    # If we've got every single updater type, we don't need to filter.
    if all(value in update_methods for value in update_method_query_param.enum):
        return Q()
    update_method_filter = Q()
    base_parameter = 'system_profile__system_update_method'
    if relation:
        base_parameter = f"{relation}__{base_parameter}"
    if 'ostree' in update_methods:
        update_method_filter |= Q(**{base_parameter: 'rpm-ostree'})
    if 'dnfyum' in update_methods:
        update_method_filter |= Q(**{base_parameter + '__in': ('dnf', 'yum')})
    return update_method_filter


#######################################################
# Sort field handling
#######################################################


def sort_param_enum(fields):
    """
    Return the list of sort field values along with their reversed direction
    alternatives.  If `fields` is a dict, we use the keys from that map.
    Each field is listed, then its sort reversed alternative, then the next
    field, and so on.
    """
    # return list(sort_field_map.keys()) + ['-' + k for k in sort_field_map.keys()]
    field_list = fields.keys() if isinstance(fields, dict) else fields
    return list(map(''.join, map(reversed, product(field_list, ('', '-')))))


def sort_params_to_fields(param_value, field_map={}, reverse_nulls_order=False):
    """
    Change the list of sort parameters into a set of F expressions with sort
    ordering, for an order_by expression.

    `param_value` is either a single value of a sort parameter, or a list of
    values from the sort parameter.  This should basically be able to take
    the output of `value_of_param(sort_field, request)` whether your sort
    parameter is defined as a csv-form list or a single value.

    If the value has '-' in front of it, the field is sorted in reverse
    order.  In forward order, nulls are sorted first; in reverse order, nulls
    are sorted last.

    `field_map` is a dictionary keyed on the sort field value with the value
    of the actual field in the model's relationships being sorted on.  This
    allows you to sort on related fields (e.g. `inventory__display_name`)
    without using long names or giving away the table structure.  If the
    sort field is not in the field map, then the sort field value is used -
    which means the field map only needs to be the 'exceptions'.

    `reverse_nulls_order` inverts if nulls are placed at the start or end of the list of OSes.
    If null OS values are replaced with 'Unknown OS ...', then this should sort last alphabetically
    when using ASC order, and first when using DESC order.

    It returns a list of F() values.

    To put it another way, these are the operations:
      1. if the param_value is a single string, turn that into a list
      2. iterate through all the param_values:
      3. if the value starts with '-', this parameter will be sorted in reverse
      4. if the value is in the field map, replace it with the map value
      5. construct an F() expression for this value in the chosen sort direction
    """
    if not isinstance(param_value, list):
        param_value = [param_value]

    # For some reason Django 5+ now doesn't accept 'False' as a value for
    # nulls_first or nulls_last, so we have to give them this little oddity...
    null_sort = True if not reverse_nulls_order else None

    def field_to_F(field, is_desc=False):
        return (
            F(field).desc(nulls_last=null_sort)
            if is_desc
            else F(field).asc(nulls_first=null_sort)
        )

    def map_and_expand(sort_param):
        is_desc = sort_param[0] == '-'
        if is_desc:
            sort_param = sort_param[1:]
        if sort_param in field_map:
            if isinstance(field_map[sort_param], list):
                for field in field_map[sort_param]:
                    yield field_to_F(field, is_desc)
            else:
                yield field_to_F(field_map[sort_param], is_desc)
        else:
            # sort params by themselves can't be lists
            yield field_to_F(sort_param, is_desc)

    return chain.from_iterable(
        map_and_expand(sort)
        for sort in param_value
    )
