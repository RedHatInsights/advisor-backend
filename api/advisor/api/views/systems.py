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

from django.utils.decorators import method_decorator

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import (
    value_of_param, host_tags_query_param, system_type_query_param,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    filter_system_profile_mssql_query_param,
    filter_system_profile_ansible_query_param,
    pathway_query_param, display_name_query_param,
    hits_query_param, incident_query_param, rhel_version_query_param,
    sort_params_to_fields, sort_param_enum, host_group_name_query_param,
    update_method_query_param, has_disabled_recommendation_query_param,
)
from api.models import (
    InventoryHost, get_systems_queryset, get_reports_subquery
)
from api.permissions import ResourceScope
from api.serializers import ReportSerializer, SystemSerializer
from api.utils import (
    CustomPageNumberPagination, PaginateMixin,
)

sort_fields = [
    'hits', 'last_seen', 'display_name', 'rhel_version', 'group_name',
    'critical_hits', 'important_hits', 'moderate_hits', 'low_hits'
]
sort_field_map = {
    'rhel_version': [
        'system_profile__operating_system__major',
        'system_profile__operating_system__minor'
    ],
    'group_name': 'groups__0__name',
}
sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    description="Order by this field",
    required=False,
    type=OpenApiTypes.STR, enum=sort_param_enum(sort_fields),
    default='-hits'
)


@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="Retrieve the reports for a single system",
        description="Retrieve the reports for a single system by Insights Inventory UUID",
    )
)
class SystemViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    List systems, or retrieve a system by UUID.

    param: uuid: The system's Host ID in the Inventory
    param: uuid type: STRING
    """
    lookup_field = 'id'
    lookup_url_kwarg = 'uuid'
    pagination_class = CustomPageNumberPagination
    queryset = InventoryHost.objects.all()
    resource_name = 'recommendation-results'
    resource_scope = ResourceScope.WORKSPACE
    serializer_class = SystemSerializer

    def get_queryset(self):
        # Used in export systems as well
        return get_systems_queryset(self.request)

    @extend_schema(
        parameters=[
            sort_query_param, display_name_query_param, host_tags_query_param,
            hits_query_param, filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            incident_query_param, rhel_version_query_param, pathway_query_param,
            host_group_name_query_param, update_method_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
            has_disabled_recommendation_query_param,
            system_type_query_param,
        ],
    )
    def list(self, request, format=None):
        """
        Returns systems with their hit count and last upload time.

        Results can be sorted and systems can be filtered by display name and hits
        """
        sort_fields = sort_params_to_fields(
            value_of_param(sort_query_param, request),
            sort_field_map
        )
        systems = self.get_queryset().order_by(*sort_fields, 'id')

        return self._paginated_response(systems, request)

    @extend_schema(
        parameters=[
            host_tags_query_param, filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            host_group_name_query_param, update_method_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
            system_type_query_param,
        ],
        responses={200: ReportSerializer(many=True)}
    )
    @action(detail=True, pagination_class=None)
    # @set_resource(scope=ResourceScope.HOST)  - needed for Kessel?
    def reports(self, request, uuid, format=None):
        """
        Returns the list of latest reports for an Inventory Host ID.

        Returns reports that:
         * are in the user's account
         * have an active, not-deleted rule
         * where the rule has not been acked by this account

        If the host ID is not found, return an empty list.
        """
        active_reports = get_reports_subquery(
            request, host_id=uuid, use_joins=True
        ).select_related(
            'rule__category', 'rule__impact', 'rule__ruleset',
        ).prefetch_related(
            'rule__resolution_set', 'rule__resolution_set__playbook_set',
            'rule__resolution_set__resolution_risk',
        ).order_by('rule_id')  # One report per rule for this system.

        return Response(ReportSerializer(
            active_reports, many=True, context={'request': request}
        ).data)
