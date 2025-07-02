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

from django.shortcuts import get_object_or_404
from django.db.models import Q, Subquery

from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import (
    value_of_param, filter_on_param, host_tags_query_param,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    filter_system_profile_mssql_query_param,
    filter_system_profile_ansible_query_param,
    category_query_param, host_group_name_query_param,
    update_method_query_param,
)
from api.models import Pathway, Resolution
from api.permissions import InsightsRBACPermission, ResourceScope
from api.serializers import (
    PathwaySerializer, SystemSerializer,
    RuleForAccountSerializer, RuleSystemsExportSerializer,
)
from api.utils import (
    PaginateMixin, CustomPageNumberPagination,
)


all_sort_fields = [
    'impacted_systems_count', 'name', 'recommendation_level'
]

sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    description="Order by this field",
    required=False,
    type=OpenApiTypes.STR,
    enum=all_sort_fields + ['-' + k for k in all_sort_fields],
    default='name'
)
impacting_query_param = OpenApiParameter(
    name='impacting', location=OpenApiParameter.QUERY,
    description="Display pathways even if they aren't impacting systems currently",
    required=False,
    type=OpenApiTypes.BOOL,
    default=True
)
reboot_required_filter_param = OpenApiParameter(
    name='reboot_required', location=OpenApiParameter.QUERY,
    description="Display only pathways where reboot is required.",
    required=False,
    type=OpenApiTypes.BOOL,
)
has_incident_filter_param = OpenApiParameter(
    name='has_incident', location=OpenApiParameter.QUERY,
    description="Display only pathways where there are incidents.",
    required=False,
    type=OpenApiTypes.BOOL,
)
text_query_param = OpenApiParameter(
    name='text', location=OpenApiParameter.QUERY,
    description="Filter pathway names with this text. "
                "If viewing details for a pathway for rules, "
                "reports and systems, additional filter on their text fields",
    required=False,
    type=OpenApiTypes.STR,
)
rule_id_param = OpenApiParameter(
    name='rule_id', location=OpenApiParameter.QUERY,
    description="Display Pathway Reports of this/these rules",
    required=False,
    many=True, type=OpenApiTypes.REGEX, pattern=r'\w+(,\w+)*', style='form',
)
host_id_param = OpenApiParameter(
    name='host_id', location=OpenApiParameter.QUERY,
    description="Display Pathway Reports of this/these systems",
    required=False,
    many=True, type=OpenApiTypes.REGEX, pattern=r'\w+(,\w+)*', style='form',
)


def filter_on_text_pathway(request):
    # Filter on text search on all text fields
    srch = value_of_param(text_query_param, request)
    if srch:
        return Q(name__icontains=srch)
    else:
        return Q()


def filter_on_text_report(request):
    # Filter on text search on all text fields
    srch = value_of_param(text_query_param, request)
    if srch:
        # Thanks, Flake8, for not allowing wrapping of binary operators
        # Also note that any joins here may affect the number of results
        # found in annotations.
        return \
            Q(rule__pathway__name__icontains=srch) | \
            Q(rule__rule_id__icontains=srch) | \
            Q(rule__description__icontains=srch) | \
            Q(rule__summary__icontains=srch) | \
            Q(rule__generic__icontains=srch) | \
            Q(rule__reason__icontains=srch) | \
            Q(rule__more_info__icontains=srch) | \
            Q(rule__id__in=Subquery(
                Resolution.objects.filter(
                    resolution__icontains=srch
                ).values('rule_id')
            ))
    else:
        return Q()


def filter_on_text_rule(request):
    # Filter on text search on all text fields
    srch = value_of_param(text_query_param, request)
    if srch:
        # Thanks, Flake8, for not allowing wrapping of binary operators
        # Also note that any joins here may affect the number of results
        # found in annotations.
        return \
            Q(rule_id__icontains=srch) | \
            Q(description__icontains=srch) | \
            Q(summary__icontains=srch) | \
            Q(generic__icontains=srch) | \
            Q(reason__icontains=srch) | \
            Q(more_info__icontains=srch) | \
            Q(id__in=Subquery(
                Resolution.objects.filter(
                    resolution__icontains=srch
                ).values('rule_id')
            ))
    else:
        return Q()


def filter_on_text_system(request):
    # Filter on text search on all text fields
    srch = value_of_param(text_query_param, request)
    if srch:
        # Thanks, Flake8, for not allowing wrapping of binary operators
        # Also note that any joins here may affect the number of results
        # found in annotations.
        return \
            Q(display_name__icontains=srch)
    else:
        return Q()


class PathwayViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    Gets the pathway(s) for rules

    This allows us to look up all Pathways
    for groups of rules, or retrieve specific details
    about Pathways such as all rules in a pathway,
    and impacted systems for pathways.

    param: slug: Slug for a Pathway.
    """
    queryset = Pathway.objects.all()  # purely for schema generation - overriden below
    permission_classes = [InsightsRBACPermission]
    lookup_field = 'slug'
    resource_name = 'recommendation-results'
    resource_scope = ResourceScope.ORG
    serializer_class = PathwaySerializer
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        impacting = value_of_param(impacting_query_param, self.request)
        query = Pathway.objects.for_account(self.request, impacting).filter(
                    filter_on_text_pathway(self.request)
                )
        return query

    @extend_schema(
        parameters=[
            host_tags_query_param, filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
            category_query_param, text_query_param, host_group_name_query_param,
            sort_query_param, impacting_query_param, reboot_required_filter_param,
            has_incident_filter_param,
        ],
        summary="Return all pathways",
    )
    def list(self, request, format=None):
        """
        This returns a list of all Pathways. Will display the same
        information as is provided in the retrieve view, but has all Pathways
        listed.
        """
        sort = value_of_param(sort_query_param, request)
        queryset = self.get_queryset().filter(
            filter_on_param('reboot_required', reboot_required_filter_param, request),
            filter_on_param('has_incident', has_incident_filter_param, request)
        ).order_by(sort, 'slug')
        return self._paginated_response(queryset, request)

    @extend_schema(
        parameters=[
            host_tags_query_param, filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
            category_query_param, text_query_param, host_group_name_query_param,
        ],
        summary="Returns an individual Pathway based on slug",
    )
    def retrieve(self, request, slug, format=None):
        """
        This returns an individual pathway based on slug.
        Will display the same information as is
        provided in the list view.
        """
        pathway = self.get_queryset().filter(slug=slug).first()
        if not pathway:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(PathwaySerializer(pathway,
                        many=False, context={'request': request}).data)

    @extend_schema(
        parameters=[
            host_tags_query_param, filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
            category_query_param, text_query_param, host_group_name_query_param,
            update_method_query_param,
        ],
        responses={200: SystemSerializer(many=True)},
        summary="Get all impacted systems for an account for a specific Pathway",
    )
    @action(detail=True, pagination_class=CustomPageNumberPagination)
    def systems(self, request, slug, format=None):
        """
        This view will retrieve/list in paginated
        format, all impacted systems for an account,
        for a specific Pathway. The specific Pathway
        is requested by its slug.
        """
        impacting = value_of_param(impacting_query_param, self.request)
        pathway_systems_query = Pathway.objects.for_account(self.request, impacting).distinct()
        pathway = get_object_or_404(pathway_systems_query, slug=slug)
        impacted_systems = pathway.impacted_systems(request).filter(
            filter_on_text_system(request)
        ).order_by('display_name')
        return self._paginated_response(impacted_systems, request,
                                        serializer_class=SystemSerializer)

    @extend_schema(
        parameters=[
            category_query_param, text_query_param,
        ],
        responses={200: RuleForAccountSerializer(many=True)},
        summary="Get all rules in a Pathway",
    )
    @action(detail=True, pagination_class=CustomPageNumberPagination)
    def rules(self, request, slug, format=None):
        """
        This view will retrieve/list in paginated
        format, all rules for a specific Pathway.
        This does not take into account acks
        or host asks. The Specific Pathway
        is requested by its slug
        """
        pathway = get_object_or_404(Pathway, slug=slug)
        rules = pathway.rules(request).filter(
            filter_on_text_rule(request),
            filter_on_param('category_id', category_query_param, request)
        )
        return self._paginated_response(rules, request, serializer_class=RuleForAccountSerializer)

    @extend_schema(
        parameters=[
            category_query_param, text_query_param, rule_id_param,
            host_id_param, host_group_name_query_param,
            update_method_query_param,
        ],
        responses={200: RuleSystemsExportSerializer()},
        summary="Get the list of systems for each rule in this pathway",
    )
    @action(detail=True)
    def reports(self, request, slug, format=None):
        """
        Each rule is listed once, with the systems currently reporting an
        incidence of that rule in a list.
        """
        pathway = get_object_or_404(Pathway, slug=slug)
        systems_for_rule = {}
        for report in pathway.get_reports(request).values(
            'rule__rule_id', 'host_id',
        ).filter(
            filter_on_text_report(request),
            filter_on_param('rule__rule_id', rule_id_param, request),
            filter_on_param('host_id', host_id_param, request)
        ).order_by('host_id'):
            if report['rule__rule_id'] in systems_for_rule:
                systems_for_rule[report['rule__rule_id']].append(report['host_id'])
            else:
                systems_for_rule[report['rule__rule_id']] = [report['host_id']]
        return Response(RuleSystemsExportSerializer(
            {'rules': systems_for_rule},
        ).data)
