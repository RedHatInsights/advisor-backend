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

from collections import OrderedDict

from django.db.models import Count, Q
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.reverse import reverse
from drf_spectacular.utils import extend_schema

from api.filters import (
    host_tags_query_param, filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    host_group_name_query_param,
)
from api.models import RuleCategory, get_reports_subquery
from api.permissions import (
    InsightsRBACPermission, CertAuthPermission, ResourceScope,
    request_object_for_testing,
)
from api.serializers import (
    StatsSerializer, OverviewStatsSerializer
)


def stats_counts(queryset, field_name):
    """
    Count the total number, and the number by risk and category, of distinct
    `field_name` values in the given queryset.
    """
    categories = RuleCategory.objects.values_list('name', flat=True)
    total_risks = (1, 2, 3, 4)

    annotations = {
        'total': Count(field_name, distinct=True),
    }
    for risk in total_risks:
        annotations[f'total_risk_{risk}'] = Count(
            field_name, filter=Q(rule__total_risk=risk), distinct=True
        )
    for categ in categories:
        annotations[f'total_category_{categ}'] = Count(
            field_name, filter=Q(rule__category__name=categ), distinct=True
        )
    annotations['incidents'] = Count(field_name, filter=Q(rule__tags__name='incident'), distinct=True)

    results = queryset.aggregate(**annotations)
    return {
        'total': results['total'],
        'total_risk': {
            risk: results[f'total_risk_{risk}']
            for risk in total_risks
        },
        'category': {
            categ: results[f'total_category_{categ}']
            for categ in categories
        },
        'incidents': results['incidents'],
    }


def overview_stats_counts(queryset):
    """
    Just get the pathways, and incidents, critical and important rule counts.
    """
    return queryset.aggregate(
        pathways=Count('rule__pathway', distinct=True),
        incidents=Count('rule', filter=Q(rule__tags__name='incident'), distinct=True),
        critical=Count('rule', filter=Q(rule__total_risk=4), distinct=True),
        important=Count('rule', filter=Q(rule__total_risk=3), distinct=True),
    )


# These get_*_stats functions are used by the weekly report emails for stats
# collection - they duplicate the code in the equivalent stats views.  The
# stats views have a complete request object, which contains the account
# details and may include host tag filtering; the weekly report emails only
# know the account org_id number and username.  The current_report_queryset function
# needs the request object to be able to filter on host tags.  So we use the
# request_object_for_testing function to make up a request object.  Ugly, but
# simpler than decoding the parameter everywhere and handing that in.
def get_rules_stats(org_id):
    request = request_object_for_testing(org_id=org_id)
    request.auth['org_id'] = org_id
    return stats_counts(get_reports_subquery(request), 'rule_id')


def get_reports_stats(org_id):
    request = request_object_for_testing(org_id=org_id)
    request.auth['org_id'] = org_id
    return stats_counts(get_reports_subquery(request), 'id')


def get_systems_stats(org_id):
    request = request_object_for_testing(org_id=org_id)
    request.auth['org_id'] = org_id
    return stats_counts(get_reports_subquery(request), 'host_id')


standard_parameters = [
    host_tags_query_param, host_group_name_query_param,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
]


class StatsViewSet(viewsets.ViewSet):
    """
    View the statistics for this account.
    """
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    resource_name = 'recommendation-results'
    resource_scope = ResourceScope.ORG
    serializer_class = StatsSerializer

    @extend_schema(
        responses={200: {'type': 'array', 'items': {'type': 'string', 'format': 'uri'}}}
    )
    def list(self, request, format=None):
        """
        Provide a simple list of URLs contained here.

        A list of statistics views.
        """
        urls = OrderedDict()
        for stat_method in self.get_extra_actions():
            urls[stat_method.url_name] = reverse(
                'stats-' + stat_method.url_name,
                request=request
            )
        return Response(urls)

    @action(detail=False)
    @extend_schema(
        responses={200: OverviewStatsSerializer},
        parameters=standard_parameters,
    )
    def overview(self, request, format=None):
        """
        Show overview statistics for this user

        This gives the number of pathways, and incident, critical and
        important recommendations, affecting systems that the user can see.
        """
        return Response(OverviewStatsSerializer(
            overview_stats_counts(get_reports_subquery(request, use_joins=True))
        ).data)

    @action(detail=False)
    @extend_schema(
        parameters=standard_parameters,
    )
    def rules(self, request, format=None):
        """
        Show statistics of rule usage across categories and risks.

        Only current reports are considered.
        """
        return Response(StatsSerializer(
            stats_counts(get_reports_subquery(request, use_joins=True), 'rule_id')
        ).data)

    @action(detail=False)
    @extend_schema(
        parameters=standard_parameters,
    )
    def reports(self, request, format=None):
        """
        Show statistics of reports impacting across categories and risks.

        Only current reports are considered.
        """
        return Response(StatsSerializer(
            stats_counts(get_reports_subquery(request, use_joins=True), 'id')
        ).data)

    @action(detail=False)
    @extend_schema(
        parameters=standard_parameters,
    )
    def systems(self, request, format=None):
        """
        Show statistics of systems being impacted across categories and risks.

        Only current reports are considered.
        """
        return Response(StatsSerializer(
            stats_counts(get_reports_subquery(request, use_joins=True), 'host_id')
        ).data)
