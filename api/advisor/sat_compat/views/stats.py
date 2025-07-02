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

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema

from api.filters import (
    branch_id_param, filter_on_branch_id, filter_on_param,
    OpenApiParameter
)
from api.models import InventoryHost, get_reports_subquery
from api.permissions import InsightsRBACPermission, CertAuthPermission, request_to_org
from sat_compat.serializers import (
    SatStatsSerializer, SatStatsSubRRSerializer, SatStatsSubSSerializer
)
from sat_compat.views.rules import severity_map, severity_enum


min_severity_query_param = OpenApiParameter(
    name='minSeverity', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Select the minimum risk level for rules affecting systems',
    enum=severity_enum
)


class StatsViewSet(ViewSet):
    """
    A simple one-stop shop for all your statistical needs.
    """
    pagination_class = None
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    serializer_class = SatStatsSerializer

    def get_queryset(self):
        org_id = request_to_org(self.request)
        host_branch_id_q = filter_on_branch_id(self.request, relation='host')
        total_systems = InventoryHost.objects.filter(
            host_branch_id_q,
            org_id=org_id,
            per_reporter_staleness__puptoo__stale_warning_timestamp__gt=str(timezone.now()),
            host__upload__current=True,
        ).count()
        return (
            get_reports_subquery(self.request)
            .filter(
                filter_on_param(
                    'rule__total_risk', min_severity_query_param,
                    self.request, severity_map
                ),
            ),
            total_systems
        )

    @extend_schema(
        parameters=[branch_id_param, min_severity_query_param],
        responses={200: SatStatsSerializer(many=False)},
    )
    def list(self, request, format=None):
        """
        List the complete Classic Insights statistics structure.

        This lists counts of total and affected systems, and reports and rules
        by category and total risk.
        """
        reports_qs, total_systems = self.get_queryset()
        reports_qs = reports_qs.aggregate(
            affected_systems=Count('host_id', distinct=True),
            total_reports=Count('id'),
            availability_reports=Count('id', filter=Q(rule__category_id=1)),
            security_reports=Count('id', filter=Q(rule__category_id=2)),
            stability_reports=Count('id', filter=Q(rule__category_id=3)),
            performance_reports=Count('id', filter=Q(rule__category_id=4)),
            info_reports=Count('id', filter=Q(rule__total_risk=1)),
            warn_reports=Count('id', filter=Q(rule__total_risk=2)),
            error_reports=Count('id', filter=Q(rule__total_risk=3)),
            critical_reports=Count('id', filter=Q(rule__total_risk=4)),
            total_rules=Count('rule_id', distinct=True),
            availability_rules=Count('rule_id', filter=Q(rule__category_id=1), distinct=True),
            security_rules=Count('rule_id', filter=Q(rule__category_id=2), distinct=True),
            stability_rules=Count('rule_id', filter=Q(rule__category_id=3), distinct=True),
            performance_rules=Count('rule_id', filter=Q(rule__category_id=4), distinct=True),
            info_rules=Count('rule_id', filter=Q(rule__total_risk=1), distinct=True),
            warn_rules=Count('rule_id', filter=Q(rule__total_risk=2), distinct=True),
            error_rules=Count('rule_id', filter=Q(rule__total_risk=3), distinct=True),
            critical_rules=Count('rule_id', filter=Q(rule__total_risk=4), distinct=True),
        )
        return Response(SatStatsSerializer({
            'systems': {
                'total': total_systems,
                'affected': reports_qs['affected_systems'],
            },
            'reports': {
                'total': reports_qs['total_reports'],
                'info': reports_qs['info_reports'],
                'warn': reports_qs['warn_reports'],
                'error': reports_qs['error_reports'],
                'critical': reports_qs['critical_reports'],
                'availability': reports_qs['availability_reports'],
                'stability': reports_qs['stability_reports'],
                'security': reports_qs['security_reports'],
                'performance': reports_qs['performance_reports'],
            },
            'rules': {
                'total': reports_qs['total_rules'],
                'info': reports_qs['info_rules'],
                'warn': reports_qs['warn_rules'],
                'error': reports_qs['error_rules'],
                'critical': reports_qs['critical_rules'],
                'availability': reports_qs['availability_rules'],
                'stability': reports_qs['stability_rules'],
                'security': reports_qs['security_rules'],
                'performance': reports_qs['performance_rules'],
            },
        }).data)

    @action(detail=False)
    @extend_schema(
        parameters=[branch_id_param, min_severity_query_param],
        responses={200: SatStatsSubRRSerializer(many=False)},
    )
    def rules(self, request, format=None):
        """
        List the Satellite rules statistics.

        This lists the total count of rules, as well as the counts broken
        down by severity and category.
        """
        reports_qs, total_systems = self.get_queryset()
        reports_qs = reports_qs.aggregate(
            total_rules=Count('rule_id', distinct=True),
            availability_rules=Count('rule_id', filter=Q(rule__category_id=1), distinct=True),
            security_rules=Count('rule_id', filter=Q(rule__category_id=2), distinct=True),
            stability_rules=Count('rule_id', filter=Q(rule__category_id=3), distinct=True),
            performance_rules=Count('rule_id', filter=Q(rule__category_id=4), distinct=True),
            info_rules=Count('rule_id', filter=Q(rule__total_risk=1), distinct=True),
            warn_rules=Count('rule_id', filter=Q(rule__total_risk=2), distinct=True),
            error_rules=Count('rule_id', filter=Q(rule__total_risk=3), distinct=True),
            critical_rules=Count('rule_id', filter=Q(rule__total_risk=4), distinct=True),
        )
        return Response(SatStatsSubRRSerializer({
            'total': reports_qs['total_rules'],
            'info': reports_qs['info_rules'],
            'warn': reports_qs['warn_rules'],
            'error': reports_qs['error_rules'],
            'critical': reports_qs['critical_rules'],
            'availability': reports_qs['availability_rules'],
            'stability': reports_qs['stability_rules'],
            'security': reports_qs['security_rules'],
            'performance': reports_qs['performance_rules'],
        }).data)

    @action(detail=False)
    @extend_schema(
        parameters=[branch_id_param, min_severity_query_param],
        responses={200: SatStatsSubSSerializer(many=False)},
    )
    def systems(self, request, format=None):
        """
        List the Satellite rules statistics.

        This lists the total count of rules, as well as the counts broken
        down by severity and category.
        """
        reports_qs, total_systems = self.get_queryset()
        reports_qs = reports_qs.aggregate(
            affected_systems=Count('host_id', distinct=True),
        )
        return Response(SatStatsSubSSerializer({
            'total': total_systems,
            'affected': reports_qs['affected_systems'],
        }).data)
