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

from django.db.models import Count, CharField, DateTimeField, Q
from django.db.models.functions import Cast
from django.utils import timezone

from rest_framework.renderers import JSONRenderer
from rest_framework_csv.renderers import CSVStreamingRenderer

from drf_spectacular.utils import extend_schema

from api.filters import branch_id_param
from api.models import Ack, CurrentReport, InventoryHost, get_reports_subquery
from api.permissions import request_to_org
from api.views.export import ExportViewSet, ExportRouter

from sat_compat.serializers import (
    SEVERITY_NAMES, SatExportReportSerializer, SatExportSystemSerializer,
)


class ReportsCSVRenderer(CSVStreamingRenderer):
    # System Name,System ID,Rule,Rule ID,Category,Severity,URL,Article,Reported Time (UTC)
    # """Stephen Super Computer""",18579840-1c44-48ad-b903-e25e7c71d677,Network connections will hang when insufficient memory is allocated for the TCP packet fragmentation,network_tcp_connection_hang|NETWORK_TCP_CONNECTION_HANG_WARN,Availability,High,https://access.redhat.com/insights/actions/availability/network_tcp_connection_hang|NETWORK_TCP_CONNECTION_HANG_WARN?machine=18579840-1c44-48ad-b903-e25e7c71d677,,2020-06-18 21:07:18
    header = [
        'display_name', 'insights_id', 'title', 'rule_id_name', 'category',
        'severity', 'url', 'article', 'reported_time',
    ]
    labels = {
        'display_name': 'System Name', 'insights_id': 'System ID', 'title': 'Rule',
        'rule_id_name': 'Rule ID', 'category': 'Category', 'severity': 'Severity',
        'url': 'URL', 'article': 'Article',
        'reported_time': 'Reported Time (UTC)'
    }


class SystemsCSVRenderer(CSVStreamingRenderer):
    # System Name,System ID,System Type,Registration Date (UTC),Last Check In (UTC),Stale,Actions,URL
    # 1acab4decb1c.mylabserver.com,a2a99650-1930-4b11-8e98-0dd959aa4283,RHEL Server,2020-10-20 09:39:53,2020-10-20 09:40:41,true,1,https://console.redhat.com/insights/advisor/systems/classic/a2a99650-1930-4b11-8e98-0dd959aa4283
    header = [
        'display_name', 'insights_id', 'system_type', 'created', 'updated',
        'stale', 'actions', 'url'
    ]
    labels = {
        'display_name': 'System Name', 'insights_id': 'System ID',
        'system_type': 'System Type', 'created': 'Registration Date (UTC)',
        'updated': 'Last Check In (UTC)', 'stale': 'Stale',
        'actions': 'Actions', 'url': 'URL',
    }


def transform_reports(report):
    return {
        'display_name': report['inventory__display_name'],
        'insights_id': report['inventory__insights_id'],
        'title': report['rule__description'],
        'rule_id_name': report['rule__rule_id'],  # rule_id already a field in CR
        'category': report['rule__category__name'],
        'severity': SEVERITY_NAMES[report['rule__total_risk']],
        'url': "{base}/{category}/{ruleid}?machine={hostid}".format(
            base='https://access.redhat.com/insights/actions',
            category=report['rule__category__name'].lower(),
            ruleid=report['rule__rule_id'],
            hostid=report['host_id'],
        ),
        'article': (
            "{base}/{node_id}".format(
                base='https://access.redhat.com/node',
                node_id=report['rule__node_id'],
            ) if report['rule__node_id'] else ''
        ),
        'reported_time': report['upload__checked_on'],
    }


class ReportsViewSet(ExportViewSet):
    """
    Export reports as CSV or JSON.

    Reports can be filtered by branch_id so far.
    """
    queryset = CurrentReport.objects.all()
    serializer_class = SatExportReportSerializer
    renderer_classes = (ReportsCSVRenderer, JSONRenderer, )

    @extend_schema(
        parameters=[branch_id_param],
    )
    def list(self, request, format=None):
        # Force CSV output
        request.accepted_renderer = ReportsCSVRenderer()
        # get_reports_subquery takes care of satellite, branch_id, etc. params
        reports = get_reports_subquery(
            request,
        ).values(
            'inventory__display_name', 'inventory__insights_id',
            'rule__description', 'rule__rule_id', 'rule__category__name',
            'rule__total_risk', 'host_id', 'rule__node_id',
            'upload__checked_on',
        ).order_by('rule__rule_id', 'inventory__display_name', 'host_id')
        return self.stream_response(
            reports, 'reports', transform_reports, format
        )


def transform_systems(system):
    return {
        'display_name': system['display_name'],
        'insights_id': str(system['insights_id']),
        'system_type': 'RHEL Server',
        'created': system['created'],
        'updated': system['updated'],
        'stale': (system['puptoo_stale_timestamp'] <= timezone.now()),
        'actions': system['actions_count'],
        'url': "{base}/{id}".format(
            base='https://console.redhat.com/insights/advisor/systems/classic',
            id=system['id']
        ),
    }


class SystemsViewSet(ExportViewSet):
    """
    Export systems as CSV or JSON.

    Systems can be filtered by branch_id so far.
    """
    queryset = InventoryHost.objects.all()
    serializer_class = SatExportSystemSerializer
    renderer_classes = (SystemsCSVRenderer, JSONRenderer, )

    @extend_schema(
        parameters=[branch_id_param],
    )
    def list(self, request, format=None):
        # Force CSV output
        org_id = request_to_org(self.request)
        request.accepted_renderer = SystemsCSVRenderer()
        acks_qs = Ack.objects.filter(
            org_id=org_id
        ).values('rule_id')
        # for_account already handles the host filtering
        systems = InventoryHost.objects.for_account(
            request, filter_stale=False,
        ).annotate(
            puptoo_stale_timestamp=Cast(Cast(
                'per_reporter_staleness__puptoo__stale_timestamp',
                output_field=CharField()
            ), output_field=DateTimeField()),
            actions_count=Count('host__satmaintenanceaction', filter=Q(
                host__satmaintenanceaction__rule__active=True,
            ) & ~ Q(
                host__satmaintenanceaction__rule__in=acks_qs
            )),
        ).values(  # acts as a select_related
            'id', 'display_name', 'insights_id',
            'created', 'updated', 'puptoo_stale_timestamp', 'actions_count',
        ).order_by('display_name', 'id')
        return self.stream_response(
            systems, 'systems', transform_systems, format
        )


router = ExportRouter(trailing_slash=False)
router.register(r'reports', ReportsViewSet, basename='sat-compat-export-reports')
router.register(r'systems', SystemsViewSet, basename='sat-compat-export-systems')
