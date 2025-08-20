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

import json

from rest_framework_csv.renderers import CSVStreamingRenderer
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.routers import Route, APIRootView, DefaultRouter
from rest_framework.viewsets import ViewSet

from drf_spectacular.utils import extend_schema

from django.db.models import Count, Exists, F, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce
from django.http import StreamingHttpResponse

from api.filters import (
    host_tags_query_param, filter_on_param, value_of_param,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    rule_id_query_param, filter_on_display_name,
    host_id_query_param, filter_on_host_id, host_group_name_query_param,
    update_method_query_param,
)
from api.models import (
    InventoryHost, Resolution, Rule, Tag, get_reports_subquery, Playbook,
)
from api.permissions import (
    InsightsRBACPermission, CertAuthPermission, ResourceScope
)
from api.serializers import (
    ExportHitsSerializer, RuleExportSerializer, ReportExportSerializer,
    SystemSerializer,
)
from api.views.rules import (
    category_query_param, impact_query_param, likelihood_query_param,
    res_risk_query_param, text_query_param, total_risk_query_param,
    incident_query_param, reboot_required_query_param, has_playbook_query_param
)
from api.views.systems import (
    get_systems_queryset, sort_query_param as systems_sort_query_param,
    display_name_query_param,
)

from datetime import date


# We anticipate that there will be multiple CSV exports here in various
# forms.  Therefore we treat this more like an index of URLs to include, and
# rely on Django REST Framework's browsable API lister to show it (in the
# service of 'don't repeat yourself').  So we define the exporter viewsets
# first and then create our router and URL patterns at the end.


class HitsCSVRenderer(CSVStreamingRenderer):
    header = [
        'hostname', 'uuid', 'rhel_version', 'last_seen', 'title',
        'solution_url', 'total_risk', 'likelihood',
        'publish_date', 'stale_at', 'results_url'
    ]
    # We should have nicer names, with a labels dictionary which links the
    # field name to the display name.  But this is the format we have now,
    # and we don't want to break things for customers...


class SystemsCSVRenderer(CSVStreamingRenderer):
    header = [
        'system_uuid', 'display_name', 'last_seen', 'stale_at', 'hits',
        'critical_hits', 'important_hits', 'moderate_hits', 'low_hits',
        'rhel_version', 'group_name'
    ]


def filter_on_incident(request):
    # Filter rules that have the 'incident' tag (or absence thereof)
    incident_param = value_of_param(incident_query_param, request)
    if incident_param is None:
        return Q()

    # If there are no incident rules the results of the Subquery will be (NULL)
    # And NOT IN (NULL) behaves unexpectedly, so coalesce the NULL to a 0 to get more expected behaviour
    incident_tag_subquery = Subquery(Tag.objects.filter(name='incident')
                                                .annotate(incident_rule_ids=Coalesce('rules__id', 0))
                                                .values('incident_rule_ids'))
    if incident_param:
        return Q(rule__in=incident_tag_subquery)
    else:
        return ~Q(rule__in=incident_tag_subquery)


def filter_on_reboot_required(request):
    reboot_param = value_of_param(reboot_required_query_param, request)
    if reboot_param is None:
        return Q()
    else:
        return Q(rule__reboot_required=reboot_param)  # True or False there.


def filter_on_has_playbook(request):
    # Filter rules that have playbooks, or not
    has_playbook_param = value_of_param(has_playbook_query_param, request)
    playbook_qs = Q(Exists(Playbook.objects.filter(resolution__rule_id=OuterRef('rule_id'))))
    if has_playbook_param is None:
        return Q()
    elif has_playbook_param:
        return playbook_qs
    else:
        return ~playbook_qs


def filter_on_resolution_risk(request):
    # Filtering naively on resolution__resolution_risk involves a join to
    # the resolution table, which then causes row duplication.  So we need to
    # encapsulate that in a subquery.  The simplest subquery therefore is a
    # search of the resolution table listing their associated rule ID number.
    # Stolen from views/rules.py, modified for upload filtering
    res_risk = value_of_param(res_risk_query_param, request)
    if res_risk:
        return Q(rule__in=Subquery(
            Resolution.objects.filter(
                resolution_risk__risk__in=res_risk
            ).values('rule_id')
        ))
    else:
        return Q()


def filter_on_text(request, field_prefix='rule'):
    # Filter on text search on all text fields, from the perspective of
    # the upload
    srch = value_of_param(text_query_param, request)
    if srch:
        # Thanks, Flake8, for not allowing wrapping of binary operators
        # Also note that any joins here may affect the number of results
        # found in annotations.
        return \
            Q(rule__rule_id__icontains=srch) | \
            Q(rule__description__icontains=srch) | \
            Q(rule__summary__icontains=srch) | \
            Q(rule__generic__icontains=srch) | \
            Q(rule__reason__icontains=srch) | \
            Q(rule__more_info__icontains=srch) | \
            Q(rule__in=Subquery(Resolution.objects.filter(
                    resolution__icontains=srch
            ).values('rule_id')))
    else:
        return Q()


def stream_json_reports(reports):
    yield '['
    first = True
    for report in reports:
        if first:
            first = False
        else:
            yield ','
        yield json.dumps(report)
    yield ']'


def make_serializer_transform(serializer):
    def serializer_transform(item):
        return serializer(item).data

    return serializer_transform


def null_transformer(item):
    return item


class ExportViewSet(ViewSet):
    """
    A common viewset to define the common process for these export viewsets
    """
    resource_name = 'exports'
    resource_scope = ResourceScope.ORG

    def stream_response(self, queryset, prefix, transformer=None, format=None):
        """
        Use a streaming renderer to output the data, setting the accepted
        media type and content disposition as appropriate.

        In order to support streaming data and iterative processing, we take
        a queryset (to use it's `iterator()` method), and a transformer
        generator that transforms each input row of the queryset into the
        fields expected in the final representation of the data.  If this is
        not explicitly supplied, the viewset's `serializer_class` will be
        used to transform values.

        We then determine the output type.  If the 'format' argument is 'csv',
        or a CSV view is explicitly selected in the test framework, or the
        HTTP_ACCEPT header has been deliberately manipulated to start with
        'text/csv', then we use CSV output.
        """
        if transformer is None:
            if self.serializer_class:
                transformer = make_serializer_transform(self.serializer_class)
            else:
                transformer = null_transformer
        output_media_type = 'application/json'
        if (format is not None and format == 'csv') or self.suffix.endswith('CSV'):
            output_media_type = 'text/csv'
        if 'HTTP_ACCEPT' in self.request.META and self.request.META['HTTP_ACCEPT'].startswith('text/csv'):
            output_media_type = 'text/csv'
        renderer = stream_json_reports
        if output_media_type == 'text/csv':
            # Pick the renderer class object specified by the viewset
            r = self.request.accepted_renderer
            renderer = r.render
        response = StreamingHttpResponse(
            renderer(transformer(i) for i in queryset.iterator()),
            content_type=output_media_type,
        )
        response.accepted_media_type = output_media_type
        if format is not None:
            filename = f"{prefix}-{date.today().strftime('%Y-%m-%d')}.{format}"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


hits_common_params = [
    category_query_param, impact_query_param, likelihood_query_param,
    res_risk_query_param, text_query_param, total_risk_query_param,
    host_tags_query_param, incident_query_param, has_playbook_query_param,
    reboot_required_query_param, filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param, display_name_query_param,
    host_id_query_param, host_group_name_query_param, update_method_query_param,
]


def transform_hits(report):
    return {
        'hostname': report['inventory__display_name'],
        'rhel_version': InventoryHost.get_rhel_version(
            report['inventory__system_profile']
        ),
        'uuid': str(report['host_id']),
        'last_seen': report['inventory__per_reporter_staleness__puptoo__last_check_in'],
        'title': report['rule__description'],
        'solution_url': (
            f"https://access.redhat.com/node/{report['rule__node_id']}"
            if report['rule__node_id'] else ''
        ),
        'total_risk': report['rule__total_risk'],
        'likelihood': report['rule__likelihood'],
        'publish_date': report['rule__publish_date'].isoformat(),
        'stale_at': report['inventory__per_reporter_staleness__puptoo__stale_timestamp'],
        'results_url': "{base}/{rule_id}/{sys_id}/".format(
            base='https://console.redhat.com/insights/advisor/recommendations',
            rule_id=report['rule__rule_id'].replace('|', '%7C'),
            sys_id=report['host_id']
        )
    }


class HitsViewSet(ExportViewSet):
    """
    Export the hosts and rules listing as CSV or JSON.
    """
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    renderer_classes = (JSONRenderer, HitsCSVRenderer, )
    serializer_class = ExportHitsSerializer

    @extend_schema(
        parameters=hits_common_params,
    )
    def list(self, request, format=None):
        """
        Get each host and all rules currently affecting it.

        We also only present active, non-acked (on an account AND host level)
        rules.  Inventory data may be requested if Advisor has not seen all
        the hosts. The accepted content type supplied in the request headers
        is used to determine the supplied content type.
        """
        reports = get_reports_subquery(request, use_joins=True).order_by(
            'host', 'rule__rule_id'
        ).values(  # also acts as a select_related
            'rule__rule_id', 'rule__description', 'rule__node_id',
            'rule__total_risk', 'rule__likelihood', 'rule__publish_date',
            'rule__category__name', 'inventory__updated', 'host_id',
            'inventory__per_reporter_staleness__puptoo__last_check_in',
            'inventory__per_reporter_staleness__puptoo__stale_timestamp',
            'inventory__display_name', 'inventory__system_profile',  # for rhel_version
            'rule__reboot_required',
        )
        if request.query_params:
            # Process parameters in alphabetical order, not because it should
            # make any difference to the query (since the conditions are ANDed
            # together) but for ease of code maintenance.

            reports = reports.filter(
                filter_on_param('rule__category_id', category_query_param, request),
                filter_on_param('rule__impact__impact', impact_query_param, request),
                filter_on_param('rule__likelihood', likelihood_query_param, request),
                filter_on_resolution_risk(request),
                filter_on_text(request),
                filter_on_param('rule__total_risk', total_risk_query_param, request),
                filter_on_incident(request),
                filter_on_reboot_required(request),
                filter_on_has_playbook(request),
                filter_on_display_name(request, 'inventory'),
                filter_on_host_id(request)
            )

        # Return all the data
        return self.stream_response(
            reports, 'hits', transform_hits, format
        )


def transform_reports(report):
    return {
        'host_id': str(report['host_id']),
        'rule_id': report['rule__rule_id'],
        'reports_url': "{base}/{rule_id}/{sys_id}/".format(
            base='https://console.redhat.com/insights/advisor/recommendations',
            rule_id=report['rule__rule_id'].replace('|', '%7C'),
            sys_id=report['host_id']
        ),
        'report_time': report['upload__checked_on'].isoformat(),
        'details': report['details'],
        'impacted_date': report['impacted_date'].isoformat(),
    }


class ReportsViewSet(ExportViewSet):
    """
    Export the reports of rule hits on hosts as JSON.  Look up the rule and
    system in the named export views.
    """
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    renderer_classes = (JSONRenderer, )
    serializer_class = ReportExportSerializer

    @extend_schema(
        parameters=hits_common_params,
    )
    def list(self, request, format=None):
        """
        List the report details of each rule affecting each system.

        System and Rule are referred to by ID only, to be correlated with the
        Rule and System export data.  It's like the hits output but much
        less repetitive.
        """
        reports = get_reports_subquery(request, use_joins=True).order_by(
            'host_id', 'rule__rule_id'
        ).values(  # also acts as a select_related
            'host_id', 'rule__rule_id', 'upload__checked_on', 'details', 'impacted_date'
        )
        return self.stream_response(
            reports, 'reports', transform_reports, format
        )


class RulesViewSet(ViewSet):
    """
    Export the reports of rule hits on hosts as JSON.  Look up the rule and
    system in the named export views.  Because this is hopefully fairly
    simple, do not attempt to stream it.
    """
    serializer_class = RuleExportSerializer

    @extend_schema(
        parameters=hits_common_params,
    )
    def list(self, request, format=None):
        """
        List the report details of each rule affecting each system.

        System and Rule are referred to by ID only, to be correlated with the
        Rule and System export data.  It's like the hits output but much
        less repetitive.
        """
        rules = Rule.objects.for_account(request).annotate(
            category_name=F('category__name'),
            impact_name=F('impact__name'),
            playbook_count=Count('resolution__playbook'),
        )
        response = Response(RuleExportSerializer(rules, many=True).data)
        if format is not None:
            filename = f"rules-{date.today().strftime('%Y-%m-%d')}.{format}"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


systems_common_parameters = [
    display_name_query_param, systems_sort_query_param,
    host_group_name_query_param, update_method_query_param,
    rule_id_query_param,
]


class SystemsViewSet(ExportViewSet):
    """
    List of systems with details and hit counts.

    Systems can be sorted and filtered by display name and rule id.
    """
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    renderer_classes = (JSONRenderer, SystemsCSVRenderer, )
    serializer_class = SystemSerializer

    @extend_schema(
        parameters=systems_common_parameters,
    )
    def list(self, request, format=None):
        sort = value_of_param(systems_sort_query_param, request)
        rule_id_value = value_of_param(rule_id_query_param, request)
        display_name_value = value_of_param(display_name_query_param, request)
        reports = get_reports_subquery(
            request, exclude_ineligible_hosts=False, host=OuterRef('id'),
        ).filter(rule__rule_id=rule_id_value)
        systems = get_systems_queryset(request).filter(
            Q(display_name__icontains=display_name_value) if display_name_value else Q(),
            Exists(reports) if rule_id_value else Q()
        ).order_by(sort, 'id')
        return self.stream_response(
            systems, 'systems', format=format  # no transform = use serializer
        )


class ExportRootView(APIRootView):
    """
    The root view of exportable data.
    """
    pass


class ExportRouter(DefaultRouter):
    """
    Use our own root view to provide a nicer schema description.
    """
    APIRootView = ExportRootView
    root_view_name = 'export-list'
    routes = [
        # List route.
        Route(
            url=r'^{prefix}{trailing_slash}$',
            mapping={'get': 'list'},
            name='{basename}-list',
            detail=False,
            initkwargs={'suffix': 'List'}
        ),
        # Extra routes specifically for format suffixes.  The suffix then
        # determines which renderers are presented to the schema generator
        # via the ViewSet's get_renderers() method.
        Route(
            url=r'^{prefix}.csv$',
            mapping={'get': '{basename}_list_csv'},
            name='{basename}-list-csv',
            detail=False,
            initkwargs={'suffix': 'List-CSV'}
        ),
        Route(
            url=r'^{prefix}.json$',
            mapping={'get': '{basename}_list_json'},
            name='{basename}-list-json',
            detail=False,
            initkwargs={'suffix': 'List-JSON'}
        ),
    ]


router = ExportRouter()
router.register(r'hits', HitsViewSet, basename='export-hits')
router.register(r'rules', RulesViewSet, basename='export-rules')
router.register(r'reports', ReportsViewSet, basename='export-reports')
router.register(r'systems', SystemsViewSet, basename='export-systems')
