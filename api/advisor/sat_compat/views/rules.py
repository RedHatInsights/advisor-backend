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

from django.db.models import (
    BooleanField, Case, CharField, Count, Exists, F, FilteredRelation, Func,
    IntegerField, Max, OuterRef, Prefetch, Q, Subquery, Value, When
)
from django.db.models.functions import Concat
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import viewsets

from drf_spectacular.utils import extend_schema
from drf_spectacular.types import OpenApiTypes

from api.filters import (
    branch_id_param, value_of_param, filter_on_param, OpenApiParameter
)
from api.models import (
    Ack, Playbook, Resolution, Rule, Tag,
    get_reports_subquery, convert_to_count_query
)
from api.permissions import request_to_org
from api.utils import PaginateMixin

from sat_compat.serializers import SatRuleSerializer, SatPlaybookSerializer
from sat_compat.utils import ClassicFakePagination

severity_map = {
    'INFO': 1, 'WARN': 2, 'ERROR': 3, 'CRITICAL': 4
}
severity_enum = sorted(severity_map.keys(), key=lambda s: severity_map[s])

ansible_query_param = OpenApiParameter(
    name='ansible', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.BOOL, required=False,
    description='Select rules that provide Ansible resolutions (or not)'
)
category_query_param = OpenApiParameter(
    name='category', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Select rules by category name',
    enum=['availability', 'security', 'stability', 'performance'],
)
ignoredrules_query_param = OpenApiParameter(
    name='ignoredRules', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Select rules by whether they are enabled or disabled',
    enum=['active', 'ignored']
)
incident_query_param = OpenApiParameter(
    name='incidents', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.BOOL, required=False,
    description='Select rules based on whether they cause an incident (or not)'
)
rec_impact_query_param = OpenApiParameter(
    name='rec_impact', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Select rules based on their impact level',
    enum=severity_enum
)
rec_likelihood_query_param = OpenApiParameter(
    name='rec_likelihood', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Select rules based on their likelihood level',
    enum=severity_enum
)
report_count_query_param = OpenApiParameter(
    name='report_count', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description="Report count",
    enum=['gt0', 'lt1'],
)
search_term_query_param = OpenApiParameter(
    name='search_term', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Search for rules with this text (case insensitive)',
)
severity_query_param = OpenApiParameter(
    name='severity', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Search for rules with this severity',
    enum=severity_enum
)
sort_fields = [
    'rule_id', 'node_id', 'severity', 'resolution_risk', 'impacted_systems',
]
sort_field_map = {f: f for f in sort_fields}
sort_field_map['severity'] = 'total_risk'
sort_field_query_param = OpenApiParameter(
    name='sort_by', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description="Order by this field",
    enum=sort_fields,
    default='rule_id'
)
sort_dir_query_param = OpenApiParameter(
    name='sort_dir', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description="Ordering direction",
    enum=['ASC', 'DESC'],
    default='ASC'
)
system_type_id_param = OpenApiParameter(
    name='system_type_id', location=OpenApiParameter.PATH,
    type=OpenApiTypes.INT, required=True,
    description='System type number',
)
playbook_type_param = OpenApiParameter(
    name='playbook_type', location=OpenApiParameter.PATH,
    type=OpenApiTypes.STR, required=True,
    description='Playbook type',
)


def ignored_rules_filter(request):
    state = value_of_param(ignoredrules_query_param, request)
    if not state:
        return Q()
    # If acks, then rule is inactive; if none, then rule is active.
    return Q(acks__isnull=(state == 'active'))


def report_count_filter(request):
    param = value_of_param(report_count_query_param, request)
    if not param:
        return Q()
    if param == 'gt0':
        return Q(report_count__gt=0)
    elif param == 'lt1':
        return Q(report_count=0)


def search_term_filter(request):
    param = value_of_param(search_term_query_param, request)
    if param:
        return \
            Q(rule_id__icontains=param) | \
            Q(description__icontains=param) | \
            Q(summary__icontains=param) | \
            Q(generic__icontains=param) | \
            Q(reason__icontains=param) | \
            Q(more_info__icontains=param) | \
            Q(id__in=Subquery(
                Resolution.objects.filter(
                    resolution__icontains=param
                ).values('rule_id')
            ))
    else:
        return Q()


class RuleViewSet(viewsets.ReadOnlyModelViewSet, PaginateMixin):
    """
    Show Advisor rules in Satellite compatible way.
    """
    queryset = Rule.objects.all()
    serializer_class = SatRuleSerializer
    pagination_class = ClassicFakePagination
    lookup_field = 'rule_id'
    # For handling the ansible_resolutions view
    extra_path_params = []

    def get_queryset(self):
        org_id = request_to_org(self.request)
        grq_conditions = {
            'rule_id': OuterRef('id'),
        }
        branch_id_value = value_of_param(branch_id_param, self.request)
        if branch_id_value:
            grq_conditions['host__branch_id'] = branch_id_value
        report_query = get_reports_subquery(self.request, **grq_conditions)
        host_count_query = convert_to_count_query(report_query, distinct=False)
        hit_count_query = convert_to_count_query(report_query, 'id', distinct=False)
        playbooks_for_rule = Playbook.objects.filter(
            resolution__rule=OuterRef('id')
        ).order_by()
        return self.queryset.filter(active=True).annotate(
            impacted_systems=Subquery(host_count_query),
            category_name=F('category__name'),  # Reduces serializer queries
            rec_impact=F('impact__impact'),  # Foreign key confuses Serializer source
            error_key=Func(F('rule_id'), Value('|'), Value(2), function='SPLIT_PART', output_field=CharField()),
            plugin=Func(F('rule_id'), Value('|'), Value(1), function='SPLIT_PART', output_field=CharField()),
            # If this is all non-deleted rules, then this will always be false...
            hasIncidents=Case(
                When(Exists(Tag.objects.filter(
                    rules__id=OuterRef('id'), name='incident'
                )), then=Value(1)),
                default=Value(0),
                output_field=IntegerField(),
            ),
            report_count=Subquery(hit_count_query),
            ansible=Subquery(
                playbooks_for_rule.values('resolution__rule').annotate(
                    playbooks=Count('pk')
                ).values('playbooks'),
                output_field=IntegerField()
            ),
            resolution_risk=Max('resolution__resolution_risk__risk'),
            # Can't filter on the prefetch...
            acks=FilteredRelation('ack', condition=Q(
                ack__org_id=org_id
            )),
            article=Case(
                When(node_id='', then=Value('')),
                default=Concat(
                    Value('https://access.redhat.com/node/'), 'node_id'
                ),
                output_field=CharField()
            ),
        ).select_related('category', 'impact').prefetch_related(
            # But can't display the FilteredRelation...
            Prefetch(
                'ack_set', queryset=Ack.objects.filter(
                    org_id=org_id
                ), to_attr='ack_id'
            ),
            Prefetch('tags'),
            Prefetch('resolution_set', queryset=(
                Resolution.objects
                .annotate(risk_level=F('resolution_risk__risk'))
                .select_related('resolution_risk')
            )),
        )

    @extend_schema(
        parameters=[
            ansible_query_param, branch_id_param, category_query_param,
            ignoredrules_query_param, incident_query_param,
            rec_impact_query_param, rec_likelihood_query_param,
            search_term_query_param,
            sort_dir_query_param, sort_field_query_param,
        ],
    )
    def list(self, request, format=None):
        """
        Information about rules in Insights Classic format.

        This provides a list of rules in the format used by Satellite, from
        Insights Classic.
        """
        sort_field = sort_field_map[value_of_param(sort_field_query_param, request)]
        if value_of_param(sort_dir_query_param, request) == 'DESC':
            sort_field = '-' + sort_field
        # Branch ID filtering is done in the queryset
        rules = (
            self.get_queryset()
            .filter(
                # Note: filtered fields must be original names, not F renames
                # Annotated fields like hasIncidents are OK though.
                filter_on_param('ansible', ansible_query_param, request),
                filter_on_param('category__name__iexact', category_query_param, request),
                filter_on_param('hasIncidents', incident_query_param, request),
                ignored_rules_filter(request),
                filter_on_param('impact__impact', rec_impact_query_param, request, severity_map),
                filter_on_param('likelihood', rec_likelihood_query_param, request, severity_map),
                filter_on_param('total_risk', severity_query_param, request, severity_map),
                report_count_filter(request),
                search_term_filter(request),
            )
            .order_by(sort_field, 'rule_id')
        )

        return self._paginated_response(rules)

    @extend_schema(
        parameters=[branch_id_param],
    )
    def retrieve(self, request, rule_id, format=None):
        """
        Retrieve the information for a single rule.

        Retrieve the information for a single rule by Insights rule ID.
        """
        rule = self.get_object()
        return Response(SatRuleSerializer(rule).data)

    # At some point it'd be good to not duplicate the path and manual
    # parameters, but I can't work out how to find out the schema parameters
    # from within the router's get_routes method.
    @action(
        detail=True,
        extra_path_params=[system_type_id_param, playbook_type_param],
        url_path='ansible-resolutions',
    )
    @extend_schema(
        parameters=[system_type_id_param, playbook_type_param],
        responses={200: SatPlaybookSerializer(many=False)},
    )
    def ansible_resolutions(
        self, request, rule_id, format=None,
        system_type_id=None, playbook_type=None
    ):
        """
        Retrieve the ansible resolution for a given rule, system type and
        playbook.

        This gives all the information about the given playbook, including
        the actual play.
        """
        def boolean_case(**kwargs):
            return Case(
                When(**kwargs, then=Value(True)),
                default=Value(False), output_field=BooleanField()
            )

        rule = self.get_object()
        resolution = get_object_or_404(rule.resolution_set.all(), system_type_id=system_type_id)
        # So at the point of getting the playbook, we add the annotations for
        # the rest of the data so they're nice available properties
        playbook = get_object_or_404(resolution.playbook_set.annotate(
            rule_id=F('resolution__rule__rule_id'),
            system_type_id=F('resolution__system_type_id'),
            needs_reboot=F('resolution__rule__reboot_required'),
            needs_pydata=boolean_case(play__contains='{{'),
            resolution_risk=F('resolution__resolution_risk__risk'),
        ), type=playbook_type)
        return Response(SatPlaybookSerializer(playbook).data)
