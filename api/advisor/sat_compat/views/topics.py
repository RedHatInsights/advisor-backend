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
    IntegerField, OuterRef, Prefetch, Q, Subquery, Value, When,
)
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import viewsets

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema

from api.filters import OpenApiParameter, branch_id_param
from api.models import (
    Resolution, ResolutionRisk, Rule, RuleTopic,
    get_reports_subquery, convert_to_count_query,
)
from api.permissions import InsightsRBACPermission, CertAuthPermission, request_to_org

from sat_compat.serializers import SatRuleTopicSerializer


include_param = OpenApiParameter(
    name='include', location=OpenApiParameter.QUERY,
    description="Include details of associated table",
    required=False,
    type=OpenApiTypes.STR,
    enum=('resolution', ),
)


class TopicsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    List the recommendation topics available.

    param: hash: The expected hash including the branch ID name.
    """
    queryset = RuleTopic.objects.all()
    lookup_field = 'slug'
    pagination_class = None
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    serializer_class = SatRuleTopicSerializer

    def get_reports_subquery(self, **report_filters):
        # If no report filters are supplied, filter on tag
        if not report_filters:
            report_filters['rule__tags'] = OuterRef('tag')
        # get_reports_subquery handles branch_id and the other host filters.
        return get_reports_subquery(self.request, **report_filters)

    def get_rule_queryset(self, rule_filter=Q()):
        """
        Return the Rule queryset that gives details of rules for a specific
        topic.  This must then be limited down, either by being included in
        """
        org_id = request_to_org(self.request)
        report_query = self.get_reports_subquery(rule=OuterRef('id')).filter(
            rule__in=Rule.objects.filter(rule_filter)
        )
        hit_counts = convert_to_count_query(report_query, distinct=True)
        return Rule.objects.filter(rule_filter, active=True).annotate(
            acks=FilteredRelation('ack', condition=Q(ack__org_id=org_id)),
            error_key=Func(F('rule_id'), Value('|'), Value(2), function='SPLIT_PART', output_field=CharField()),
            plugin=Func(F('rule_id'), Value('|'), Value(1), function='SPLIT_PART', output_field=CharField()),
            hitCount=Subquery(hit_counts, output_field=IntegerField()),
            ansible=Case(
                When(
                    # Subquery to avoid duplication of rules with two resolutions
                    Exists(Resolution.objects.filter(
                        rule_id=OuterRef('id'), playbook__isnull=False
                    ).values('id')), then=Value(1)
                ),
                default=Value(0),
                output_field=IntegerField()
            ),
            acked=Case(
                When(acks__isnull=False, then=Value(1)),
                default=Value(0),
                output_field=IntegerField()
            ),
            category_name=F('category__name'),
            rec_impact=F('impact__impact'),
            risk_level=Subquery(
                # Satellite only has system types 105 and 89; prefer the former.
                ResolutionRisk.objects.filter(
                    resolution__rule=OuterRef('id'),
                    resolution__system_type_id__in=(105, 89),
                ).order_by('resolution__system_type_id').reverse().values('risk')[:1],
                output_field=IntegerField()
            ),
        ).filter(Exists(report_query.values('id'))).order_by('rule_id')

    def get_queryset(self):
        # Here we DO NOT have to cope with 'special' topics with different
        # rule filters.  We only list topics that exist.  Therefore we do not
        # handle any other rule filters.
        # get_count_queries automatically applies the tag link filter.
        report_query = self.get_reports_subquery()
        hit_counts = convert_to_count_query(report_query, field='id', distinct=True)
        host_counts = convert_to_count_query(report_query, distinct=True)
        rule_queryset = self.get_rule_queryset()

        return (
            self.queryset.filter(enabled=True)
            .annotate(
                hitCount=Subquery(hit_counts, output_field=IntegerField()),
                affectedSystemCount=Subquery(host_counts, output_field=IntegerField()),
                ruleBinding=Value('tagged', output_field=CharField()),  # always for these topics
                alwaysShow=Value(True, output_field=BooleanField()),
                priority=Case(
                    When(featured=True, then=Value(1)),
                    default=Value(0),
                    output_field=IntegerField()
                ),
                listed=Value('always', output_field=CharField()),
                hidden=Value(False, output_field=BooleanField()),
                tag_name=F('tag__name'),
            )
            .select_related('tag')
            .prefetch_related(
                Prefetch('tag__rules', queryset=rule_queryset),
            )
        )

    @extend_schema(
        parameters=[include_param, branch_id_param],
    )
    def list(self, request, format=None):
        """
        List the rule topics and their impacted systems counts.
        """
        # Note that we always return the 'resolution_risk' field, so we don't
        # bother with checking for the 'include=' parameter
        return Response(SatRuleTopicSerializer(
            self.get_queryset(), many=True
        ).data)

    @extend_schema(
        parameters=[branch_id_param],
    )
    def retrieve(self, request, slug, format=None):
        """
        Information about a specific topic of recommendations

        This recognises the specific topic names:
        - {low,medium,high-critical}-risk - select by total-risk value
        - {availability,security,stability,performance} - select by category
        - 'incident' - selects rules with the tag 'incident'
        """
        # Fix for https://issues.redhat.com/browse/ADVISOR-2195 - getting
        # requests for .../topics/Security.
        slug = slug.lower()
        # If we got one of the 'special' Satellite slugs, filter the rules
        # as if there was a topic for just those rules.
        rule_filter = Q()
        synthetic_topic_description_for = {
            'incidents': 'Rule hits that cause an incident',
            'low-risk': 'Actions identified with a low level of risk',
            'medium-risk': 'Actions identified with a medium level of risk',
            'high-risk': 'Actions identified with a high level of risk',
            'critical-risk': 'Actions identified with a critical level of risk',
            'availability': """
The availability of a service can be compromised even if the service's host
machine is up and running. Actions in the Availability category pertain to
networking and/or service issues on a given machine. Review and resolve
these availability issues to ensure that your vital services can be reached.""",
            'security': """
Red Hat Insights not only detects security issues, it also strives to let you
know whether these issues leave you in a vulnerable state. SSL exploits,
remote access, and local privilege escalation issues can lead to compromised
data and data loss. Review and resolve these security issues to ensure your
systems and data are kept safe.""",
            'stability': """
Hardware issues, kernel panics, and memory corruption can lead to outages and
data loss. Red Hat Insights detects stability issues in your environment that
need to be addressed.""",
            'performance': """
Filesystem, networking, and NUMA performance issues can cause unacceptable
slow downs in your server environments. Whether it be hardware error or
simple configuration Red Hat Insights is here to help. Reviewing, and
resolving these actions will help you maintain your environments
performance.""",
        }
        special_slug_filters = {
            'incidents': Q(tags__name='incident'),
            'low-risk': Q(total_risk=1),
            'medium-risk': Q(total_risk=2),
            'high-risk': Q(total_risk=3),
            'critical-risk': Q(total_risk=4),
            'availability': Q(category__name='Availability'),
            'security': Q(category__name='Security'),
            'stability': Q(category__name='Stability'),
            'performance': Q(category__name='Performance'),
        }
        if slug in special_slug_filters:
            rule_filter = special_slug_filters[slug]
            rule_binding = 'implicit'
            priority = 0
            name = slug.capitalize()
            description = synthetic_topic_description_for[slug]
            tag_name = slug
        else:
            topic = get_object_or_404(RuleTopic, slug__iexact=slug)
            # Put back actual slug of topic from case-insenstive match
            slug = topic.slug
            rule_filter = Q(tags__topic=topic)
            priority = 1 if topic.featured else 0
            rule_binding = 'tagged'
            name = topic.name
            description = topic.description
            tag_name = topic.tag
        rules = self.get_rule_queryset(rule_filter)
        # Don't use that to count the reports though, it's too complex?
        # Use one query to aggregate both counts.
        count_query = self.get_reports_subquery(
            rule__in=Rule.objects.filter(rule_filter)
        ).aggregate(
            hitCount=Count('id', distinct=True),
            affectedSystemCount=Count('host', distinct=True)
        )

        return Response(SatRuleTopicSerializer(
            {
                'tag': {'rules': rules},
                'hitCount': count_query['hitCount'],
                'affectedSystemCount': count_query['affectedSystemCount'],
                'slug': slug,
                'ruleBinding': rule_binding,
                'alwaysShow': True,
                'priority': priority,
                'listed': 'always',
                'hidden': False,
                'name': name,
                'description': description,
                'tag_name': tag_name,
            },
            many=False
        ).data)
