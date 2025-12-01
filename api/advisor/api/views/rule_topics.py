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

from django.db.models import OuterRef, Subquery
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import (
    value_of_param, host_tags_query_param,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    sort_params_to_fields, host_group_name_query_param,
    update_method_query_param,
)
from api.models import (
    Rule, RuleTopic,
    convert_to_count_query, get_reports_subquery, get_reporting_system_ids_queryset,
)
from api.permissions import (
    IsRedHatInternalUser, InsightsRBACPermission, CertAuthPermission,
    ReadOnlyUser, ResourceScope, TurnpikeIdentityAuthentication,
)
from api.serializers import (
    RuleSerializer, SystemsForRuleSerializer, TopicSerializer, TopicEditSerializer
)
from api.views.rules import systems_sort_field_map, systems_sort_query_param


show_disabled_query_param = OpenApiParameter(
    name='show_disabled', location=OpenApiParameter.QUERY,
    description="Display topics that are disabled as well as enabled",
    required=False,
    type=OpenApiTypes.BOOL,
    default=False
)


class RuleTopicViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Rules have topics, set by Insights administrators.  This is a view of
    the topics available, along with the rules and systems to which they
    apply.

    retrieve: Fetch a single topic with its associated data
    update: Update fields of a given topic with new data
    partial_update: Update the given fields of a topic with new data
    delete: Delete a topic
    """
    lookup_field = 'slug'
    pagination_class = None
    permission_classes = [
        (InsightsRBACPermission & (ReadOnlyUser | IsRedHatInternalUser)) | CertAuthPermission
    ]
    queryset = RuleTopic.objects.all()
    resource_name = 'recommendation-results'
    resource_scope = ResourceScope.ORG
    serializer_class = TopicSerializer

    def get_queryset(self):
        report_query = get_reports_subquery(self.request, rule__tags=OuterRef('tag'))
        system_counts = convert_to_count_query(report_query, distinct=True)
        return self.queryset.annotate(
            impacted_systems_count=Subquery(system_counts),
        )

    @extend_schema(
        parameters=[
            show_disabled_query_param, host_tags_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            host_group_name_query_param, update_method_query_param,
        ],
    )
    def list(self, request, format=None):
        """
        List the rule topics and their impacted systems counts.

        Normally this only shows enabled topics, but if the 'show_disabled'
        parameter is set to True then this will show disabled topics as
        well.
        """
        topics = self.get_queryset()
        show_disabled = value_of_param(show_disabled_query_param, request)
        if not show_disabled:
            topics = topics.filter(enabled=True)
        return Response(TopicSerializer(
            topics, many=True, context={'request': request}
        ).data)

    # We define the retrieve view because we want to use the topic with rules
    # serializer.  Create, update and partial-update should all take just the
    # topic input serializer.
    def retrieve(self, request, slug, format=None):
        """
        Retrieve a single topic by slug.

        This also lists the topic's impacted systems count.
        """
        topic = self.get_object()
        return Response(TopicSerializer(
            topic, many=False, context={'request': request}
        ).data)

    @extend_schema(
        parameters=[
            host_tags_query_param, systems_sort_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            host_group_name_query_param, update_method_query_param,
        ],
        responses={200: SystemsForRuleSerializer(many=False)},
    )
    @action(detail=True)
    def systems(self, request, slug, format=None):
        """
        List all systems affected by this rule topic.

        Systems are just listed by their UUID.
        """
        # Avoid get_queryset because of annotation:
        topic = get_object_or_404(RuleTopic, slug=slug)
        sort_list = value_of_param(systems_sort_query_param, request)
        sort_fields = sort_params_to_fields(sort_list, systems_sort_field_map)
        # Because we're possibly seeing the current reports for different
        # rules on the same system, we need to make the sort fields distinct.
        impacted_systems = get_reporting_system_ids_queryset(
            request, rule__tags__topic=topic
        ).order_by(*sort_fields).distinct(*sort_fields)

        return Response(SystemsForRuleSerializer(
            {'host_ids': impacted_systems},
            many=False, context={'request': request}
        ).data)

    @extend_schema(responses={200: RuleSerializer(many=True)})
    @action(detail=True)
    def rules_with_tag(self, request, slug, format=None):
        """
        Lists the available rules that have this tag.

        This shows the rule information for rules with this tag.
        """
        topic = self.get_object()

        return Response(RuleSerializer(
            Rule.objects.filter(active=True, tags__topic=topic),
            many=True, context={'request': request}
        ).data)


class InternalRuleTopicViewSet(viewsets.ModelViewSet):
    """
    Internal editing interface for rule topics.

    This viewset is only available to Red hat associates.
    """
    authentication_classes = [TurnpikeIdentityAuthentication]
    lookup_field = 'slug'
    permission_classes = [AssociatePermission]
    serializer_class = TopicEditSerializer
