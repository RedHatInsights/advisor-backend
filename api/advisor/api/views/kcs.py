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

from django.db.models import F, Q, Value
from django.db.models.functions import Concat
from django.shortcuts import get_list_or_404

from rest_framework import viewsets
from rest_framework.response import Response
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import value_of_param
from api.models import Rule
from api.serializers import KcsSerializer, KcsRuleSerializer

from os import getenv
RULE_URL = getenv('RULE_URL', 'console.redhat.com/insights/advisor/recommendations/')

node_ids_query_param = OpenApiParameter(
    name='node_ids', location=OpenApiParameter.QUERY,
    description="Display the rule urls for the given list of comma separated KCS solution node_ids",
    required=False,
    many=True, type=OpenApiTypes.REGEX, pattern=r'\d+', style='form',
)


def filter_on_node_ids(request):
    node_ids = value_of_param(node_ids_query_param, request)
    if node_ids:
        return Q(node_id__in=node_ids)
    else:
        return Q()


class KcsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Endpoint to retrieve lists of C.R.C URLs for active rules and their associated KCS articles
    """
    authentication_classes = []
    lookup_field = 'node_id'
    pagination_class = None
    permission_classes = []
    queryset = Rule.objects.filter(active=True).exclude(node_id="").annotate(
        rule_url=Concat(Value(RULE_URL), F('rule_id'))
    )
    serializer_class = KcsSerializer

    @extend_schema(
        parameters=[node_ids_query_param]
    )
    def list(self, request, format=None):
        """
        Looks for all active rules with KCS solutions

        Returns a list of dicts of the C.R.C rule URL and its KCS solution number
        """
        rules_n_nodes = self.get_queryset().filter(
            filter_on_node_ids(request)
        ).values('rule_id', 'node_id', 'rule_url')
        return Response(KcsSerializer(rules_n_nodes, many=True).data)

    # Because we use a special serializer that is a list serializer, the
    # auto operation ID determination doesn't work.  So we set it explicitly.
    @extend_schema(
        operation_id='kcs_retrieve',
        responses={200: KcsRuleSerializer},
    )
    def retrieve(self, request, node_id, format=None):
        """
        Gets active rule(s) for a particular KCS solution (node_id)

        Returns a list of C.R.C rule url(s) for that KCS solution
        """
        # KcsRuleSerializer is just a ListSerializer instance, so it
        # automatically takes a list of child values
        rules_4_node = get_list_or_404(
            self.get_queryset().values_list('rule_url', flat=True),
            node_id=node_id
        )
        return Response(rules_4_node)
