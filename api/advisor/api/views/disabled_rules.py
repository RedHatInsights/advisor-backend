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

from django.db.models import Q, Value
from rest_framework import status, viewsets
from rest_framework.response import Response

from api.models import Ack, HostAck, Rule
from api.permissions import (
    InsightsRBACPermission, CertAuthPermission,
    request_to_org, ResourceScope,
)
from api.serializers import DisabledRulesSerializer
from api.utils import CustomPageNumberPagination, PaginateMixin


class DisabledRulesViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    Shows a list of rules that are disabled, either organisation-wide
    (Ack) or system-specific (HostAck).  The status flag indicates which of
    these causes this rule to be disabled.  To find which systems have
    disabled a rule, use the 'rule_id' query parameter in the hostack/
    endpoint.
    """
    lookup_field = 'rule_id'
    permission_classes = [InsightsRBACPermission | CertAuthPermission]
    pagination_class = CustomPageNumberPagination
    # Note that the queryset here is not what we return, but is needed so that
    # DRF can intuit the type of the 'rule_id' lookup field.  If the queryset
    # refers to Ack or HostAck, rule_id is an int....
    queryset = Rule.objects.all()
    resource_name = 'disable-recommendations'
    resource_scope = ResourceScope.ORG
    serializer_class = DisabledRulesSerializer

    def get_queryset(self):
        org_id = request_to_org(self.request)
        # Internal ordering also makes sure that fields aren't implicitly
        # selected by default ordering, but then we want the whole queyset
        # to be explicitly sorted by rule_id.
        return Ack.objects.filter(
            org_id=org_id, rule__active=True
        ).annotate(
            scope=Value('account')
        ).order_by('rule__rule_id').values(
            'rule__rule_id', 'scope'
        ).union(HostAck.objects.filter(
            org_id=org_id, rule__active=True
        ).annotate(
            scope=Value('system')
        ).distinct('rule__rule_id').order_by('rule__rule_id').values(
            'rule__rule_id', 'scope'
        )).order_by('rule__rule_id', 'scope')

    def retrieve(self, request, rule_id, format=None):
        """
        Get the detail on whether the given rule is disabled, and the scope,
        by rule_id.  A 404 only means that the rule is not disabled - it may
        also not exist.  The account-wide scope will be returned first, if
        the rule has both an account-wide and a system-specific acknowledgement.
        """
        # We have to query each queryset explicitly because Unions can't be
        # queried in Django.
        org_id = request_to_org(request)
        filter_q = Q(org_id=org_id, rule__active=True, rule__rule_id=rule_id)
        try:
            Ack.objects.get(filter_q)
            scope = 'account'
        except Ack.DoesNotExist:
            hostack = HostAck.objects.filter(filter_q)
            if not hostack.exists():
                return Response(status=status.HTTP_404_NOT_FOUND)
            scope = 'system'
        return Response(DisabledRulesSerializer({
            'rule__rule_id': rule_id, 'scope': scope
        }).data)
