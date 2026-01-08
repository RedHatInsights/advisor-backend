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
from rest_framework import viewsets
from rest_framework.mixins import DestroyModelMixin
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema

from api.filters import (
    OpenApiParameter, value_of_param, branch_id_param,
)
from api.models import Ack, Rule
from api.permissions import request_to_org
from api.utils import store_post_data

from sat_compat.serializers import (
    SatAckSerializer, SatAckInputSerializer, SatAckWithRuleSerializer
)


include_param = OpenApiParameter(
    name='include', location=OpenApiParameter.QUERY,
    description="Include details of associated table",
    required=False,
    type=OpenApiTypes.STR,
    enum=('rule', ),
)


class AckViewSet(viewsets.ReadOnlyModelViewSet, DestroyModelMixin):
    """
    Acks acknowledge (and therefore hide) a rule from view in an account.

    This view handles listing, retrieving, creating and deleting acks.  Acks
    are created by supplying the rle to ack, but are deleted here by their
    own ack ID.
    """
    queryset = Ack.objects.filter(rule__deleted_at__isnull=True, rule__active=True)
    pagination_class = None
    serializer_class = SatAckSerializer

    def get_queryset(self):
        """
        Get the rule acknowledgements queryset for this account, for active,
        non-deleted rules, based on the request's account params.
        """
        # Testing sometimes hasn't checked authentication at this point
        if hasattr(self, 'swagger_fake_view'):
            return Ack.objects.none()
        org_id = request_to_org(self.request)
        return (
            self.queryset
            .filter(org_id=org_id)
            .select_related('rule')
        )

    @extend_schema(
        parameters=[include_param, branch_id_param],
    )
    def list(self, request, format=None):
        """
        List acks from this account where the rule is active

        Will return an empty list if this account has no acks.
        """
        queryset = (
            self.get_queryset()
            .order_by('id')
        )
        serializer = self.serializer_class
        include = value_of_param(include_param, request)
        if include and include == 'rule':
            serializer = SatAckWithRuleSerializer
        return Response(serializer(queryset, many=True).data)

    @extend_schema(
        request=SatAckInputSerializer,
        responses={201: SatAckSerializer(many=False)},
    )
    def create(self, request, format=None):
        """
        Add an acknowledgement for a rule, by rule ID.

        If there's already an acknowledgement of this rule by this
        account, then return that.  Otherwise, a new ack is created.
        """
        store_post_data(request, SatAckInputSerializer)
        serdata = SatAckInputSerializer(data=request.data)
        # If we can't deserialise the rule ID, then return a 400 now
        serdata.is_valid(raise_exception=True)
        # Get the related rule object, or return a 404 now
        rule = get_object_or_404(Rule, rule_id=serdata.data['rule_id'])
        # Update or create this ack:
        new_ack, created = Ack.objects.update_or_create(
            org_id=request.auth['org_id'], rule_id=rule.id,
            defaults={
                'account': request.account,  # Retain the account for backwards compat, metadata and other analysis
                'justification': 'Satellite compatibility',
                'created_by': 'Satellite compatibility',
            }
        )
        return Response(SatAckSerializer(
            new_ack, many=False, context={'request': request}
        ).data, status=HTTP_201_CREATED)

    @extend_schema(
        parameters=[branch_id_param]
    )
    def destroy(self, request, pk, format=None):
        """
        Delete an acknowledgement for a rule, by ack ID.

        Only acknowledgements in this account with the given branch ID can
        be deleted.
        """
        ack = get_object_or_404(Ack, pk=pk, org_id=request.auth['org_id'])
        ack.delete()
        return Response(status=HTTP_204_NO_CONTENT)
