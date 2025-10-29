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

from django.conf import settings
from django.db.models import Count, F
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

from api.models import Ack, Rule
from api.serializers import (
    AckSerializer, AllAckSerializer, AckInputSerializer,
    AckJustificationSerializer, AckCountSerializer
)
from api.permissions import (
    IsRedHatInternalUser, InsightsRBACPermission, CertAuthPermission,
    ResourceScope, request_to_username, set_resource,
)
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, store_post_data,
)


class RedHatAllAcksPermission(IsRedHatInternalUser):
    allowed_views = ['All', ]


# We use a ReadOnlyModelViewSet for the list and retrieve, and then add our
# own delete and create methods which only need the rule ID.
@method_decorator(
    name='list',
    decorator=extend_schema(
        summary="List the rules that have been acknowledged (disabled)",
        description="""
        Display the list of rules that have been disabled or acknowledged in
        this account, along with who disabled them and their justification.
        """,
    )
)
@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="Display a specific acknowledgement (disabling) of a rule",
        description="""
        Display who disabled a rule in this account, when, and their
        justification for disabling it.
        """,
    )
)
class AckViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    Acks acknowledge (and therefore hide) a rule from view in an account.

    This view handles listing, retrieving, creating and deleting acks.  Acks
    are created and deleted by Insights rule ID, not by their own ack ID.

    param: rule_id: Rule ID defined by Insights ruleset
    """
    queryset = Ack.objects.filter(
        rule__deleted_at__isnull=True, rule__active=True
    )
    lookup_field = 'rule__rule_id'
    lookup_url_kwarg = 'rule_id'
    pagination_class = CustomPageNumberPagination
    permission_classes = [InsightsRBACPermission | CertAuthPermission | RedHatAllAcksPermission]
    serializer_class = AckSerializer
    resource_name = 'disable-recommendations'
    resource_scope = ResourceScope.ORG

    def get_queryset(self):
        """
        Get the rule acknowledgements queryset for this account, for active,
        non-deleted rules, based on the request's account org_id params.
        """
        # If no authentication, org_id is None here so never matches
        org_id = self.request.auth['org_id']
        return self.queryset.filter(org_id=org_id)

    @set_resource('denied')
    @extend_schema(
        responses={200: AllAckSerializer(many=True)}
    )
    @action(detail=False, pagination_class=None,)
    def all(self, request, format=None):
        """
        List acks from all accounts, with org_id.

        Has no pagination.
        """
        return Response(AllAckSerializer(
            Ack.objects
            .filter(rule__active=True)
            .exclude(created_by=settings.AUTOACK['CREATED_BY'])
            .order_by('org_id', 'rule__rule_id')
            .annotate(
                # The F() implicitly does a select_related('rule__rule_id')
                rule_id_field=F('rule__rule_id')
            ), many=True
        ).data)

    @set_resource(scope=ResourceScope.ORG)
    @extend_schema(
        request=AckInputSerializer,
        responses={200: AckSerializer(many=False)},
    )
    def create(self, request, format=None):
        """
        Add an acknowledgement for a rule, by rule ID.

        If there's already an acknowledgement of this rule by this
        accounts org_id, then return that.  Otherwise, a new ack is created.
        """
        store_post_data(request, AckInputSerializer)
        serdata = AckInputSerializer(data=request.data)
        # If we can't deserialise the rule ID, then return a 400 now
        serdata.is_valid(raise_exception=True)
        # Get the related rule object, or return a 404 now
        rule = get_object_or_404(Rule, rule_id=serdata.data['rule_id'])
        # Update or create this ack:
        new_ack, created = Ack.objects.update_or_create(
            org_id=request.auth['org_id'], rule_id=rule.id,
            defaults={
                'account': request.account,  # Remove at a later time, keep for now for potential backwards compat
                'justification': serdata.validated_data.get('justification', ''),
                'created_by': request_to_username(request),
            }
        )
        return Response(AckSerializer(
            new_ack, many=False, context={'request': request}
        ).data)

    @extend_schema(
        request=AckJustificationSerializer,
        responses={200: AckSerializer(many=False)},
    )
    def update(self, request, rule_id, format=None):
        """
        Update an acknowledgement for a rule, by rule ID.

        A new justification can be supplied.  The username is taken from the
        authenticated request.  The updated ack is returned.
        """
        store_post_data(request, AckJustificationSerializer)
        serdata = AckJustificationSerializer(data=request.data)
        # If we can't deserialise the rule ID, then return a 400 now
        serdata.is_valid(raise_exception=True)
        # Get the related rule object, or return a 404 now
        # ack = get_object_or_404(
        #     Ack, rule__rule_id=rule_id, org_id=request.auth['org_id'],
        # )
        ack = self.get_object()
        ack.justification = serdata.validated_data.get('justification', '')
        ack.created_by = request_to_username(request)
        ack.save()
        return Response(AckSerializer(ack, many=False, context={'request': request}).data)

    @extend_schema(
        responses={204: str},
    )
    def destroy(self, request, rule_id, format=None):
        """
        Delete an acknowledgement for a rule, by its rule ID.

        If the ack existed, it is deleted and a 204 is returned.  Otherwise,
        a 404 is returned.
        """
        # ack = get_object_or_404(
        #     Ack, rule__rule_id=rule_id, org_id=request.auth['org_id'],
        # )
        ack = self.get_object()
        ack.delete()
        return Response(
            status=status.HTTP_204_NO_CONTENT
        )


class AckCountViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Endpoint to retrieve the number of acks for each active rule

    param: rule_id: Get a count of acks for this rule_id
    """
    permission_classes = [IsRedHatInternalUser]
    # No resource_name - not using RBAC permissions
    serializer_class = AckCountSerializer
    queryset = (
        Rule.objects.filter(active=True)
        .annotate(ack_count=Count('ack'))
        .values('rule_id', 'ack_count')
    )
    lookup_field = 'rule_id'

    def retrieve(self, request, rule_id, format=None):
        """
        Get the ack count for the given rule_id

        Returns the rule_id and its ack count
        """
        rule_ack_count = self.get_object()
        return Response(rule_ack_count)

    @extend_schema(
        # Non-paginated list view
        responses={200: AckCountSerializer(many=True)}
    )
    def list(self, request, format=None):
        """
        Get the ack counts for all active rules

        Return a list of rule_ids and their ack counts
        """
        all_rule_ack_counts = self.queryset.order_by('rule_id')
        return Response(all_rule_ack_counts)
