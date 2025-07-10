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

from django.utils.decorators import method_decorator

from rest_framework import status, viewsets
from rest_framework.response import Response
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import (
    filter_on_param, host_tags_query_param,
    filter_multi_param, filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    host_group_name_query_param, filter_on_host_tags
)
from api.models import (
    HostAck, stale_systems_q
)
from api.permissions import (
    request_to_username, InsightsRBACPermission, CertAuthPermission,
    request_to_org, IsRedHatInternalUser, ResourceScope,
)
from api.serializers import (
    HostAckSerializer, HostAckInputSerializer,
    HostAckJustificationSerializer
)
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, store_post_data,
)


rule_id_param = OpenApiParameter(
    name='rule_id', location=OpenApiParameter.QUERY,
    description="Display host acknowledgement of this/these rules",
    required=False,
    many=True, type=OpenApiTypes.REGEX, pattern=r'\w+(,\w+)*', style='form',
)


class RedHatAllAcksPermission(IsRedHatInternalUser):
    allowed_views = ['All', ]


# We use a ReadOnlyModelViewSet for the list and retrieve, and then add our
# own delete and create methods which only need rule ID, system UUID and account.
@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="Display a specific acknowledgement (disabling) of a rule on a system",
        description="""
        Display who disabled a rule on a system, when, and their justification
        for disabling it.  Host acks are selected by their ID number.
        """,
    )
)
class HostAckViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    HostAcks acknowledge (and therefore hide) a rule from view in an account
    for a specific system.

    This viewset handles listing, retrieving, creating and deleting hostacks.
    """
    queryset = HostAck.objects.filter(rule__deleted_at__isnull=True, rule__active=True)
    permission_classes = [InsightsRBACPermission | CertAuthPermission | RedHatAllAcksPermission]
    pagination_class = CustomPageNumberPagination
    resource_name = 'disable-recommendations'
    resource_scope = ResourceScope.ORG  # Host?
    serializer_class = HostAckSerializer

    def get_queryset(self):
        """
        Get the rule acknowledgements queryset for this account, and host, for active,
        non-deleted rules, based on the request's account org_id params.
        """
        # Unfortunately, we have to assume here that the user might not be
        # authenticated because in schema generation, because we don't set a
        # URL kwarg, this function is called to try and determine the
        # underlying model and find out if it uses a non-standard name for
        # its primary key.  This is the least-pain defence against that.
        swagger_fake_view = getattr(self, 'swagger_fake_view', False)
        org_id = request_to_org(self.request) if not swagger_fake_view else None
        return self.queryset.filter(
            stale_systems_q(org_id, field='host_id'),
            # TODO should filter on host groups too, to prevent acking a host you dont have access to, or seeing acks for hosts you no longer have access to
            org_id=org_id
        )

    @extend_schema(
        parameters=[
            rule_id_param, host_tags_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            host_group_name_query_param,
        ],
    )
    def list(self, request, format=None):
        """
        HostAcks acknowledge (and therefore hide) a rule from view in an
        account for a specific system.

        Hostacks are retrieved, edited and deleted by the 'id' field.
        """
        system_profile_filter = filter_multi_param(
            request, 'system_profile', field_prefix='host__inventory'
        )
        qs = self.get_queryset().filter(
            filter_on_param('rule__rule_id', rule_id_param, request),
            filter_on_host_tags(request, field_name='host_id'),
            system_profile_filter,
        )
        return self._paginated_response(qs, request)

    @extend_schema(
        request=HostAckInputSerializer,
        responses={
            200: HostAckSerializer(many=False),
        }
    )
    def create(self, request, format=None):
        """
        Add an acknowledgement for a rule, by rule ID, system, and account.

        Return the new hostack.  If there's already an acknowledgement of
        this rule by this account for a system, then return that.  This does
        not take an 'id' number.
        """
        # If we can't deserialize the hostack information, then return a 400 now
        store_post_data(request, HostAckInputSerializer)
        hostack_serdata = HostAckInputSerializer(data=request.data)
        hostack_serdata.is_valid(raise_exception=True)
        rule = hostack_serdata.validated_data['rule']
        acked_uuid = hostack_serdata.validated_data['host_id']
        new_host_ack, updated = self.get_queryset().update_or_create(
            org_id=request.auth['org_id'], host_id=acked_uuid, rule=rule,
            defaults={
                'account': request.account,  # Remove at a later time, keep for now for potential backwards compat
                'justification': hostack_serdata.validated_data.get('justification', ''),
                'created_by': request_to_username(request),
            }
        )
        return Response(HostAckSerializer(
            new_host_ack, many=False, context={'request': request}
        ).data)

    @extend_schema(
        request=HostAckJustificationSerializer,
        responses={200: HostAckJustificationSerializer(many=False)}
    )
    def update(self, request, pk, format=None, partial=False):
        """
        Update the justification for this host acknowledgement.

        The justification is taken from the request body.  The created_by
        field is taken from the username in the x-rh-identity field, and the
        updated_at field is set to the current time.
        """
        # This also sets the rh_identity property on the request object so we
        # can look up the user name from it.
        hostack = self.get_object()
        store_post_data(request, HostAckJustificationSerializer)
        serdata = HostAckJustificationSerializer(
            instance=hostack, data=request.data,
        )
        # If validation failed, raise an exception here.
        serdata.is_valid(raise_exception=True)
        hostack.justification = serdata.validated_data.get('justification', '')
        hostack.created_by = request_to_username(request)
        hostack.save()

        return Response(HostAckJustificationSerializer(
            hostack, many=False, context={'request': request}
        ).data)

    @extend_schema(
        responses={204: str},
    )
    def destroy(self, request, pk):
        """
        Delete an acknowledgement for a rule, for a system, for an account, by its ID.

        Takes the hostack ID (given in the hostack list) as an identifier.
        """
        hostack = self.get_object()
        hostack.delete()
        return Response(
            status=status.HTTP_204_NO_CONTENT
        )
