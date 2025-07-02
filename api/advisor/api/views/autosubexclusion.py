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

from rest_framework import status, viewsets
from rest_framework.response import Response
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import value_of_param
from api.models import SubscriptionExcludedAccount
from api.permissions import (
    InsightsRBACPermission, IsRedHatInternalUser, set_resource
)
from api.serializers import (
    SubscriptionExcludedAccountSerializer
)
from api.utils import (
    PaginateMixin, CustomPageNumberPagination, store_post_data,
)


sort_fields = [
    'account', 'org_id'
]

sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    description="Order by this field",
    required=False,
    type=OpenApiTypes.STR,
    enum=sort_fields + ['-' + k for k in sort_fields],
    default='org_id'
)


class AutosubExclusionAdminPermission(IsRedHatInternalUser):
    list_method = ('Autosub Exclusion List', 'GET')
    create_method = ('Autosub Exclusion List', 'POST')
    retrieve_method = ('Autosub Exclusion Instance', 'GET')
    update_method = ('Autosub Exclusion Instance', 'PUT')
    delete_method = ('Autosub Exclusion Instance', 'DELETE')
    allowed_views = [list_method, create_method, retrieve_method, update_method, delete_method]


class AutosubExclusionViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    Gets the subscription(s) excluded for accounts

    This allows us to look up all accounts that are excluded
    from the autosubscription path for weekly report subscriptions.

    param: org_id: org_id for a subscription excluded.
    """
    queryset = SubscriptionExcludedAccount.objects.all()  # purely for schema generation - overriden below
    permission_classes = [InsightsRBACPermission | AutosubExclusionAdminPermission]
    lookup_field = 'org_id'
    serializer_class = SubscriptionExcludedAccountSerializer
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        sort = value_of_param(sort_query_param, self.request)
        query = SubscriptionExcludedAccount.objects.order_by(sort, 'org_id')
        return query

    @set_resource('denied')
    @extend_schema(
        parameters=[],
    )
    def retrieve(self, request, org_id, format=None):
        """
        Returns an individual subscription exclusion based on org_id.

        This returns an individual subscription exclusion
        based on the org_id.
        """
        exclusion = self.get_queryset().filter(org_id=org_id).first()
        if not exclusion:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(SubscriptionExcludedAccountSerializer(exclusion,
                        many=False, context={'request': request}).data)

    @set_resource('denied')
    @extend_schema(
        parameters=[],
    )
    def list(self, request, format=None):
        """
        Returns all subscription exclusions for accounts

        This returns a list of all subscription exclusions.
        This contains exclusions and their account and org_id.
        These are all accounts that are excluded from the autosub
        subscription path for weekly report subscriptions.
        """
        sort = value_of_param(sort_query_param, request)
        query = self.get_queryset()
        queryset = query.order_by(sort, 'org_id')
        return self._paginated_response(queryset, request)

    @set_resource('denied')
    @extend_schema(
        request=SubscriptionExcludedAccountSerializer,
        responses={
            200: SubscriptionExcludedAccountSerializer(many=False),
        }
    )
    def create(self, request, format=None):
        """
        Create a new subscription exclusion for an account.

        This creates a new subscription exclusion for an account.
        This should contain an org_id and account. Only org_id is required.
        Account is optional.
        """
        store_post_data(request, SubscriptionExcludedAccountSerializer)
        serdata = SubscriptionExcludedAccountSerializer(data=request.data)
        serdata.is_valid(raise_exception=True)

        new_exclusion, created = SubscriptionExcludedAccount.objects.update_or_create(
            org_id=serdata.validated_data['org_id'],
            account=serdata.validated_data['account']
        )
        return Response(SubscriptionExcludedAccountSerializer(
            new_exclusion, many=False, context={'request': request}
        ).data)

    @set_resource('denied')
    @extend_schema(
        responses={204: str},
    )
    def destroy(self, request, org_id, format=None):
        """
        Destroy an existing subscription exclusion in the system.

        This will DELETE an existing subscription exclusion
        in the system. Existing subscription exclusions
        are identified and deleted by the "org_id" field.
        """
        exclusoin = get_object_or_404(SubscriptionExcludedAccount, org_id=org_id)
        exclusoin.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
