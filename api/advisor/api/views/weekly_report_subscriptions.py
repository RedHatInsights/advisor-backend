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

from rest_framework import viewsets
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema

from api.models import WeeklyReportSubscription
from api.serializers import WeeklyReportSubscriptionSerializer
from api.permissions import ResourceScope, request_to_username
from api.utils import store_post_data
from api.wrs_utils import update_wrs


class WeeklyReportSubscriptionViewSet(viewsets.ViewSet):
    """
    Allow a user to subscribe to weekly email reports from Insights.
    """
    resource_name = 'weekly-report'
    resource_scope = ResourceScope.ORG
    serializer_class = WeeklyReportSubscriptionSerializer(many=False)

    def list(self, request, format=None):
        """
        Show the user's current subscription status.

        This shows the presence of a weekly report subscription by the user
        in this account.
        """
        return Response(WeeklyReportSubscriptionSerializer(
            {'is_subscribed': WeeklyReportSubscription.objects.filter(
                username=request_to_username(request),
                org_id=request.auth['org_id'],
            ).exists()},
            many=False, context={'request': request}
        ).data)

    @extend_schema(
        request=WeeklyReportSubscriptionSerializer,
        responses={200: WeeklyReportSubscriptionSerializer(many=False)},
    )
    def create(self, request, format=None):
        """
        Set the subscription status of the current user to the supplied
        `is_subscribed` value.

        If 'is_subscribed' is true, a subscription is added if it doesn't
        already exist.  If it is false, the subscription is removed if it
        exists.
        """
        username = request_to_username(request)
        store_post_data(request, WeeklyReportSubscriptionSerializer)
        serdata = WeeklyReportSubscriptionSerializer(data=request.data)
        serdata.is_valid(raise_exception=True)
        request_subbed = serdata.validated_data['is_subscribed']
        update_wrs(username, request.account, request_subbed, request.auth['org_id'])
        # Now return the new status.
        return Response(WeeklyReportSubscriptionSerializer(
            {'is_subscribed': request_subbed},
            many=False, context={'request': request}
        ).data)
