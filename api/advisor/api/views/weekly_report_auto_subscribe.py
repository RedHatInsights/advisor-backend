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
from rest_framework import viewsets, status
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema

from api.models import WeeklyReportSubscription, SubscriptionExcludedAccount
from api.serializers import AutoSubscribeSerializer, AutoSubscribeInputSerializer
from api.permissions import ResourceScope, request_to_username
from api.utils import store_post_data
from api.wrs_utils import update_wrs

from advisor_logging import logger


class WeeklyReportAutoSubscribeViewSet(viewsets.ViewSet):
    """
    Allow Frontend to auto-subscribe the user to weekly email reports from Insights.
    """

    resource_name = "weekly-report-auto-subscribe"
    resource_scope = ResourceScope.ORG
    serializer_class = AutoSubscribeSerializer(many=False)

    def list(self, request, format=None):
        """
        Show the user's current subscription status.

        This shows the presence of a weekly report subscription by the user
        in this account.
        """
        return Response([
            AutoSubscribeSerializer(
                {
                    "org_id": request.auth["org_id"],
                    "is_auto_subscribed": WeeklyReportSubscription.objects.filter(
                        username=request_to_username(request),
                        org_id=request.auth["org_id"],
                        autosub=True,
                    ).exists()
                }
            ).data
        ])

    @extend_schema(
        request=AutoSubscribeInputSerializer,
        responses={200: AutoSubscribeSerializer(many=False)},
    )
    def create(self, request, format=None):
        """
        Set the auto-subscription status of the current user to the supplied
        `is_auto_subscribed` value.

        If 'is_auto_subscribed' is true, an auto-subscription is added if it doesn't
        already exist.  If it is false, the auto-subscription is removed if it
        exists.

        Check if ENABLE_AUTOSUB enviroment variable is set to allow the method.
        """
        org_id = request.auth["org_id"]
        account = request.account
        username = request_to_username(request)

        if not settings.ENABLE_AUTOSUB:
            result_msg = "Auto-subscription is not enabled on this enviroment"
            logger.warning(result_msg)
            return Response(
                data={"message": result_msg},
                status=status.HTTP_405_METHOD_NOT_ALLOWED,
            )

        if SubscriptionExcludedAccount.objects.filter(org_id=org_id).exists():
            result_msg = "Auto-subscription is excluded for this Org Id"
            logger.warning(result_msg)
            return Response(
                data={"message": result_msg},
                status=status.HTTP_405_METHOD_NOT_ALLOWED,
            )

        store_post_data(request, AutoSubscribeInputSerializer)
        serdata = AutoSubscribeInputSerializer(data=request.data)
        serdata.is_valid(raise_exception=True)
        subscribe = serdata.validated_data['is_auto_subscribed']

        update_wrs(
            username=username,
            account=account,
            sub_desired=subscribe,
            org_id=org_id,
            auto_subscribed=subscribe,
        )
        # Now return the new status.
        return Response(
            AutoSubscribeSerializer(
                {"org_id": org_id, "is_auto_subscribed": subscribe},
                many=False,
                context={"request": request},
            ).data
        )
