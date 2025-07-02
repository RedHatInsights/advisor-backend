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
from api.serializers import SettingsDDFSerializer, PreferencesInputSerializer
from api.permissions import (
    ResourceScope, has_rbac_permission, request_to_username,
)
from api.utils import store_post_data
from api.wrs_utils import update_wrs


class PreferencesViewSet(viewsets.ViewSet):
    """
    Show all the user preferences for the Insights component.

    This produces a Data-Driven Forms format which describes the list of
    settings we have.  It can then input the settings in raw form.

    We would recommend using the /weeklyreportsubscription API endpoint for
    API level control of these settings.  This output is merely for driving
    console.redhat.com internal forms.
    """
    resource_name = 'weekly-report'
    resource_scope = ResourceScope.ORG
    serializer_class = SettingsDDFSerializer

    def list(self, request, format=None):
        """
        Describe the settings we have in a Data-Driven Forms way.

        This simply compiles the 'show_satellite_hosts' account-wide setting
        and the weekly report 'is_subscribed' user-specific setting into one
        handy view, with the description metadata necessary to use Data-Driven
        Forms to display it.
        """
        username = request_to_username(request)
        org_id = request.auth['org_id']
        # compile settings list
        settings = []
        # Can this be a bit more ... data driven?
        if has_rbac_permission(
            username, org_id, 'advisor:weekly-report:*',
            request=request, account=request.account
        ):
            # Get weekly report subscription setting
            wrs_qs = WeeklyReportSubscription.objects.filter(username=username, org_id=org_id)
            is_subscribed = wrs_qs.exists()
            settings.append({
                'name': 'is_subscribed',
                'title': "Weekly report",
                'label': 'Weekly Report',
                'description': "Subscribe to this account's Advisor Weekly Report email",
                'helperText': "User-specific setting to subscribe a user to the account's weekly reports email",
                'component': 'descriptiveCheckbox',
                'isRequired': True,
                'initialValue': is_subscribed,
                'isDisabled': False,
            })
        # The DDF specification seems to require a list of one element, which
        # has a 'fields' property listing the fields.
        return Response(SettingsDDFSerializer(
            [{'fields': settings}], many=True,
        ).data)

    @extend_schema(
        request=PreferencesInputSerializer(many=False),
        responses={200: PreferencesInputSerializer(many=False)},
    )
    def create(self, request, format=None):
        """
        Accept the settings as input, and adjust the actual models accordingly.

        The current account settings will be updated, or one will be created,
        with the
        """
        username = request_to_username(request)
        store_post_data(request, PreferencesInputSerializer)
        serdata = PreferencesInputSerializer(data=request.data)
        serdata.is_valid(raise_exception=True)
        request_subbed = serdata.validated_data['is_subscribed']
        update_wrs(username, request.account, request_subbed, request.auth['org_id'])
        return Response(PreferencesInputSerializer(
            serdata.validated_data, many=False, context={'request': request},
        ).data)
