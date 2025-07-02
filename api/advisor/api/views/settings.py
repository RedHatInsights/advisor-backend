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

from api.permissions import InsightsRBACPermission
from api.serializers import SettingsDDFSerializer


class SettingsViewSet(viewsets.ViewSet):
    """
    Show all the settings for the Insights component.

    This produces a Data-Driven Forms format which describes the list of
    settings we have.  It can then input the settings in raw form.
    """
    resource_name = 'preferences'
    permission_classes = [InsightsRBACPermission]
    serializer_class = SettingsDDFSerializer

    def list(self, request, format=None):
        """
        Describe the settings we have in a Data-Driven Forms way.

        This simply compiles the 'show_satellite_hosts' account-wide setting
        into a format compatible with Data-Driven Forms.
        """
        # compile settings list - easy because we have none
        settings = []
        # The DDF specification seems to require a list of one element, which
        # has a 'fields' property listing the fields.
        return Response(SettingsDDFSerializer(
            [{'fields': settings}], many=True,
        ).data)
