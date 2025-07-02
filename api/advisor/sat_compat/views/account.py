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

from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from drf_spectacular.utils import extend_schema

from sat_compat.serializers import (
    SatAccountProductsSerializer, SatAccountSettingsSerializer
)


class AccountViewSet(ViewSet):
    """
    A simple one-stop shop for all your account needs.
    """
    permission_classes = []

    @extend_schema(
        responses={200: SatAccountProductsSerializer(many=False)},
    )
    @action(detail=False)
    def products(self, request, format=None):
        """
        This is the list of products available for this account.

        At the moment we just return a single value, 'rhel'.
        """
        return Response(SatAccountProductsSerializer(
            ['rhel']
        ).data)

    @extend_schema(
        responses={200: SatAccountSettingsSerializer(many=True)},
    )
    @action(detail=False, url_path='settings', url_name='settings')
    # Viewsets have a `settings` attribute which is the settings for DRF.
    # Overriding that causes pain and woe, so we change it in the action
    def setting(self, request, format=None):
        """
        The list of settings for this account.

        At the moment this just lists the 'Show Satellite Systems' setting
        as 'True'.
        """
        return Response(SatAccountSettingsSerializer(
            [{"name": "Show Satellite Systems", "value": True}],
            many=True
        ).data)
