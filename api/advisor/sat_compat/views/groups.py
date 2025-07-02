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

from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from drf_spectacular.utils import extend_schema

from sat_compat.serializers import SatGroupSerializer


class GroupsViewSet(ViewSet):
    """
    Satellite doesn't support doing anything with groups, so we just return
    an empty list.
    """
    permission_classes = []

    @extend_schema(
        responses={200: SatGroupSerializer(many=True)},
    )
    def list(self, request, format=None):
        """
        List the available groups.

        At the moment we do not support any groups, so this will be an empty
        list.
        """
        return Response(SatGroupSerializer([], many=True).data)
