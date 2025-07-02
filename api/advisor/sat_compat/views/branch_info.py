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

from sat_compat.serializers import SatBranchInfoSerializer


class BranchInfoViewSet(ViewSet):
    """
    A simple one-stop shop for all your branch information needs.
    """
    permission_classes = []

    @extend_schema(
        responses={200: SatBranchInfoSerializer(many=False)},
    )
    def list(self, request, format=None):
        """
        Return the branch information.

        At the moment this simply returns -1 for both remote branch and leaf.
        """
        return Response(SatBranchInfoSerializer({
            'remote_branch': -1, 'remote_leaf': -1
        }).data)
