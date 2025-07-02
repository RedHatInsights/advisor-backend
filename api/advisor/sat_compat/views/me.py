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

from api.permissions import InsightsRBACPermission, CertAuthPermission, request_to_org

from sat_compat.serializers import SatMeSerializer


class MeView(ViewSet):
    """
    The only thing this provides is the account number, since that is the
    only thing that Satellite uses.
    """
    permission_classes = [InsightsRBACPermission | CertAuthPermission]

    @extend_schema(
        responses={200: SatMeSerializer(many=False)},
    )
    def list(self, request, format=None):
        """
        Display account information for the requesting user/system.

        Just returns the account number.
        """
        org_id = request_to_org(request)
        me = {'account_number': request.account, 'org_id': org_id}
        return Response(SatMeSerializer(me).data)
