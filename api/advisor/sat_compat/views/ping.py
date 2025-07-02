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

from django.http.response import HttpResponse
# from rest_framework.response import Response
from rest_framework.viewsets import ViewSet


class PingViewSet(ViewSet):
    """
    The only thing this provides is a heart-beat.
    """
    authentication_classes = []
    permission_classes = []

    def list(self, request, format=None):
        """
        Provide a heart-beat signal.

        Just returns the string 'lub-dub', in accordance with tradition.
        """
        return HttpResponse('lub-dub', content_type='text/plain')
