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

from django.utils.decorators import method_decorator
from rest_framework import viewsets
from drf_spectacular.utils import extend_schema

from api.models import SystemType
from api.serializers import SystemTypeSerializer


@method_decorator(
    name='list',
    decorator=extend_schema(
        summary="List all system types",
        description="List all system types by role and product code",
    )
)
@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="Retrieve a system type",
        description="Retrieve details of a single system type",
    )
)
class SystemTypeViewSet(viewsets.ReadOnlyModelViewSet):
    """
    System Types group systems by their nature (physical or virtual) and management method.
    """
    authentication_classes = []
    pagination_class = None
    permission_classes = []
    queryset = SystemType.objects.order_by('role', 'product_code')
    serializer_class = SystemTypeSerializer
