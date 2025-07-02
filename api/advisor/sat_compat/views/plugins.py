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

from django.db.models import CharField, F, Func, Value
from django.utils.decorators import method_decorator

from rest_framework.viewsets import ReadOnlyModelViewSet

from drf_spectacular.utils import extend_schema

from api.models import Rule

from sat_compat.serializers import SatPluginSerializer
from sat_compat.utils import ClassicPageNumberPagination


@method_decorator(
    name='list',
    decorator=extend_schema(
        summary="List the plugin names and descriptions",
        description="Gives a contained list of plugin names and descriptions",
    )
)
@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="Retrieve a single plugin names and description",
        description="Gives a plugin name and description selected by plugin name"
    )
)
class PluginViewset(ReadOnlyModelViewSet):
    """
    Provide the 'plugin' name (a slug) and the description of the rules.
    """

    queryset = Rule.objects.filter(active=True).annotate(
        plugin=Func(
            F('rule_id'), Value('|'), Value(1), function='SPLIT_PART',
            output_field=CharField()
        ),
        name=F('description'),
    ).values('plugin', 'name').order_by('plugin', 'name')
    pagination_class = ClassicPageNumberPagination
    permission_classes = []
    serializer_class = SatPluginSerializer
