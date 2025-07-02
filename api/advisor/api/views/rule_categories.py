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

from api.models import RuleCategory
from api.serializers import RuleCategorySerializer


class RuleCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Rules are divided into categories, the usual being Availability,
    Stability, Security and Performance.

    Categories are listed in decreasing order of importance.
    """
    authentication_classes = []
    pagination_class = None
    permission_classes = []
    queryset = RuleCategory.objects.all()
    serializer_class = RuleCategorySerializer
