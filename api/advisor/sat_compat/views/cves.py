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

from rest_framework.mixins import ListModelMixin
from rest_framework.viewsets import GenericViewSet

from api.models import CurrentReport
from api.utils import PaginateMixin

from sat_compat.serializers import SatReportSerializer
from sat_compat.utils import ClassicPageNumberPagination


class CVEViewSet(GenericViewSet, ListModelMixin, PaginateMixin):
    """
    CVEs are now handled by the Vulnerability app which is not provided in
    Classic.
    """
    queryset = CurrentReport.objects.none()
    pagination_class = ClassicPageNumberPagination
    permission_classes = []
    serializer_class = SatReportSerializer

    def list(self, request, format=None):
        """
        List the available CVEs.

        CVEs are now handled by the separate Vulnerability application and
        are no longer provided by Classic or Advisor.
        """
        return self._paginated_response(self.get_queryset())
