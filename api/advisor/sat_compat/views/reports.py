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

from django.db.models import F, Prefetch
from django.utils.decorators import method_decorator

from rest_framework.viewsets import ReadOnlyModelViewSet

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema

from api.filters import (
    OpenApiParameter, branch_id_param, filter_on_param,
)
from api.models import CurrentReport, Host, get_reports_subquery
from api.utils import PaginateMixin
from sat_compat.serializers import SatReportSerializer
from sat_compat.utils import ClassicPageNumberPagination


rule_query_param = OpenApiParameter(
    name='rule', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Filter reports by this rule ID'
)


@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="A single report about a rule impacting a system",
        description="Describes a single report"
    )
)
class ReportsViewSet(ReadOnlyModelViewSet, PaginateMixin):
    """
    List and filter all reports for this account or view a single report.
    """
    queryset = CurrentReport.objects.all()
    pagination_class = ClassicPageNumberPagination
    serializer_class = SatReportSerializer

    def get_queryset(self):
        if hasattr(self, 'swagger_fake_view'):
            return CurrentReport.objects.none()

        return get_reports_subquery(
            self.request, rule__active=True,
        ).annotate(
            rule_name=F('rule__rule_id'),  # rule_id is a field already
            date=F('upload__checked_on'),
            insights_id=F('host__inventory__insights_id'),
        ).select_related('rule', 'upload').prefetch_related(
            Prefetch('host', queryset=Host.objects.annotate(
                system_id=F('inventory__insights_id'),
                display_name=F('inventory__display_name'),
                last_check_in=F('inventory__updated'),
            ))
        )

    @extend_schema(
        parameters=[rule_query_param, branch_id_param],
    )
    def list(self, request, format=None):
        """
        List the reports for this account.

        Reports can be filtered by rule ID.
        """
        reports = (
            self.get_queryset()
            .filter(filter_on_param('rule__rule_id', rule_query_param, request))
            .order_by('rule__rule_id', 'host__inventory__display_name')
        )
        return self._paginated_response(reports)
