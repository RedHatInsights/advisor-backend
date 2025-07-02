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

from collections import OrderedDict

from django.core.paginator import InvalidPage

from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

##############################################################################
# Pagination
##############################################################################


class ClassicPageNumberPagination(PageNumberPagination):
    """
    Pagination as per Classic with page number and size parameters."""
    page_query_param = 'page'
    page_size_query_param = 'page_size'

    def paginate_queryset(self, queryset, request, view=None):
        """
        Direct copy of paginate_queryset because we need to fix `page=0` and
        there's no 'get_page' method (yet) to override.
        """
        page_size = self.get_page_size(request)
        if not page_size:
            return None

        paginator = self.django_paginator_class(queryset, page_size)
        page_number = request.query_params.get(self.page_query_param, 0)
        if page_number in self.last_page_strings:
            page_number = paginator.num_pages
        # Pages here number from 1, in the old API they number from 0.
        # So we offset up to compensate for the offset down in paginator.
        page_number = int(page_number) + 1

        try:
            self.page = paginator.page(page_number)
        except InvalidPage as exc:
            msg = self.invalid_page_message.format(
                page_number=page_number, message=str(exc)
            )
            raise NotFound(msg)

        if paginator.num_pages > 1 and self.template is not None:
            # The browsable API should display pagination controls.
            self.display_page_controls = True

        self.request = request
        return list(self.page)

    def get_paginated_response(self, data):
        """
        Format the paginated response in the way Classic does.
        """
        return Response(OrderedDict([
            ('total', self.page.paginator.count),
            ('resources', data),
        ]))

    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object', 'properties': {
                'total': {'type': 'integer', 'examples': '23'},
                'resources': schema
            }
        }


class ClassicFakePagination(ClassicPageNumberPagination):
    """
    The `/rules` list is actually not paginated but has the same 'total'
    and 'resources' structure.  So we need to pretend its paginated but not
    do any actually pagination on the response.  We inherit the same schema
    as ClassicPageNumberPagination.
    """
    def paginate_queryset(self, queryset, request, view=None):
        return queryset

    def get_paginated_response(self, data):
        """
        Just count the data here since we have no paginator.
        """
        return Response(OrderedDict([
            ('total', len(data)),
            ('resources', data),
        ]))
