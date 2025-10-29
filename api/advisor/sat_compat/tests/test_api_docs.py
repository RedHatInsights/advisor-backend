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

from api.tests.test_api_docs import APIDocsTestCase


class SatCompatAPIDocsTestCase(APIDocsTestCase):
    schema_path_name = 'sat-compat-openapi-spec'

    list_views_no_pagination_check = {
        '/r/insights/v3/articles/overview-satellite6',
        '/r/insights/v3/evaluation/status',
    }

    def test_schema_has_docs_with_rbac(self):
        # We don't really use RBAC for access to the Sat-Compat API, and the
        # view list we need to check is different.
        pass

    def test_schema_has_is_internal_views(self):
        # We don't really use RBAC for access to the Sat-Compat API, and the
        # view list we need to check is different.
        pass

    def test_stats_views_take_parameters(self):
        # We don't have the same paths, and we don't have the same schema
        # problems.
        pass
