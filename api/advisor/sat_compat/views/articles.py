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

from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from drf_spectacular.utils import extend_schema

from sat_compat.serializers import SatArticleOverviewSerializer


class ArticlesViewSet(ViewSet):
    """
    A simple one-stop shop for all your article needs.
    """
    permission_classes = []

    @extend_schema(
        responses={200: SatArticleOverviewSerializer(many=False)},
    )
    @action(detail=False, url_path='overview-satellite6')
    def overview_satellite6(self, request, format=None):
        """
        A list of articles giving an overview of Satellite 6 features.

        Just copying the ones given in Classic.
        """
        return Response(SatArticleOverviewSerializer({
            "content_html":
                "<p>Starting May 2019, your Smart Management "
                "subscription now includes Red Hat Satellite and new cloud "
                "management services for Red Hat Enterprise Linux. These "
                "services are hosted on console.redhat.com and include services "
                "for vulnerability, compliance, and system comparison. "
                "</p>\n<p>If your Red Hat Enterprise Linux environment needs "
                "a more traditional, on-premise management solution, then you "
                "can manage all your hosts with Red Hat Satellite. If you "
                "need a hosted, cloud-based management solution, then you can "
                "choose cloud management services for Red Hat Enterprise "
                "Linux. In some cases, you might need to manage part of your "
                "environment on-premise while managing other parts of your "
                "environment using a hosted management tool. Red Hat Smart "
                "Management gives you that flexibility.</p>\n<ul>\n<li>"
                "<a href=\"https://access.redhat.com/products/cloud_management_services_for_rhel/#getstarted\">Get "
                "started</a> with the cloud management services for RHEL "
                "</li>\n<li>Visit our "
                "<a href=\"https://www.redhat.com/en/technologies/management/smart-management\">Smart "
                "management webpage</a> to get more details on these services "
                "</li>\n</ul>\n",
            "id": "overview-satellite6",
            "title": "New SaaS services now part of your Red Hat Smart Management subscription:",
            "content":
                "Starting May 2019, your Smart Management subscription "
                "now includes Red Hat Satellite and new cloud management "
                "services for Red Hat Enterprise Linux. These services are "
                "hosted on console.redhat.com and include services for "
                "vulnerability, compliance, and system comparison. \n\nIf "
                "your Red Hat Enterprise Linux environment needs a more "
                "traditional, on-premise management solution, then you can "
                "manage all your hosts with Red Hat Satellite. If you need a "
                "hosted, cloud-based management solution, then you can choose "
                "cloud management services for Red Hat Enterprise Linux. In "
                "some cases, you might need to manage part of your "
                "environment on-premise while managing other parts of your "
                "environment using a hosted management tool. Red Hat Smart "
                "Management gives you that flexibility.\n\n* [Get "
                "started](https://access.redhat.com/products/cloud_management_services_for_rhel/#getstarted) "
                "with the cloud management services for RHEL \n* Visit our "
                "[Smart management webpage](https://www.redhat.com/en/technologies/management/smart-management) "
                "to get more details on these services "
        }).data)
