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

from django.http import HttpResponseBadRequest
from rest_framework import viewsets
from rest_framework.response import Response

from api.serializers import ImportStatsSerializer
from api.scripts import import_content

from json import loads


class ImportContentViewSet(viewsets.ViewSet):
    """
    Imports content from the content server.
    """
    authentication_classes = []
    permission_classes = []
    # Don't generate an openapi/swagger schema
    schema = None

    def create(self, request):
        """
        Import content from the content server, by taking the given config
        and content and feeding them into the update functions directly.
        """
        if not ('config' in request.data and 'content' in request.data):
            # Data is not valid for some reason.
            return HttpResponseBadRequest(
                content=b"Config or content fields were not present"
            )

        if 'application/json' in request.content_type:
            # application/json is the recommended content-type for import content
            config_data = request.data['config']
            content_data = request.data['content']
        else:
            # Other content-types work but may have issues with high memory usage
            try:
                config_data = loads(request.data['config'])
                content_data = loads(request.data['content'])
            except:
                return HttpResponseBadRequest(
                    content=b"Could not read config and content as JSON"
                )

        # Some basic data checks:
        if not isinstance(config_data, dict):
            return HttpResponseBadRequest(
                content=b"Config parses as JSON but isn't a dictionary"
            )
        if 'resolution_risk' not in config_data:
            return HttpResponseBadRequest(
                content=b"Config parses as JSON but doesn't have resolution_risk data"
            )
        all_rule_apis_are_dicts = all(isinstance(rule_api, dict) for rule_api in content_data)
        all_rule_apis_have_rule_id = all('rule_id' in rule_api for rule_api in content_data)
        if not (isinstance(content_data, list) and all_rule_apis_are_dicts and all_rule_apis_have_rule_id):
            return HttpResponseBadRequest(
                content=b"Content parses as JSON but doesn't look like a list of rules"
            )
        # Rely on the import_content routines to validate the data.
        stats = import_content.import_all(config_data, content_data)
        return Response(ImportStatsSerializer({'stats': stats}).data)
