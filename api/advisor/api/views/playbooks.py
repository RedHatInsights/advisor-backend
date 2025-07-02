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
from rest_framework.response import Response

from django.db.models import F
from django.shortcuts import get_object_or_404

from api.models import Rule, Playbook
from api.serializers import PlaybookSerializer


class PlaybooksViewSet(viewsets.ViewSet):
    """
    Gets the playbook(s) for individual rules or a list of all rules with their playbooks
    """
    authentication_classes = []
    permission_classes = []
    lookup_field = 'rule_id'
    # Don't generate an openapi/swagger schema
    schema = None

    @staticmethod
    def get_playbooks_for_rule(rule, request):
        playbooks = (
            Playbook.objects.filter(resolution__rule_id=rule)
            .annotate(
                resolution_risk=F('resolution__resolution_risk__risk'),
                resolution_type=F('type'))
            .order_by('resolution_type')
        )
        return PlaybookSerializer(playbooks, many=True, context={'request': request}).data

    def retrieve(self, request, rule_id, format=None):
        """
        Returns a list of playbooks for a particular rule_id, or an empty list [] if none
        eg: [{playbook1}, {playbook2}, etc...]
        """
        rule = get_object_or_404(Rule.objects.values('id'), rule_id=rule_id)
        return Response(self.get_playbooks_for_rule(rule['id'], request))

    def list(self, request, format=None):
        """
        Returns a dict of all rules with playbooks along with a list of their playbooks
        eg: {rule_id1: [{playbook1}, {playbook2}, etc...], rule_id2: [{playbook1}, etc...], etc...}
        """
        rules_with_playbooks = {
            rule['rule_id']: self.get_playbooks_for_rule(rule['id'], request)
            for rule in Rule.objects.filter(
                resolution__playbook__isnull=False
            ).distinct().values('id', 'rule_id')
        }
        return Response(rules_with_playbooks)
