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

import re
from collections import OrderedDict
import time
from django.conf import settings
from django.db.models import (
    Avg, BooleanField, Case, CharField, Exists, F,
    OuterRef, Prefetch, Q, Subquery, Value, When,
)
from django.db.models.functions import Concat
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework_yaml.renderers import YAMLRenderer
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from rest_framework.viewsets import GenericViewSet
from rest_framework_csv.renderers import CSVRenderer

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiResponse, extend_schema

from advisor_logging import logger

from api.filters import (
    value_of_param, branch_id_param, required_branch_id_param,
    OpenApiParameter,
)
from api.models import Ack, Host, InventoryHost, Playbook, Rule
from api.permissions import (
    request_to_username, http_auth_header_key, auth_header_key, request_to_org
)
from api.utils import retry_request, store_post_data

from sat_compat.models import SatMaintenance, SatMaintenanceAction
from sat_compat.serializers import (
    SatMaintenanceSerializer, SatMaintenanceActionSimpleSerializer,
    SatMaintenancePlaySerializer, SatMaintenanceNewMaintenancePlanSerializer,
    SatMaintenanceEditSerializer, SatMaintenanceActionCSVSerializer,
    SatMaintenanceActionAddPlaybookSerializer, SatMaintenanceAddSerializer,
    DRF400ErrorSerializer,
)
from sat_compat.views.systems import isCheckingIn_case


accept_query_param = OpenApiParameter(
    name='accept', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Set output format type (json or CSV)',
    enum=('json', 'csv'), default='json',
)
rule_id_param = OpenApiParameter(
    name='rule_id', location=OpenApiParameter.PATH,
    type=OpenApiTypes.STR, required=True,
    description='Insights Rule ID', pattern=r'\w+\|[\w-]+',
)
system_type_id_param = OpenApiParameter(
    name='system_type_id', location=OpenApiParameter.PATH,
    type=OpenApiTypes.INT, required=True,
    description='System type number',
)


class PlanCSVRenderer(CSVRenderer):
    header = [
        'display_name', 'insights_id', 'description', 'category',
        'severity', 'article', 'completed', 'start', 'end',
    ]
    labels = {
        'display_name': 'Hostname',
        'insights_id': 'Machine ID',
        'description': 'Description',
        'category': 'Category',
        'severity': 'Severity',
        'article': 'Article',
        'completed': 'Completed',
        'start': 'Scheduled start (UTC)',
        'end': 'Scheduled end (UTC)',
    }


TEST_PLAYBOOK = """---
# Red Hat Insights has recommended one or more actions for you, a system administrator

- name: run insights to obtain latest report info
  hosts: "ceeph.jaylin.org,mhuth-laptop,rhel6-box,rhel7-box"
  become: True
  tasks:
    - name: determine insights version
      shell: 'redhat-access-insights --version'
      changed_when: false
      register: insights_version

# New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled
# Identifier: (ansible_deprecated_repo|ANSIBLE_DEPRECATED_REPO,105,fix)
# Version: ee6c70ac35309b933d79147388f9c703d3c68b25
- name: Enable ansible repo and update ansible package
  hosts: "ceeph.jaylin.org,mhuth-laptop"
  become: true

  tasks:
    - name: Enable ansible repo
      command: subscription-manager repos --enable=rhel-7-server-ansible-2-rpms
      register: command_result
      changed_when: command_result.rc == 0

    - name: Update ansible package
      yum:
        name: ansible
        state: latest

- name: run insights
  hosts: "ceeph.jaylin.org,mhuth-laptop,rhel6-box,rhel7-box"
  become: True
  gather_facts: False
  tasks:
    - name: run insights
      command: redhat-access-insights
      changed_when: false
    """


def hosts_for_rules_in_plan(plan, use_inventory_id=False, **plan_filters):
    """
    Create a lookup table for the hosts in each rule in a plan.

    We use this both in getting the playbook and in deduplicating hosts being
    added to actions in a plan.
    """
    hosts_for_rule = OrderedDict()
    # Don't need to deduplicate here, it's already been deduplicated.
    for act in plan.actions.filter(**plan_filters).order_by(
        'rule__rule_id', 'host__inventory__display_name'
    ):
        if act.rule.rule_id not in hosts_for_rule:
            # Store the action data as well as the hosts list.
            hosts_for_rule[act.rule.rule_id] = {
                'action': act, 'hosts': []
            }
        hosts_for_rule[act.rule.rule_id]['hosts'].append(str(
            act.host_id if use_inventory_id else act.host.inventory.insights_id
        ))
    return hosts_for_rule


def get_playbook(plan, request):
    """
    Take this plan, mangle it into something that Remediations recognises,
    request a playbook from them, and return it as is.
    """
    # Note that the URL here is a 'base' URL (AFAICS).
    # Note that this has to be done here at run time, rather than once at
    # start up, because otherwise the tests can't override the setting.
    # Only get actions with current rules that have a playbook.
    hosts_for_rule = hosts_for_rules_in_plan(
        plan, use_inventory_id=True, rule__active=True,
        rule__resolution__playbook__isnull=False
    )
    # Now create the plan data request from that

    def issue_data(rule_id, meta):
        value = {
            'id': 'advisor:' + rule_id,
            'systems': meta['hosts'],
        }
        if meta['action'].playbook:
            value['resolution'] = meta['action'].playbook.type
        return value

    plan_data = {
        'issues': [
            issue_data(rule_id, meta)
            for rule_id, meta in hosts_for_rule.items()
        ],
        'auto_reboot': plan.allow_reboot,
    }
    if settings.REMEDIATIONS_URL is None:
        logger.error("REMEDIATIONS_URL is not set")
        return False
    PLAYBOOK_URL = settings.REMEDIATIONS_URL + '/api/remediations/v1/playbook'
    response, elapsed = retry_request(
        'Remediations', PLAYBOOK_URL, mode='post',
        json=plan_data,
        headers={http_auth_header_key: request.META[auth_header_key]}
    )
    if response is None:
        return False
    elif response.status_code != 200:
        logger.error(f"Request to {PLAYBOOK_URL} returned {response.status_code}: {response.content.decode()}")
        return False
    else:
        logger.info(f"Request to {PLAYBOOK_URL} on plan {plan.id} took {elapsed:.2f} seconds")
        return response.content.decode()


def add_actions(plan_obj, validated_actions, request):
    """
    Add actions for the given plan from a validated 'add' list.  Actions
    without a system will be expanded into a list of systems of this
    Satellite currently impacted by the given rule .  This is used when both
    creating and updating plans.

    We do not add actions if there is already an action for this host on that
    rule, either in this set of validated actions or in the plan, if we're
    updating it.
    """
    # Gather the hosts for the rules in the plan's existing actions.
    hosts_for_rule = hosts_for_rules_in_plan(plan_obj)
    actions = []
    for action_data in validated_actions:
        rule = Rule.objects.get(rule_id=action_data['rule_id'])
        # Ignore inactive rules when adding
        if not rule.active:
            continue
        if 'system_id' in action_data:
            # This is an insights_id
            insights_ids = [action_data['system_id']]
        else:
            # Therefore these need to be insights_ids
            insights_ids = rule.reports_for_account(  # Will need to rename/redo this function after adoption
                request,
            ).filter(
                # Only hosts which are owned by this Satellite
                host__branch_id=plan_obj.branch_id
            ).values_list(
                'host__inventory__insights_id', flat=True
            ).distinct()
        if rule.rule_id not in hosts_for_rule:
            hosts_for_rule[rule.rule_id] = {'hosts': []}
        for host in Host.objects.filter(
            inventory__insights_id__in=insights_ids,
            inventory__account=request.account,  # To be replaced with org_id after adoption
        ).exclude(
            inventory__insights_id__in=hosts_for_rule[rule.rule_id]['hosts']
        ).select_related('inventory').order_by('inventory__display_name'):
            actions.append(
                SatMaintenanceAction(plan=plan_obj, rule=rule, host=host)
            )
            hosts_for_rule[rule.rule_id]['hosts'].append(str(host.inventory.insights_id))
    SatMaintenanceAction.objects.bulk_create(actions)


class MaintenanceViewSet(GenericViewSet):
    """
    Maintenance plans group together one or more maintenance actions into a
    unit that is executed by the user, usually involving generating and
    executing an Ansible playbook.

    """
    pagination_class = None
    queryset = SatMaintenance.objects.all()
    serializer_class = SatMaintenanceSerializer
    # For handling the plays_set_playbook view
    extra_path_params = []

    def get_queryset(self):
        if hasattr(self, 'swagger_fake_view'):
            return SatMaintenance.objects.none()
        org_id = request_to_org(self.request)
        plan_filter = Q(org_id=org_id)
        action_host_filter = Q()
        branch_id_value = value_of_param(branch_id_param, self.request)
        if branch_id_value:
            plan_filter &= Q(branch_id=branch_id_value)
        # For ansible information on the rule
        playbook_subquery = Playbook.objects.filter(
            resolution__rule_id=OuterRef('id')
        ).values('id')
        # If Inventory deletes a host, then the action's host ends up null.
        # But because of the OneToOneField, we can't test for that directly.
        # We have to filter actions to be on hosts that exist in Inventory.
        if not org_id:
            return self.queryset.none()
        acct_org_id_hosts_qs = InventoryHost.objects.filter(
            org_id=org_id
        ).values('id')
        acks_qs = Ack.objects.filter(org_id=org_id).values('rule_id')
        # Note that we filter acks and not hostacks because Satellite can't
        # set or remove host acks, which is why they don't have a branch ID.
        return (
            self.queryset
            .filter(plan_filter)
            .prefetch_related(
                Prefetch(
                    'actions',
                    queryset=SatMaintenanceAction.objects.filter(
                        action_host_filter,
                        host_id__in=acct_org_id_hosts_qs, rule__active=True
                    ).exclude(
                        rule__in=Subquery(acks_qs),
                    ).order_by('rule__rule_id', 'host__inventory__display_name')
                ),
                Prefetch(
                    'actions__host', queryset=Host.objects.filter(
                        upload__current=True, inventory_id__in=acct_org_id_hosts_qs,
                    ).select_related('inventory').annotate(
                        display_name=F('inventory__display_name'),
                        isCheckingIn=isCheckingIn_case('inventory'),
                        system_type_id=F('upload__system_type_id'),  # see filter above
                        last_check_in=F('inventory__updated'),
                    )
                ),
                Prefetch(
                    'actions__rule', queryset=Rule.objects.filter(
                        active=True
                    ).annotate(
                        category_name=F('category__name'),  # Reduces serializer queries
                        rec_impact=F('impact__impact'),  # Reduces serializer queries
                        ansible=Exists(
                            playbook_subquery,
                            output_field=BooleanField()
                        ),
                        ansible_fix=Exists(
                            playbook_subquery.filter(type='fix'),
                            output_field=BooleanField()
                        ),
                        ansible_mitigation=Exists(
                            playbook_subquery.filter(type__in=('workaround', 'mitigate')),
                            output_field=BooleanField()
                        ),
                    ).select_related('category')
                ),
            )
            .order_by('id')
        )

    @extend_schema(
        parameters=[branch_id_param],
    )
    def list(self, request, format=None):
        """
        List the maintenance plans currently available for this Satellite.
        """
        plans_qs = self.get_queryset()
        return Response(SatMaintenanceSerializer(
            plans_qs, many=True
        ).data)

    @extend_schema(
        parameters=[branch_id_param, accept_query_param],
    )
    def retrieve(self, request, pk, format=None):
        """
        Retrieve details of a single maintenance action.
        """
        org_id = request_to_org(request)
        plan = get_object_or_404(
            self.get_queryset(),
            pk=pk, org_id=org_id
        )
        accept_param = value_of_param(accept_query_param, request)
        if accept_param == 'json':
            return Response(SatMaintenanceSerializer(plan, many=False).data)

        # Output just the action details in CSV format
        actions_qs = plan.actions.annotate(
            display_name=F('host__inventory__display_name'),
            insights_id=F('host__inventory__insights_id'),
            description=F('rule__description'),
            category=F('rule__category__name'),
            severity=F('rule__total_risk'),
            article=Case(
                When(rule__node_id='', then=Value('')),
                default=Concat(
                    Value('https://access.redhat.com/node/'), 'rule__node_id'
                ),
                output_field=CharField()
            ),
            completed=F('done'),
            start=F('plan__start'),
            end=F('plan__end'),
        )
        response = Response(
            SatMaintenanceActionCSVSerializer(actions_qs, many=True).data,
        )
        response['Content-Disposition'] = f'attachment; filename="plan_{pk}_{timezone.now():%Y-%m-%d}.csv"'
        # Force the use of CSV as output - have to set request's
        # accepted_renderer and accepted_media_type due to finalize_response
        request.accepted_renderer = PlanCSVRenderer()
        request.accepted_media_type = 'text/csv'
        return response
        # Note that we don't attempt to provide this as an alternate schema.

    @extend_schema(
        request=SatMaintenanceAddSerializer,
        parameters=[required_branch_id_param],
        responses={201: SatMaintenanceNewMaintenancePlanSerializer}
    )
    def create(self, request, format=None):
        """
        Create a new maintenance plan.

        This basically takes a name and the 'add' field, which is a list of
        actions.  Each action can be either a rule_id and host_id to
        remediate that rule on that host, or just a rule_id to remediate that
        rule on all hosts.

        Branch ID (i.e. Satellite ID) must be specified.
        """
        org_id = request_to_org(request)
        branch_id = value_of_param(required_branch_id_param, request)
        store_post_data(request, SatMaintenanceAddSerializer)
        plan = SatMaintenanceAddSerializer(data=request.data)
        plan.is_valid(raise_exception=True)

        # Because the SatMaintenance object doesn't have an 'add' field,
        # though, remove it and process it separately
        validated_actions = plan.validated_data['add']
        del plan.validated_data['add']
        plan.validated_data['org_id'] = org_id
        if request.account:
            plan.validated_data['account'] = request.account
        plan.validated_data['branch_id'] = branch_id
        # If Cert auth, no username...
        plan.validated_data['created_by'] = request_to_username(request)
        plan_obj = SatMaintenance(**plan.validated_data)
        plan_obj.save()
        add_actions(plan_obj, validated_actions, request)

        return Response(
            SatMaintenanceNewMaintenancePlanSerializer(plan_obj, many=False).data,
            status=HTTP_201_CREATED
        )

    @extend_schema(
        request=SatMaintenanceEditSerializer,
        parameters=[required_branch_id_param],
        responses={200: SatMaintenanceSerializer}
    )
    def update(self, request, pk, format=None):
        """
        Update a maintenance plan.

        This can be used to both edit the plan's details, and to add to and
        delete from the plan's actions.
        """
        org_id = request_to_org(request)
        value_of_param(required_branch_id_param, request)
        # value_of_param catches the 'required=True' in the parameter
        # Get current plan
        plan = get_object_or_404(self.get_queryset(), org_id=org_id, pk=pk)
        # Check validity of update:
        store_post_data(request, SatMaintenanceEditSerializer)
        update = SatMaintenanceEditSerializer(data=request.data)
        update.is_valid(raise_exception=True)
        # Update plan itself:
        plan_updated = False
        for field in ('name', 'description', 'start', 'end', 'silenced', 'hidden'):
            if field in update.validated_data:
                value = update.validated_data[field]
                if getattr(plan, field) != value:
                    setattr(plan, field, value)
                    plan_updated = True
        # Temp implementation for storing org_ids until full adoption
        if not plan.org_id:
            plan.org_id = request.auth['org_id']
            plan_updated = True
        if plan_updated:
            plan.save()
        # Update the actions - delete, then actions, then add.
        if 'delete' in update.validated_data:
            plan_updated = True
            plan.actions.filter(id__in=update.validated_data['delete']).delete()
        if 'actions' in update.validated_data:
            plan_updated = True
            plan.actions.exclude(id__in=update.validated_data['actions']).delete()
        if 'add' in update.validated_data:
            plan_updated = True
            add_actions(plan, update.validated_data['add'], request)
        if plan_updated:
            # Can't use refresh_from_db here because of the prefetches.
            plan = self.get_queryset().get(org_id=org_id, pk=pk)

        return Response(SatMaintenanceSerializer(plan).data)

    def destroy(self, request, pk, format=None):
        """
        Delete an existing maintenance plan.

        All actions associated with this plan are also deleted.
        """
        org_id = request_to_org(request)
        plan = get_object_or_404(SatMaintenance, org_id=org_id, pk=pk)
        plan.delete()
        return Response(status=HTTP_204_NO_CONTENT)

    @extend_schema(
        responses={200: OpenApiResponse(description='YAML content')}
    )
    # If we put the YAML renderer first, then any authentication failures
    # end up raising a 500 exception because it doesn't handle the
    # authentication exception objects correctly.
    @action(detail=True, renderer_classes=[JSONRenderer, YAMLRenderer])
    def playbook(self, request, pk, format=None):
        """
        Return the Ansible Playbook for this maintenance plan, in YAML.

        Actions in this plan that do not have playbooks will be ignored.
        """
        # For some reason the YAML renderer does not behave well with
        # get_object_or_404 so we have to do that ourselves.
        org_id = request_to_org(request)
        try:
            plan = self.get_queryset().get(
                pk=pk, org_id=org_id
            )
        except SatMaintenance.DoesNotExist:
            raise Http404("Plan not found")
        # Get the playbook
        playbook = get_playbook(plan, request)
        if not playbook:
            raise ValidationError("Unable to generate playbook")

        # And render it.  Since we've already got YAML formatted text,
        # we get the response to do its job and then replace the content
        # with the formatted playbook.  This preserves all the nice
        # comments and ordering and spacing and stuff.
        file_name = plan.name.lower().strip()
        file_name = ''.join(file_name.split())  # remove white space
        file_name = re.sub(r'[^\w-]', '', file_name)  # only alphanumeric, hyphens or underscore
        response = Response([], headers={
            'Content-Type': 'text/vnd.yaml; charset=utf-8',
            'Content-Disposition': f'attachment;filename="{file_name}-{plan.id}-{round(time.time() * 1000)}.yml"',
        })
        response.content = playbook
        return response

    @extend_schema(
        responses={200: SatMaintenancePlaySerializer(many=True)}
    )
    @action(detail=True, url_path='playbook/plays')
    def plays(self, request, pk, format=None):
        """
        List the metadata of the plays in this maintenance plan.

        This gives the rule and the list of Ansible resolutions available for
        each action in the plan.
        """
        # Do we need to use branch ID here?
        org_id = request_to_org(request)
        plan = get_object_or_404(
            self.get_queryset(),
            pk=pk, org_id=org_id
        )
        # This list of actions will have one action per host per rule, and we
        # want to output this list per rule.  I think this means, therefore,
        # that we have to collect the list of rules in this plan, make that
        # unique on rule and collect the hosts for each rule (for their system
        # type), and then construct the list of plays by fetching the rule
        # resolution data for those rules in turn.
        # Note: we don't yet handle actions that have a playbook
        system_types_for_rule = OrderedDict()
        all_system_types = set()
        # Annoying: have to get the system type from the upload...
        for act in (
            plan.actions
            .order_by('rule__rule_id')
            .filter(host__upload__current=True, host__upload__source_id=1)
            .values('rule_id', 'host__upload__system_type')
            .distinct()
        ):
            rid = act['rule_id']  # ID number because of fast Rule look up
            system_type = act['host__upload__system_type']
            if rid not in system_types_for_rule:
                system_types_for_rule[rid] = []
            # Thanks to distinct, just append
            system_types_for_rule[rid].append(system_type)
            all_system_types.add(system_type)

        # Now get the rule and resolution information for those rules...
        # Do it in one query and then break it down in code
        play_list = [
            {
                'system_type_id': system_type,
                'rule': rule,
                'ansible_resolutions': rule.playbooks().filter(
                    resolution__system_type_id=system_type
                ),
            }
            for rule in Rule.objects.filter(
                id__in=system_types_for_rule.keys(),
                resolution__system_type__in=all_system_types
            ).annotate(
                category_name=F('category__name'),
                risk_level=Avg(
                    'resolution__resolution_risk__risk',
                    filter=Q(resolution__system_type_id__in=all_system_types)
                )
            ).order_by('rule_id')
            for system_type in system_types_for_rule[rule.id]
        ]

        return Response(SatMaintenancePlaySerializer(
            play_list, many=True
        ).data)

    @action(
        detail=True,
        extra_path_params=[rule_id_param, system_type_id_param],
        url_path='playbook/plays',
        methods={'put'},
    )
    @extend_schema(
        parameters=[rule_id_param, system_type_id_param],
        request=SatMaintenanceActionAddPlaybookSerializer,
        responses={
            200: SatMaintenanceActionSimpleSerializer(many=True),
        }
    )
    def plays_set_playbook(
        self, request, pk, format=None,
        rule_id=None, system_type_id=None,
    ):
        """
        List the metadata of the plays in this maintenance plan.

        This gives the rule and the list of Ansible resolutions available for
        each action in the plan.
        """
        # Do we need to use branch ID here?
        org_id = request_to_org(request)
        plan = get_object_or_404(
            self.get_queryset(),
            pk=pk, org_id=org_id
        )
        actions = plan.actions.filter(
            rule__rule_id=rule_id,
            rule__resolution__system_type_id=int(system_type_id),
        )
        if not actions.exists():
            raise Http404('Actions in this plan with the given rule ID and resolution system type do not exist')
        store_post_data(request, SatMaintenanceActionAddPlaybookSerializer)
        serdata = SatMaintenanceActionAddPlaybookSerializer(data=request.data)
        serdata.is_valid(raise_exception=True)
        try:
            playbook = Playbook.objects.get(
                resolution__rule__rule_id=rule_id,
                type=serdata.validated_data['resolution_type']
            )
        except Playbook.DoesNotExist:
            return Response(DRF400ErrorSerializer(
                {'errors': ['Resolution type specified does not exist']}
            ).data, status=400)
        # Can't be bothered doing a bulk update here...
        for act in actions:
            act.playbook = playbook
            act.save()
        # Classic just returns empty content, but we want to obey a schema.
        # But we don't want to do a bunch of extra queries to do it.
        return Response(
            SatMaintenanceActionSimpleSerializer(actions, many=True).data)
