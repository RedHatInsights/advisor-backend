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

import yaml

from django.conf import settings
from django.db.models import Case, CharField, F, Value, When
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet
from rest_framework_yaml.renderers import YAMLRenderer
from drf_spectacular.utils import extend_schema
from drf_spectacular.types import OpenApiTypes

from advisor_logging import logger

from api.filters import (
    host_tags_query_param, filter_multi_param,
    sort_params_to_fields, value_of_param,
    display_name_query_param, filter_on_display_name,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    host_group_name_query_param, filter_on_host_tags,
)
from api.models import get_host_group_filter
from api.permissions import (
    TurnpikeIdentityAuthentication, AssociatePermission,
    CertAuthPermission, ResourceScope, request_header_data,
)
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, retry_request,
)
from tasks.models import Host, ExecutedTask, Job, JobStatusChoices, Task
from tasks.permissions import TasksRBACPermission
from tasks.serializers import (
    TaskSerializer, TaskContentSerializer, TaskHostSerializer
)
from tasks.utils import (
    os_version_query_param, filter_on_os_version, system_sort_query_param,
    os_name_query_param, filter_on_os_name, os_query_param, filter_on_os,
    build_task_system_requirements, system_requirements_filter,
    apply_system_connected_filter, all_systems_query_param,
    direct_connect_filter, satellite_rhc_filter
)
from tasks.views.system import system_sort_field_map, annotate_rhc_status


class TaskViewSet(ReadOnlyModelViewSet, PaginateMixin):
    """
    View a list of tasks, or a single task
    """
    lookup_field = 'slug'
    pagination_class = CustomPageNumberPagination
    permission_classes = [TasksRBACPermission | CertAuthPermission]
    queryset = Task.objects.filter(active=True).order_by('publish_date').prefetch_related(
        'taskparameters'
    )
    resource_name = 'tasks'
    resource_scope = ResourceScope.ORG
    serializer_class = TaskSerializer

    # If we put the YAML renderer first, then any authentication failures
    # end up raising a 500 exception because it doesn't handle the
    # authentication exception objects correctly.
    @extend_schema(responses={200: OpenApiTypes.STR})
    @action(detail=True, renderer_classes=[JSONRenderer, YAMLRenderer])
    def playbook(self, request, slug, format=None):
        """
        Return the playbook for this task.

        Playbook generally do not change per task.
        """
        inventory_id = request.query_params.get('inventory_id')
        run_id = request.query_params.get('run_id')
        token = request.query_params.get('token')

        task = get_object_or_404(Task, slug=slug)

        playbook = yaml.load(task.playbook, yaml.Loader)[0]
        playbook_content_changed = False

        #  Since cyndi doesn't syndicate ansible_host and fqdn, we need to reach out to the inventory.
        if inventory_id:
            (response, elapsed) = retry_request(
                'Inventory', settings.INVENTORY_SERVER_URL + '/hosts/' + inventory_id,
                max_retries=1,
                mode='GET',
                headers=request_header_data(request)
            )
            if response.status_code != 200:
                logger.error(
                    "Received non-200 response from inventory %s: %s",
                    settings.INVENTORY_SERVER_URL, response.content.decode()
                )
                return None
            # Todo handle missing system
            host = response.json()['results'][0]
            hostname = host['ansible_host'] if host['ansible_host'] else host['fqdn']
            playbook['hosts'] = [hostname]
            playbook_content_changed = True
            # Because we know the inventory ID, we can look up the job and
            # add a log that the system requested the playbook.  But if we're
            # given the run_id that's handled later because it's unique.
            if not run_id:
                # Jobs will be running, on this system, from this task.
                jobs = Job.objects.filter(
                    executed_task__task=task, status=JobStatusChoices.RUNNING,
                    system_id=inventory_id
                )
                if jobs.count() == 1:
                    jobs[0].new_log(
                        True, f'Playbook requested (identified by inventory ID {inventory_id})'
                    )

        if token:
            # Try to work out which executed task this was, and update the
            # playbook parameters if that executed task had some.
            try:
                # Which of this task's executed tasks has this token?
                extask = task.executedtask_set.get(token=token)
                # If there are parameters, put them into the
                # '/vars/content_vars' section.  The '/vars' section must
                # exist or the playbook wouldn't be signed.
                if 'content_vars' not in playbook['vars']:
                    playbook['vars']['content_vars'] = dict()
                    playbook_content_changed = True
                for parameter in extask.parameters.all():
                    playbook['vars']['content_vars'][parameter.parameter.key] = parameter.value
                    playbook_content_changed = True
            except ExecutedTask.DoesNotExist:
                pass
            # The token by itself is not enough is not enough to identify
            # which system is requesting the playbook, so we can't log it.

        if run_id:
            # The only reason we are given a run ID is to log this access;
            # an inventory_id will only be used if this wasn't given.
            try:
                job = Job.objects.get(run_id=run_id)
                job.new_log(True, f'Playbook requested (run ID {run_id})')
            except Job.DoesNotExist:
                pass

        response = Response([], headers={
            'Content-Type': 'application/yaml',
            'Content-Disposition': f'attachment;filename="{slug}.yml"',
        })
        if playbook_content_changed:
            # sort_keys=False preserves the key order of the playbook, necessary for playbook signature verification
            response.content = '---\n' + yaml.dump([playbook], indent=2, sort_keys=False)
        else:
            response.content = task.playbook
        return response

    @extend_schema(
        parameters=[
            system_sort_query_param, host_tags_query_param, display_name_query_param,
            os_version_query_param, os_name_query_param, os_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            host_group_name_query_param, all_systems_query_param,
        ],
        responses={200: TaskHostSerializer(many=True)}
    )
    @action(detail=True, pagination_class=CustomPageNumberPagination)
    def systems(self, request, slug, format=None):
        """
        List all systems, with an extra 'requirements' field that is a list
        of reasons why the system cannot run this task.  If that list is
        empty, the system can run this task; otherwise the reasons should be
        displayed.
        """
        task = self.get_object()
        # Do same filtering as systems list...
        sort_fields = list(sort_params_to_fields(
            value_of_param(system_sort_query_param, request),
            system_sort_field_map,
            reverse_nulls_order=True
        )) + ['id']  # Enforce a repeatable ordering just in case
        systems = Host.objects.filter(
            apply_system_connected_filter(request),
            filter_on_host_tags(request, field_name='id'),
            filter_multi_param(request, 'system_profile'),
            get_host_group_filter(request),
            system_requirements_filter(request, task),
            filter_on_display_name(request),
            filter_on_os_version(request), filter_on_os_name(request), filter_on_os(request),
            org_id=request.auth['org_id'],
            per_reporter_staleness__puptoo__stale_warning_timestamp__gt=str(timezone.now()),
        ).annotate(
            connection_type=Case(
                When(direct_connect_filter, then=Value('direct')),
                When(satellite_rhc_filter, then=Value('satellite')),
                default=Value('none'),
                output_field=CharField()
            ),
            last_check_in=F('per_reporter_staleness__puptoo__last_check_in'),
            requirements=build_task_system_requirements(task)
        ).order_by(*sort_fields)
        return self._paginated_response(
            systems, serializer_class=TaskHostSerializer, request=request,
            page_annotator_fn=annotate_rhc_status,
        )


class InternalTaskViewSet(ModelViewSet):
    """
    View a list of tasks, or a single task.  Provides editing funcationality
    to internal users via Turnpike.  Provides more fields and the ability
    to create, edit and delete
    """
    authentication_classes = [TurnpikeIdentityAuthentication]
    pagination_class = CustomPageNumberPagination
    permission_classes = [AssociatePermission]
    queryset = Task.objects.order_by('id').prefetch_related(
        'taskparameters'
    )
    lookup_field = 'slug'
    serializer_class = TaskContentSerializer
