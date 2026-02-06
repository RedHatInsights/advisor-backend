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
from rest_framework.renderers import BaseRenderer
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.utils import (
    CustomPageNumberPagination, PaginateMixin,
)
from api.filters import (
    sort_params_to_fields, sort_param_enum, filter_on_param, value_of_param,
    display_name_query_param, filter_on_display_name,
)
from api.permissions import request_header_data, OrgPermission, ResourceScope
from tasks.models import Job, JobLog, JobStatusChoices, TaskTypeChoices
from tasks.permissions import TasksRBACPermission
from tasks.serializers import JobSerializer, JobLogSerializer
from tasks.utils import choices_obj_value_map
from tasks.management.commands.tasks_service import fetch_playbook_dispatcher_stdout


class PlainTextRenderer(BaseRenderer):
    media_type = 'text/plain'
    format = 'txt'
    # Charset defaults to utf-8

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data


executed_task_param = OpenApiParameter(
    name='executed_task', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.INT, required=False, many=False
)
job_sort_fields = (
    'executed_task', 'system', 'status', 'updated_on', 'display_name',
)
job_sort_field_map = {
    'system': 'system_id',
    'display_name': 'system__display_name',
}
job_sort_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY, type=OpenApiTypes.STR,
    required=False, many=False,
    description='Sort jobs by this field',
    enum=sort_param_enum(job_sort_fields), default='-updated_on',
)
job_status_param = OpenApiParameter(
    name='status', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False, many=True, style='form',
    enum=JobStatusChoices.labels
)
has_stdout_param = OpenApiParameter(
    name='has_stdout', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.BOOL, required=False, many=False
)


class JobViewSet(ReadOnlyModelViewSet, PaginateMixin):
    """
    View the jobs of running executed tasks.
    """
    lookup_field = 'id'
    pagination_class = CustomPageNumberPagination
    permission_classes = [OrgPermission, TasksRBACPermission]
    queryset = Job.objects.all()
    resource_name = 'task'
    resource_scope = ResourceScope.ORG
    serializer_class = JobSerializer

    def get_queryset(self):
        return self.queryset.filter(
            executed_task__org_id=self.request.auth['org_id'],
        )

    @extend_schema(
        parameters=[
            display_name_query_param, executed_task_param, job_sort_param,
            job_status_param, has_stdout_param,
        ]
    )
    def list(self, request, format=None):
        sort_fields = list(sort_params_to_fields(
            value_of_param(job_sort_param, request),
            job_sort_field_map,
            reverse_nulls_order=True
        )) + ['id']  # Enforce a repeatable ordering just in case
        jobs = self.get_queryset().filter(
            filter_on_param('executed_task_id', executed_task_param, request),
            filter_on_param(
                'status', job_status_param, request,
                value_map=choices_obj_value_map(JobStatusChoices),
            ),
            filter_on_param('has_stdout', has_stdout_param, request),
            filter_on_display_name(request, relation='system'),
        ).order_by(*sort_fields)
        return self._paginated_response(jobs)

    @extend_schema(
        responses=JobLogSerializer(many=True)
    )
    @action(detail=True, pagination_class=CustomPageNumberPagination)
    def log(self, request, id, format=None):
        """
        Show the log lines for this job.
        """
        job = self.get_object()  # or 404
        # the job has to be in this org due to get_queryset()
        log = JobLog.objects.filter(job=job)
        return self._paginated_response(log, request, serializer_class=JobLogSerializer)

    @extend_schema(responses={(200, "text/plain"): OpenApiTypes.STR})
    @action(detail=True, renderer_classes=[PlainTextRenderer])
    def stdout(self, request, id, format=None):
        """
        Show the stdout for this job
        """
        job = self.get_object()  # or 404
        if job.status == JobStatusChoices.RUNNING and job.executed_task.task.type == TaskTypeChoices.ANSIBLE:
            # We don't have a STDOUT yet, request it from Playbook Dispatcher.
            # Don't store it because we only want to process the output when
            # it's actually fully complete.
            # Make the request to Playbook Dispatcher with the user's identity
            stdout = fetch_playbook_dispatcher_stdout(
                job, auth_header=request_header_data(request)
            )
            if stdout is None:
                stdout = ''
            return Response(stdout)
        return Response(job.stdout)
