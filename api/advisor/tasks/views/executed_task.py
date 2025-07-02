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

from hashlib import sha256
from itertools import batched
import uuid

from django.conf import settings
from django.core.exceptions import BadRequest
from django.db import transaction
from django.db.models import (
    Count, F, Q, UUIDField
)
from django.db.models.expressions import RawSQL, Subquery
from django.db.models.functions import Coalesce, Cast
from django.urls import reverse
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

import splunk_logger
from advisor_logging import logger

from api.filters import (
    sort_params_to_fields, sort_param_enum, filter_on_param,
    host_tags_query_param, value_of_param, host_group_name_query_param,
    display_name_query_param, filter_on_display_name, filter_on_host_tags,
)
from api.models import get_host_group_filter
from api.permissions import OrgPermission, http_auth_header_key, auth_header_key
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, retry_request,
    store_post_data,
)
from tasks.kafka_utils import send_event_message
from tasks.models import (
    ExecutedTask, ExecutedTaskStatusChoices, ExecutedTaskParameter, Host, Job,
    JobLog, JobStatusChoices, SatelliteRhc, Task, TaskTypeChoices,
)
from tasks.permissions import TasksRBACPermission
from tasks.serializers import (
    ExecutedTaskSerializer, ExecutedTaskOneSerializer, ExecuteTaskSerializer,
    JobSerializer, JobLogTaskSerializer
)
from tasks.utils import (
    os_version_query_param, filter_on_os_version, choices_obj_value_map
)
from tasks.management.commands.tasks_service import update_executed_task_status


extask_text_query_param = OpenApiParameter(
    name='text', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False, many=False
)
extask_status_query_param = OpenApiParameter(
    name='status', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False, many=True, style='form',
    enum=ExecutedTaskStatusChoices.labels
)
extask_sort_fields = [
    'name', 'title', 'status', 'start_time', 'end_time', 'systems_count',
]
extask_sort_field_map = {
    'title': 'task__title',
}
extask_sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False, many=False,
    enum=sort_param_enum(extask_sort_fields), default='start_time'
)

# Have to have our own here because we operate via the 'system' foreign key
jobs_sort_field_map = {
    'os_version': [
        'system__system_profile__operating_system__major',
        'system__system_profile__operating_system__minor'
    ],
    'last_seen': 'system__updated',
    'status': ['status', 'system__display_name'],
}
# We also sort on job status here so this is different from system sort
jobs_sort_fields = ['display_name', 'os_version', 'last_seen', 'status']
jobs_sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description='Sort systems by this field',
    enum=sort_param_enum(jobs_sort_fields), default='display_name',
)
# However the display_name is annotated in...
status_filter_query_param = OpenApiParameter(
    name='status', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False, many=True, style='form',
    enum=JobStatusChoices.labels
)


def satellite_id_from_tags(tags):
    """
    Find the satellite instance ID in the list of tags, or None
    """
    for tag in tags:
        if tag['namespace'] == 'satellite' and tag['key'] == 'satellite_instance_id':
            return tag['value']
    return None


def execute_playbook_dispatcher(hosts, org_id, task, user, executed_task_url):
    dispatch_body = []
    for host in hosts:
        if host['rhc_client_id'] is None:
            raise ValidationError({'hosts': f'host {host["id"]} does not have an associated RHC client id'})
        run = {
            'recipient': str(host['rhc_client_id']),
            'org_id': org_id,
            'url': executed_task_url,
            'principal': user,
            'name': task.title,
        }
        if host['satellite_instance_id']:
            run['recipient_config'] = {
                "sat_id": host['satellite_instance_id'],
                "sat_org_id": host['satellite_org_id']
            }
            run['hosts'] = [{'inventory_id': str(host['id'])}]
            run['url'] = f"{run['url']}?inventory_id={str(host['id'])}"
        dispatch_body.append(run)
    logger.info(dispatch_body)
    (response, elapsed) = retry_request(
        'Playbook Dispatcher', settings.PLAYBOOK_DISPATCHER_URL + '/internal/v2/dispatch',
        max_retries=1,
        mode='POST',
        headers={"Authorization": f"PSK {settings.PDAPI_PSK}"},
        json=dispatch_body
    )
    if response.status_code != 207:
        logger.error(
            "Received non-207 response from playbook dispatcher %s: %s",
            settings.PLAYBOOK_DISPATCHER_URL, response.content.decode()
        )
        raise BadRequest()
    runs_created = response.json()
    return runs_created


def execute_cloud_connector(hosts, task, auth_header, executed_task_url):
    runs_created = []
    for host in hosts:
        if host['rhc_client_id'] is None:
            raise ValidationError({'hosts': f'host {host["id"]} does not have an associated RHC client id'})
        run_id = str(uuid.uuid4())
        run = {
            'payload': executed_task_url,
            'directive': 'rhc-worker-script',
            'metadata': {
                'correlation_id': run_id,
                'return_url': f'https://{settings.PLATFORM_HOSTNAME_URL}/api/ingress/v1/upload',
                'return_content_type': 'application/vnd.redhat.tasks.payload+tgz',
            }
        }
        (response, elapsed) = retry_request(
            'Cloud Connector',
            f'http://{settings.CLOUD_CONNECTOR_HOST}:{settings.CLOUD_CONNECTOR_PORT}/api/cloud-connector/v2/connections/{host["rhc_client_id"]}/message',
            max_retries=1,
            mode='POST',
            headers={http_auth_header_key: auth_header},
            json=run
        )
        if response:
            logger.info(f'Cloud Connector response:{response.status_code} {response.text}')
        run = {'code': response.status_code}

        if response.status_code == 201:  # following PBD convention of returning id on success
            run['id'] = run_id

        runs_created.append(run)
    return runs_created


def extask_text_filter(request):
    """
    Search for the given text in the name, slug, title and description of the
    executed task.  These are fields within the Task.  At some point we may
    have text fields within the ExecutedTask to search on and they should
    be added here.
    """
    search_text = value_of_param(extask_text_query_param, request)
    # Based on Host so look up directly
    if search_text is None:
        return Q()
    return Q(
        Q(name__icontains=search_text)
        | Q(task__slug__icontains=search_text)
        | Q(task__title__icontains=search_text)
        | Q(task__description__icontains=search_text)
    )


def create_task_parameters(extask, parameters):
    if parameters:
        # Map parameter keys to their IDs, since we only get keys from
        # the form
        parameter_id_for = {
            parameter.key: parameter.id
            for parameter in extask.task.taskparameters.all()
        }
        # The parameters here are stored in the way the
        # ExecutedTaskParameterSerializer stores them - parameter.key and
        # value
        parameter_list = [
            ExecutedTaskParameter(
                executed_task=extask,
                parameter_id=parameter_id_for[exparam['parameter']['key']],
                value=exparam['value']
            )
            for exparam in parameters
        ]
        # Make sure that any parameters which haven't been given,
        # are required, and have a default, are also added explicitly
        given_parameter_keys = set(
            exparam['parameter']['key']
            for exparam in parameters
        )
    else:
        given_parameter_keys = set()
        parameter_list = []
    # Add any extra parameters that are required, have a default, and for
    # which no value has been given.
    for param in extask.task.taskparameters.filter(
        required=True, default__isnull=False
    ).exclude(key__in=given_parameter_keys):
        parameter_list.append(ExecutedTaskParameter(
            executed_task=extask, parameter_id=param.id, value=param.default
        ))
    # Add all parameters
    ExecutedTaskParameter.objects.bulk_create(parameter_list)
    # Return just whether the executed task actually has parameters
    return bool(parameter_list)


def create_jobs_for_executed_task(extask, hosts, runs_created, dispatcher, now):
    started_jobs = []
    failed_jobs = []
    # Create jobs for each host in the list
    for host_no, host in enumerate(hosts):
        run_id = runs_created[host_no].get('id')
        job = Job(
            executed_task=extask, system_id=host['id'], updated_on=now,
            status=JobStatusChoices.RUNNING if run_id else JobStatusChoices.FAILURE,
            results={}, run_id=run_id if run_id else uuid.UUID(int=0),
            rhc_client_id=host['rhc_client_id']
        )
        job.save()
        if run_id:
            job.new_log(True, f'Job dispatched to {dispatcher} (run ID {run_id})')
            started_jobs.append(job)
        else:
            # Can we determine a reason?
            if runs_created[host_no]["code"] == 404:
                reason = "host is not currently connected to RHC"
            else:
                reason = f"returned status code {runs_created[host_no]["code"]}"
            job.new_log(False, f'Job dispatch to {dispatcher} failed - {reason}')
            failed_jobs.append(job)

    update_executed_task_status(extask)
    return (started_jobs, failed_jobs)


def send_start_messages(extask, started_jobs, failed_jobs):
    """
    Send out the job messages for this
    """
    send_event_message(
        event_type='executed-task-started',
        org_id=extask.org_id,
        context={},
        event_payloads=[{
            'task_name': extask.name,
            'task_slug': extask.task.slug,
            'executed_task_id': extask.id,
            'status': extask.get_status_display(),
        }]
    )

    # And for the job updates, started and failed:
    def send_job_start_messages(event_type, jobs_list):
        if not jobs_list:
            return
        send_event_message(
            event_type=event_type,
            org_id=extask.org_id,
            context={
                'task_name': extask.name,
                'task_slug': extask.task.slug,
                'executed_task_id': extask.id,
            },
            event_payloads=[
                {
                    'system_uuid': str(job.system_id),
                    'display_name': job.system.display_name,
                    'status': job.get_status_display(),
                }
                for job in jobs_list
            ]
        )

    send_job_start_messages('job-started', started_jobs)
    send_job_start_messages('job-failed', failed_jobs)


class ExecutedTaskViewSet(ReadOnlyModelViewSet, PaginateMixin):
    """
    View a list of executed tasks, or a single executed task
    """
    lookup_field = 'id'
    pagination_class = CustomPageNumberPagination
    permission_classes = [OrgPermission, TasksRBACPermission]
    queryset = ExecutedTask.objects.all()
    serializer_class = ExecutedTaskSerializer

    def get_queryset(self):
        return self.queryset.filter(
            org_id=self.request.auth['org_id']
        ).select_related('task').annotate(
            task_slug=F('task__slug'),
            task_title=F('task__title'),
            task_description=F('task__description'),
            task_filter_message=F('task__filter_message'),
            systems_count=Count('job'),
        )

    @extend_schema(
        parameters=[extask_text_query_param, extask_sort_query_param, extask_status_query_param]
    )
    def list(self, request):
        sort_param = value_of_param(extask_sort_query_param, request)
        extasks = self.get_queryset().annotate(
            running_jobs_count=Count('job', filter=Q(job__status=JobStatusChoices.RUNNING)),
            completed_jobs_count=Count('job', filter=Q(job__status=JobStatusChoices.SUCCESS)),
            failure_jobs_count=Count('job', filter=Q(job__status=JobStatusChoices.FAILURE)),
            timeout_jobs_count=Count('job', filter=Q(job__status=JobStatusChoices.TIMEOUT)),
        ).filter(
            extask_text_filter(request),
            filter_on_param(
                'status', extask_status_query_param, request,
                value_map=choices_obj_value_map(ExecutedTaskStatusChoices)
            ),
        ).order_by(
            # has default of ['start_time']
            *sort_params_to_fields(sort_param, extask_sort_field_map)
        )
        return self._paginated_response(extasks)

    @extend_schema(
        parameters=[jobs_sort_query_param],
        responses=ExecutedTaskOneSerializer
    )
    def retrieve(self, request, id, format=None):
        """
        Retrieve a single executed task, along with its list of jobs and the
        systems they represent.
        """
        extask = self.get_object()
        sort_fields = list(sort_params_to_fields(
            value_of_param(jobs_sort_query_param, request),
            jobs_sort_field_map
        )) + ['id']  # Enforce a repeatable ordering just in case
        extask.jobs = extask.job_set.order_by(*sort_fields)
        return Response(ExecutedTaskOneSerializer(
            extask, many=False, context={'request': request},
        ).data)

    @action(detail=True, methods=['POST'])
    def cancel(self, request, id, format=None):
        """
        Cancel an existing executed task, by ID.

        This sends a signal to the Playbook Dispatcher to cancel all the jobs
        in this executed task.  It updates the state of the executed task to
        be CANCELLED.  Jobs in this task will be updated as we receive
        messages back from the Playbook Dispatcher.
        """
        extask = self.get_object()
        # Only try to cancel running jobs
        running_jobs = extask.job_set.filter(
            status=JobStatusChoices.RUNNING
        )
        # Pre-emptively in the fields that the serialiser needs
        extask.jobs = extask.job_set.all()
        # If the task has completed or been cancelled, don't do anything
        # further.
        if extask.status != ExecutedTaskStatusChoices.RUNNING:
            return Response(ExecutedTaskOneSerializer(extask, many=False).data)
        # Send signal to Playbook Dispatcher to cancel the jobs in this
        # executed task.
        user = request.auth['user']['username']
        org_id = request.auth['org_id']
        # Need to batch this, maximum 50 items per request.  Could try in
        # parallel, just for LOLs...
        for batch in batched(running_jobs.values_list('run_id', flat=True), settings.TASKS_API_BATCH_SIZE):
            (response, elapsed) = retry_request(
                'Playbook Dispatcher', settings.PLAYBOOK_DISPATCHER_URL + '/internal/v2/cancel',
                max_retries=1,
                mode='POST',
                headers={"Authorization": f"PSK {settings.PDAPI_PSK}"},
                json=[
                    {
                        'run_id': str(run_id),
                        'org_id': org_id,
                        'principal': user,
                    }
                    for run_id in batch
                ]
            )
        # We kind of throw away the status here, since we're relying on the
        # tasks service listening on the playbook dispatcher Kafka channel to
        # pick up the updates for each run.  So...
        # Update the jobs
        running_jobs.update(status=JobStatusChoices.CANCELLED)
        # Mark this executed task as cancelled.
        update_executed_task_status(extask)
        return Response(ExecutedTaskOneSerializer(
            extask, many=False, context={'request': request},
        ).data)

    @extend_schema(
        request=ExecuteTaskSerializer,
        responses={201: ExecutedTaskOneSerializer}
    )
    def create(self, request, format=None):
        """
        Execute a task on one or more hosts.

        This takes a task, a list of one or more hosts, and any parameters
        the task may define, and creates a new executed task linked to a job
        for each host.  The jobs are then scheduled on those hosts by the
        dispatch mechanism defined by the task.
        """

        # Validate incoming data:
        store_post_data(request, ExecuteTaskSerializer, context={'request': request})
        etserializer = ExecuteTaskSerializer(data=request.data, context={'request': request})
        etserializer.is_valid(raise_exception=True)

        user = request.auth['user']['username']
        is_org_admin = request.auth['user'].get('is_org_admin', False)
        org_id = request.auth['org_id']
        validated_data = etserializer.validated_data
        task = Task.objects.get(slug=validated_data['task'])
        name = validated_data['name'] if 'name' in validated_data else task.title
        splunk_logger.log("Insights Tasks Execution",
            org_id=org_id, user=user, task=task.title,
            ip_address=request.headers.get('X_FORWARDED_FOR'),
            hosts=[str(host) for host in validated_data['hosts']],
            # Note that this may not match the actual script if it was
            # modified by adding parameters or a host.
            script_hash=sha256(task.playbook.encode('utf-8')).hexdigest()
        )
        # Directly-connected hosts have a rhc_client_id.  Satellite-connected
        # hosts have a satellite instance ID tag.  Those are the
        # 'recipient' of the request to dispatch a playbook.  But in order
        # to make sure that the recipients we send to are in the same order
        # as our query here, we don't group systems by Satellite.
        hosts = Host.objects.filter(
            get_host_group_filter(request),
            org_id=self.request.auth['org_id'],
            id__in=validated_data['hosts'],
        ).annotate(
            satellite_instance_id=Host.tag_query('satellite_instance_id'),
            satellite_org_id=Host.tag_query('organization_id'),
            rhc_client_id=Coalesce(
                Cast(RawSQL("system_profile->>'rhc_client_id'", []), output_field=UUIDField()),
                Subquery(SatelliteRhc.objects.filter(
                    instance_id=Cast(Host.tag_query('satellite_instance_id'), output_field=UUIDField())
                ).values('rhc_client_id'))
            )
        ).order_by(
            'id'  # for repeatable testing
        ).values(
            'id', 'satellite_instance_id', 'satellite_org_id', 'rhc_client_id',
            'display_name',
        )

        dispatcher = 'Cloud Connector' if task.type == TaskTypeChoices.SCRIPT else 'Playbook Dispatcher'
        runs_created = []
        playbook_script_url = "https://{host}{path}".format(
            host=settings.PLATFORM_HOSTNAME_URL,
            path=reverse('tasks-task-playbook', kwargs={'slug': task.slug})
        )

        # Because we differentiate between started and failed jobs, we have
        # two lists and put the jobs in each.  Could have one list and
        # check for status, but the logic is simpler this way...
        # started_jobs = []
        # failed_jobs = []

        # Do all the database object creation and job dispatch
        extask_id = None
        with transaction.atomic():
            now = timezone.now()
            # Create the executed task (need this for the token)
            extask = ExecutedTask(
                name=name, task=task, initiated_by=user, is_org_admin=is_org_admin,
                start_time=now, org_id=org_id, status=ExecutedTaskStatusChoices.RUNNING
            )
            extask.save()
            # pass the ID out of the atomic context
            extask_id = extask.id

            # Create parameters for executed task if required
            has_parameters = create_task_parameters(extask, validated_data.get('parameters'))
            # Only add the token if the executed task has set parameters.  This
            # includes parameters that have a default.
            if has_parameters:
                playbook_script_url += f"?token={extask.token}"

            # Send off the requests to start this task.  We do this now because
            # playbook dispatcher in particular assigns the run_id, and we need
            # that to create the Job for each host.
            for batch in batched(hosts, settings.TASKS_API_BATCH_SIZE):
                if task.type == TaskTypeChoices.SCRIPT:
                    runs_created += execute_cloud_connector(
                        batch, task, request.META[auth_header_key], playbook_script_url
                    )
                else:
                    runs_created += execute_playbook_dispatcher(
                        batch, org_id, task, user, playbook_script_url
                    )

            logger.info("Created runs for executed task id %d: %s", extask_id, runs_created)
            assert isinstance(runs_created, list)
            assert len(runs_created) == len(hosts)

            started_jobs, failed_jobs = create_jobs_for_executed_task(
                extask, hosts, runs_created, dispatcher, now
            )

        # Load the object from the database outside the atomic context, with
        # the annotations necessary for the serialiser
        extask = self.get_queryset().get(id=extask_id)
        extask.jobs = extask.job_set.all()
        # Now we can send messages: one for the executed task update
        send_start_messages(extask, started_jobs, failed_jobs)
        # And return the executed task we created
        return Response(
            ExecutedTaskOneSerializer(extask, many=False, context={'request': request}).data,
            status=201
        )

    def destroy(self, request, id, format=None):
        """
        Delete an existing execut(ing,ed) task.  If the task is still
        executing (i.e. it is not yet cancelled or completed) then also
        cancel all running jobs.  This also deletes the data for all of the
        executed task's jobs.
        """
        extask = self.get_object()
        extask.delete()
        return Response(status=204)

    @extend_schema(
        parameters=[
            jobs_sort_query_param, host_tags_query_param,
            display_name_query_param, os_version_query_param,
            status_filter_query_param, host_group_name_query_param,
        ],
        responses={200: JobSerializer(many=True)},
    )
    @action(detail=True)
    def jobs(self, request, id, format=None):
        """
        List the jobs associated with the given executed task.
        """
        extask = self.get_object()
        sort_fields = list(sort_params_to_fields(
            value_of_param(jobs_sort_query_param, request),
            jobs_sort_field_map
        )) + ['id']  # Enforce a repeatable ordering just in case
        jobs = Job.objects.select_related('system').filter(
            filter_on_host_tags(request, field_name='system_id'),
            get_host_group_filter(request, relation='system'),
            filter_on_display_name(request, relation='system'),
            filter_on_os_version(request, relation='system'),
            filter_on_param(
                'status', status_filter_query_param, request,
                # We need to map 'Running' to 1; JobStatusChoices.choices
                # maps 1 to 'Running'
                value_map=choices_obj_value_map(JobStatusChoices),
            ),
            executed_task_id=extask.id,
        ).order_by(*sort_fields)
        return self._paginated_response(jobs, request, serializer_class=JobSerializer)

    @extend_schema(
        responses={200: JobLogTaskSerializer(many=True)}
    )
    @action(detail=True)
    def job_logs(self, request, id, format=None):
        extask = self.get_object()
        log = JobLog.objects.filter(job__executed_task=extask).select_related(
            'job', 'job__system'
        ).annotate(
            system_id=F('job__system_id'),
            display_name=F('job__system__display_name')
        ).order_by('created_at')
        return self._paginated_response(
            log, request, serializer_class=JobLogTaskSerializer
        )
