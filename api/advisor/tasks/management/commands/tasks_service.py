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

import base64
from json import loads, dumps
import re
import signal

from django.conf import settings
from project_settings import kafka_settings
from django.core.management.base import BaseCommand
from django.core.cache import cache
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from kafka_utils import KafkaDispatcher, send_kafka_message
from advisor_logging import logger
from api.permissions import auth_header_for_testing
from api.utils import retry_request
from tasks.kafka_utils import send_event_message
from tasks.models import (
    ExecutedTask, ExecutedTaskStatusChoices, Host, Job, JobStatusChoices,
    SatelliteRhc, TaskTypeChoices,
)
from tasks.utils import is_valid_uuid


EVENT_TYPE_FOR_JOB_STATUS = {
    JobStatusChoices.CANCELLED: 'job-cancelled',
    JobStatusChoices.FAILURE: 'job-failed',
    JobStatusChoices.SUCCESS: 'job-completed',
    JobStatusChoices.TIMEOUT: 'job-failed',
}

JSON_DELIMITERS = {
    TaskTypeChoices.ANSIBLE: {
        'prefix': '"task_results": ',
        'suffixes': re.compile(r'}\s+PLAY RECAP \*', re.MULTILINE),  # don't need re.DOTALL
        'source': 'Playbook Dispatcher',
    },
    TaskTypeChoices.SCRIPT: {
        'prefix': "### JSON START ###",
        'suffixes': ["### JSON END ###"],
        'source': 'Cloud Connector',
    }
}


def parse_json_from_stdout(job, stdout, task_type: TaskTypeChoices):
    """
    Find the job for this run and try to process the stdout for it.  If
    something goes wrong,
    """
    delims = JSON_DELIMITERS[task_type]

    job.stdout = stdout
    job.save()
    job.new_log(True, f"got stdout from {delims['source']} for this job")
    init_status = JobStatusChoices.FAILURE
    init_results = {
        'error': True, 'alert': True,
        'message': "An error occurred in parsing data from the script's output."
    }

    # Allows us to exit early on failure but still set status and results.
    def get_results(status, results):
        if delims['prefix'] not in stdout:
            log_line = f"Could not find JSON prefix '{delims['prefix']}' in stdout"
            job.new_log(False, log_line)
            results['message'] = log_line
            return status, results
        start = stdout.index(delims['prefix']) + len(delims['prefix'])
        # Find the ending, either by regex or one or more strings
        if isinstance(delims['suffixes'], re.Pattern):
            # search whole stdout otherwise end pos is relative
            match = delims['suffixes'].search(stdout)
            if not match:
                log_line = f"Could not find regular expression {delims['suffixes']} in stdout after prefix"
                job.new_log(False, log_line)
                results['message'] = log_line
                return status, results
            # before } character, because we don't care about '"task_results": {'
            end = match.start()
        else:
            for suffix in delims['suffixes']:
                if suffix in stdout[start:]:
                    break
            else:
                log_line = f"Could not find any of JSON suffix {delims['suffixes']} in stdout after prefix"
                job.new_log(False, log_line)
                results['message'] = log_line
                return status, results
            end = stdout.index(suffix, start)

        # Now try to get the result from that section of the stdout
        try:
            results = loads(stdout[start:end])
            # Cope with old results not having the 'alert' field.
            if 'alert' not in results:
                # either what 'error' is set to, or False (no alert = fine)
                results['alert'] = results.get('error', False)
            status = JobStatusChoices.SUCCESS
            job.new_log(True, "Parsed JSON output successfully")
        except Exception as exc:
            log_line = f"Error in parsing JSON between delimiters ({str(exc)}"
            job.new_log(False, log_line)
            results['message'] = log_line
        return status, results

    status, results = get_results(init_status, init_results)
    job.results = results
    job.status = status
    job.save()


# Job update handler
def handle_ansible_job_updates(topic, message):
    """
    Message is of the form:
    {
        "event_type": "create",
        "payload": {
          "id": "6555d6f7-8dc1-4dec-9d1e-0ef8a02d7d43",
          "account": "901578",
          "recipient": "dd018b96-da04-4651-84d1-187fa5c23f6c",
          "correlation_id": "fbf49ad9-ea79-41fb-9f6c-cb13307e993d",
          "service": "remediations",
          "url": "http://example.com",
          "labels": {
            "remediation_id": "1234",
          },
          "name": "Apply fix",
          "web_console_url": "http://example.com/remediations/1234",
          "recipient_config": {
            "sat_id": "16372e6f-1c18-4cdb-b780-50ab4b88e74b",
            "sat_org_id": "6826"
          },
          "status": "running",
          "timeout": 3600,
          "created_at": "2022-04-22T11:15:45.429294Z",
          "updated_at": "2022-04-22T11:15:45.429294Z"
        }
    }

    Event_type doesn't really matter - what we care about is the status line
    and the recipient ID.

    The correlation ID should be one we assigned to the job when we started.

    """
    if 'payload' not in message:
        return
    missing_keys = list(filter(
        lambda key: key not in message['payload'],
        ('id', 'status')
    ))
    if missing_keys:
        logger.warning("Received message missing keys (%s)", ', '.join(missing_keys))
        return
    run_id = message['payload']['id']
    updated_on = message['payload']['updated_at']

    try:
        job = Job.objects.get(run_id=run_id)
    except Job.DoesNotExist:
        logger.warning(
            'Job with run ID not found during Ansible playbook update processing when updating job status for task',
            extra={
                'run_id': run_id,
                'account': message['payload'].get('account'),
                'org_id': message['payload'].get('org_id'),
                'inventory_id': message['payload'].get('recipient'),  # yes?
            }
        )
        return

    status_name = message['payload']['status'].upper()
    try:
        # Annoyingly, the StatusChoices enum does not support __contains__ to
        # search for names (only values), so we have to catch the KeyError
        new_status = JobStatusChoices[status_name]
    except KeyError:
        logger.warning(
            "Received update with unknown status %s", status_name
        )
        new_status = JobStatusChoices[job.status]

    update_job_status(job, new_status, updated_on)

    if new_status == JobStatusChoices.RUNNING:
        # Don't process the stdout if we haven't finished running yet.
        return
    stdout = fetch_playbook_dispatcher_stdout(job)
    if not stdout:
        return
    parse_json_from_stdout(job, stdout, TaskTypeChoices.ANSIBLE)


def fetch_playbook_dispatcher_stdout(job):
    """
    This function retrieves the stdout of the playbook from a given run id.
    The auth header is constructed manually instead of auth_header_for_testing().
    This is because the playbook-dispatcher requires:
    1. No account key
    2. a type key
    3. org id in both top level and internal

    You get back the stdout text.
    """
    # Only works if Playbook Dispatcher is actually set up
    if not settings.PLAYBOOK_DISPATCHER_URL:
        return
    auth_header = {"x-rh-identity": base64.b64encode(dumps({
        "identity": {
            "org_id": job.executed_task.org_id,
            "type": "User",
            "user": {
                "username": job.executed_task.initiated_by,
                "is_org_admin": job.executed_task.is_org_admin,
            },
            "internal": {"org_id": job.executed_task.org_id}
        }
    }
    ).encode())}
    job.new_log(
        True, f'Requesting data from Playbook Dispatcher for run ID {job.run_id}'
    )
    (response, elapsed) = retry_request(
        'Playbook Dispatcher',
        f'{settings.PLAYBOOK_DISPATCHER_URL}/api/playbook-dispatcher/v1/run_hosts'
        f'?fields[data]=stdout&filter[run][id]={job.run_id}',
        max_retries=1,
        headers=auth_header
    )
    if response.status_code != 200:
        logger.error({
            'message': 'Error getting playbook-dispatcher stdout response',
            'status': response.status_code, 'text': response.text
        })
        job.new_log(
            False, f'Playbook Dispatcher returned {response.status_code} for run ID {job.run_id}'
        )
        return
    json = response.json()
    if not isinstance(json, dict):
        logger.error({
            'message': 'Error in parsing playbook-dispatcher stdout response',
            'original_text': response.text, 'problem': "Did not get a JSON object"
        })
        job.new_log(
            False, f'Playbook Dispatcher returned non-JSON response for run ID {job.run_id}'
        )
        return
    if 'data' not in json:
        logger.error({
            'message': 'Error in parsing playbook-dispatcher stdout response',
            'original_text': response.text, 'problem': "'data' not found in JSON object"
        })
        job.new_log(
            False, f'Playbook Dispatcher returned JSON response with no data object for run ID {job.run_id}'
        )
        return
    if not isinstance(json['data'], list):
        logger.error({
            'message': 'Error in parsing playbook-dispatcher stdout response',
            'original_text': response.text, 'problem': "'data' value not a list"
        })
        job.new_log(
            False, f'Playbook Dispatcher JSON data is not a list for run ID {job.run_id}'
        )
        return
    if len(json['data']) < 1:
        logger.error({
            'message': 'Error in parsing playbook-dispatcher stdout response',
            'original_text': response.text, 'problem': "'data' list is empty"
        })
        job.new_log(
            False, f'Playbook Dispatcher an empty JSON data list for run ID {job.run_id}'
        )
        return
    if not isinstance(json['data'][0], dict):
        logger.error({
            'message': 'Error in parsing playbook-dispatcher stdout response',
            'original_text': response.text, 'problem': "'data' list element 0 is not a JSON object"
        })
        job.new_log(
            False, f'Playbook Dispatcher JSON data list with non-object for run ID {job.run_id}'
        )
        return
    if 'stdout' not in json['data'][0]:
        logger.error({
            'message': 'Error in parsing playbook-dispatcher stdout response',
            'original_text': response.text, 'problem': "'data' list element 0 does not have the 'stdout' key"
        })
        job.new_log(
            False, f'Playbook Dispatcher JSON data list item has no stdout data for run ID {job.run_id}'
        )
        return
    return json['data'][0]['stdout']


def handle_script_job_updates(topic, message):
    """
    Process the upload of the results of the rhc-worker-script via
    the payload tracker.
    """
    logger.info('received tasks upload from ingress', extra={
        "topic": topic,
        "request_id": message.get('request_id'),
        "ingress_kafka_message": message
    })
    updated_on = message['timestamp']
    send_kafka_message(kafka_settings.PAYLOAD_TRACKER_TOPIC, {
        'status': 'received',
        'service': 'tasks',
        'source': 'rhc-worker-script',
        'account': message.get('account'),
        'org_id': message.get('org_id'),
        'inventory_id': message.get('id'),
        'request_id': message.get('request_id'),
        'status_msg': 'Tasks backend starting to process rhc-worker-script payload',
        'date': updated_on
    })
    upload_url = message['url']

    (request, duration) = retry_request('s3', upload_url)

    file_contents = request.json()  # We may need request.raw if it comes over as a gziped tar

    logger.info('downloaded tasks upload from s3', extra={
        "request_id": message.get('request_id'),
        "file": file_contents
    })
    run_id = file_contents['correlation_id']
    stdout = file_contents['stdout']

    try:
        job = Job.objects.get(run_id=run_id)
    except Job.DoesNotExist:
        logger.warning(
            'Job with run ID not found during script update processing when updating job status for task',
            extra={
                'run_id': run_id,
                'account': message.get('account'),
                'org_id': message.get('org_id'),
                'inventory_id': message.get('id'),
            }
        )
        return
    parse_json_from_stdout(job, stdout, TaskTypeChoices.SCRIPT)
    update_job_status(job, job.status, None)


def update_job_status(job, new_status: JobStatusChoices, updated_on):
    """
    Does more than what it says on the tin:
    * Updates the job status and update time, if the status is different.
    * Logs a message
    """
    # Set new status
    if job.status != new_status:
        job.status = new_status.value
        updated_datetime = parse_datetime(updated_on)  # doesn't raise exceptions
        if updated_datetime:
            job.updated_on = updated_datetime
        else:
            job.updated_on = timezone.now()
        job.save()
        job.new_log(
            job.status == JobStatusChoices.SUCCESS,
            f"Updated job status to {job.get_status_display()}, update time {job.updated_on} (run ID {job.run_id})"
        )
        logger.info(f"Tasks service update status updated {job.run_id} to {new_status.name}")

    # Since there's only one job to update, send this message off - if
    # it's not still running (ergo, not one of our status mappings)
    # Since customers (usually QE people) can delete the system between
    # when the system was dispatched to and when we receive this update,
    # we can't assume that job.system exists any more.
    try:
        display_name = job.system.display_name
        system_exists = True
    except Host.DoesNotExist:
        system_exists = False
    if system_exists and job.status in EVENT_TYPE_FOR_JOB_STATUS:
        send_event_message(
            event_type=EVENT_TYPE_FOR_JOB_STATUS[job.status],
            org_id=job.executed_task.org_id,
            context={
                'task_name': job.executed_task.name,
                'task_slug': job.executed_task.task.slug,
                'executed_task_id': job.executed_task_id,
            },
            event_payloads=[{
                'system_uuid': str(job.system_id),
                'display_name': display_name,
                'status': new_status.label,
            }]
        )
        job.new_log(
            True,
            f"Sent message that this job is {job.get_status_display()} on system {display_name} (ID {job.system_id}, run ID {job.run_id})"
        )
    # Update the executed task status
    update_executed_task_status(job.executed_task, job)
    logger.info("Tasks service update finished")
    return job


def update_executed_task_status(
    extask: ExecutedTask, job=None, send_message=True, delete_empty=False
):
    """
    Update the executed task status to reflect the status of its jobs.
    This can also update the job (if provided - that would be the job that
    caused the status change), can (if required) send messages about the
    updated executed task status, and can (if required) delete executed tasks
    that have no jobs.
    """
    # We need the untrammeled Job list because otherwise it joins to Host
    # and that's unnecessary for these filters.
    job_statuses = set(
        Job.objects.original_queryset().filter(
            executed_task=extask
        ).values_list('status', flat=True).distinct()
    )
    # Historically some executed tasks have ended up with no associated jobs.
    # We should deal with them early.
    if not job_statuses:
        logger.warning(
            "Found executed task %s id %d has no jobs - %s delete",
            extask.name, extask.id, ("will" if delete_empty else "not set to")
        )
        if delete_empty:
            extask.delete()
        return
    # Executed tasks start in the RUNNING state, and jobs are timed out every
    # minute if RUNNING too long, so the only situation we need to deal with
    # is if there are no running jobs.
    if JobStatusChoices.RUNNING in job_statuses:
        # Let's make sure!
        if extask.status != ExecutedTaskStatusChoices.RUNNING:
            logger.warning(
                "Executed task %s id %d has running jobs - needed to be in RUNNING state",
                extask.name, extask.id
            )
            extask.status = ExecutedTaskStatusChoices.RUNNING
            extask.save()
        return
    # If we're given a job, at this point it is the last job to change
    # state, so it can get a special message!
    if job is not None:
        job.new_log(
            True,
            f"No more jobs running for executed task {job.executed_task.name} (ID {job.executed_task_id})"
        )
    # Now check all the job status combinations
    if JobStatusChoices.CANCELLED in job_statuses:
        # One or more jobs cancelled
        new_status = ExecutedTaskStatusChoices.CANCELLED
    elif job_statuses == {JobStatusChoices.SUCCESS}:
        # All jobs completed
        new_status = ExecutedTaskStatusChoices.COMPLETED
    elif JobStatusChoices.SUCCESS in job_statuses:
        # One or more jobs have failed or timed out.
        new_status = ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS
    else:
        # All jobs failed, timed out or cancelled
        new_status = ExecutedTaskStatusChoices.FAILURE

    if extask.status == new_status:
        # Nothing more to do, no messages to send
        return
    logger.info(
        "Updating executed task %s id %d state from %s to %s",
        extask.name, extask.id, extask.status, new_status
    )
    extask.status = new_status
    extask.end_time = timezone.now()
    extask.save()
    if send_message:
        send_event_message(
            event_type='executed-task-completed',
            org_id=extask.org_id,
            context={},
            event_payloads=[{
                'task_name': extask.name,
                'task_slug': extask.task.slug,
                'executed_task_id': extask.id,
                'status': extask.get_status_display(),
            }]
        )


def get_satellite_source_type_id():
    """
    Gets the ID source_type for satellite from the sources api. Since this value never changes for each
     environment, it is stored in the django cache for future accesses.
    """
    satellite_source_type_id = cache.get('satellite_source_type_id')
    if satellite_source_type_id:
        return satellite_source_type_id
    auth_header = auth_header_for_testing(
        account=settings.SOURCE_API_ACCOUNT, org_id=settings.SOURCE_API_ORG,
        supply_http_header=True
    )
    (response, elapsed) = retry_request(
        'sources api',
        f"{settings.SOURCES_API_URL}/api/sources/v3.1/source_types?filter[name]=satellite",
        headers=auth_header
    )
    satellite_source_type_id = int(response.json()['data'][0]['id'])
    cache.set('satellite_source_type_id', satellite_source_type_id)
    return satellite_source_type_id


def handle_sources_event(topic, message):
    """
    messages that we care about are of the form
    {
      "availability_status": null,
      "last_checked_at": null,
      "last_available_at": null,
      "id": 147,
      "created_at": "2022-04-20 13:17:59 CDT",
      "updated_at": "2022-04-20 13:17:59 CDT",
      "paused_at": null,
      "name": "demo test2",
      "uid": "f243386e-d59d-4f24-bad8-04e24d0c4b14",
      "version": null,
      "imported": null,
      "source_ref": "357b7360-c0d6-11ec-a1f5-abea1b2200b3",
      "app_creation_workflow": "manual_configuration",
      "source_type_id": 7,
      "tenant": ""
    }
    (for picking up the source ID and the Satellite instance ID)
    --OR--
    {
      "id": "1",
      "rhc_id": "52321130-c0d6-11ec-a1f5-abea1b2200b3",
      "extra": null,
      "availability_status": null,
      "last_checked_at": null,
      "last_available_at": null,
      "availability_status_error": "",
      "source_ids": [2], // Array guaranteed to have 1 value
      "created_at": "2022-04-20 13:18:47 UTC",
      "updated_at": "2022-04-20 13:18:47 UTC"
    }
    (for picking up the source ID and the RHC Client ID)
    """
    if 'source_type_id' in message and 'source_ref' in message:
        # the satellite_source_message
        satellite_source_type_id = get_satellite_source_type_id()
        if message['source_type_id'] == satellite_source_type_id and is_valid_uuid(message['source_ref']):
            _ = SatelliteRhc.objects.update_or_create(
                instance_id=message['source_ref'],
                defaults={'source_id': message['id']}
            )
            return
    if 'rhc_id' in message and 'source_ids' in message:
        # the rhc_source_message
        # rhc_id seems to be able to be set by customers, who don't seem to
        # set it to a recognisable UUID.  Validate and log failures.
        if not is_valid_uuid(message['rhc_id']):
            _ = logger.error(f"Invalid RHC UUID {message['rhc_id']} for source ID {message['source_ids'][0]}")
        elif not message['source_ids']:
            _ = logger.error(f"No source ID for RHC UUID {message['rhc_id']}")
        else:
            _ = SatelliteRhc.objects.filter(
                source_id=message['source_ids'][0],
            ).update(rhc_client_id=message['rhc_id'])


# Main command


class Command(BaseCommand):
    help = "Updates the job and executed task states based on Kafka messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Tasks service starting up')

        receiver = KafkaDispatcher()
        receiver.register_handler(kafka_settings.TASKS_UPDATES_TOPIC, handle_ansible_job_updates, service='tasks')
        receiver.register_handler(kafka_settings.TASKS_SOURCES_TOPIC, handle_sources_event)
        receiver.register_handler(kafka_settings.TASKS_UPLOAD_TOPIC, handle_script_job_updates, service='tasks')

        def terminate(signum, frame):
            logger.info("SIGTERM received, triggering shutdown")
            receiver.quit = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Tasks service shutting down')
