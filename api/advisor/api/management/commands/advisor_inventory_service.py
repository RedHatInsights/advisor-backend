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

import prometheus
import signal
import time
import traceback

from bounded_executor import BoundedExecutor
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from project_settings import kafka_settings

import build_info
import payload_tracker
import reports as report_hooks
import thread_storage
import utils
from advisor_logging import logger
from api.models import (  # pyright: ignore[reportImplicitRelativeImport]
    Ack, CurrentReport, Host, HostAck, InventoryHost,
    Rule, SystemType, Upload, UploadSource
)
from feature_flags import (
    feature_flag_is_enabled, FLAG_INVENTORY_EVENT_REPLICATION
)
from kafka_utils import JsonValue, KafkaDispatcher


#############################################################################
def handle_inventory_event(topic: str, message: dict[str, JsonValue]) -> None:
    """
    Handle inventory events.

    The inventory event messages are documented at:
    https://inscope.corp.redhat.com/docs/default/component/host-based-inventory/#created-event
    """
    if 'type' not in message:
        logger.error("Message received on topic %s with no 'type' field", topic)
        return

    if not feature_flag_is_enabled(FLAG_INVENTORY_EVENT_REPLICATION):
        sys_uuid: str = message.get('host', {}).get('id', 'unknown UUID')
        logger.info(
            "Received Inventory %s event for %s - feature flag not enabled, ignoring",
            message['type'], sys_uuid
        )
        return

    match message['type']:
        case 'delete':
            handle_deleted_event(message)
        case 'created' | 'updated':
            handle_created_event(message)
        case msg_type:
            logger.error("Inventory event: Unknown message type: %s", msg_type)


#############################################################################
def log_missing_key(request_id: str, event_type: str, key_name: str):
    logger.error(
        "Request %s: Inventory %s event did not contain required key '%s'",
        request_id, event_type, key_name
    )
    prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()


#############################################################################
SYSTEM_PROFILE_KEYS = (
    'ansible', 'bootc_status', 'host_type', 'mssql', 'operating_system',
    'owner_id', 'rhc_client_id', 'sap', 'sap_system', 'sap_sids',
    # need to phase out sap_system and sap_sids in favour of sap structure.
    'system_update_method',
)


def extract_system_profile(source: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """
    Grab just the keys we need from the given system profile.
    """
    return {
        key: source[key]
        for key in SYSTEM_PROFILE_KEYS
        if key in source
    }


#############################################################################
def handle_created_event(message: dict[str, JsonValue]):
    """
    Handle a 'created' or 'updated' event message.

    We break this down into two parts:
        1. Create or update the basic information of the host.
        2. Update the host's system_profile and other complex fields.

    This just breaks down the amount of data being updated in each transaction.

    Message is of the form:
        {
           "type": "created",  # or 'updated' - already checked.
           "timestamp": "<timestamp>",
           "platform_metadata": "<metadata_json_doc>",
           "metadata": {
               "request_id": "<request_id>",
           },
           "host": {
              "id": "<id>",
              "account": "<account_number>",
              "org_id": "<org_id>",
              "display_name": "<display_name>",
              "ansible_host": "<ansible_host>",
              "fqdn": "<fqdn>",
              "insights_id": "<insights_id>",
              "subscription_manager_id": "<subscription_manager_id>",
              "satellite_id": "<satellite_id>",
              "bios_uuid": "<bios_uuid>",
              "ip_addresses": [<ip_addresses>],
              "mac_addresses": [<mac_addresses>],
              "facts": [<facts>],
              "provider_id": "<provider_id>",
              "provider_type": "<provider_type>",
              "created": "<created_date>",
              "updated": "<updated_date>",
              "last_check_in": "<last_check_in_date>",
              "stale_timestamp": "<stale_timestamp>",
              "stale_warning_timestamp": "<stale_warning_timestamp>",
              "culled_timestamp": "<culled_timestamp>",
              "reporter": "<reporter>",
              "tags": [<tags>],
              "system_profile": {<system_profile>},
              "per_reporter_staleness": {<per_reporter_staleness>},
              "groups": [{
                "id": <group_id>,
                "name": <group_name>
              }],
              "openshift_cluster_id": "<openshift_cluster_id>",
           }
        }

    """
    # We know this exists because handle_inventory_message used it
    event_type: str = str(message['type'])
    logger.info(f"Handling '{event_type}' event")

    # Maybe this is a weird way of handling checking the keys, but ... it
    # saves writing what amounts to an exception handler.
    request_id = 'Unknown'
    # Only use 'get' specifically on optional fields, everything else should
    # be required.
    try:
        metadata: dict[str, str] = message['metadata']
        request_id = metadata['request_id']
        host: dict[str, str] = message['host']
        host_id = host['id']
        display_name = host['display_name']
        account = host.get('account')  # optional
        org_id = host['org_id']
        tags = host['tags']
        groups = host['groups']
        created = host['created']
        updated = host['updated']
        insights_id = host['insights_id']
        satellite_id = host.get('satellite_id')  # optional
        # No branch_id ?
        # Sadly the staleness fields are still mandatory even though we
        # should not use them.
        stale_timestamp = host['stale_timestamp']
        stale_warning_timestamp = host['stale_warning_timestamp']
        culled_timestamp = host['culled_timestamp']
        system_profile_field = host['system_profile']
        per_reporter_staleness = host['per_reporter_staleness']
    except KeyError as key_name:
        # Might be missing metadata or request_id...
        key_name = str(key_name).strip("'")  # Error is quoted in single quotes
        if key_name == 'metadata':
            request_id = 'metadata'
        elif key_name == 'request_id':
            request_id = 'unknown request_id'
        # else the request_id variable exists from above
        return log_missing_key(request_id, event_type, key_name)

    # These are the particular fields that Advisor and Tasks uses
    system_profile: dict[str, JsonValue] = extract_system_profile(system_profile_field)

    # Create or update the inventory host.
    # If we're creating the host, we need to supply a system_profile.
    # However, if updating we don't really want to supply a large quantity
    # of system_profile data that may not be changing.  When the system
    # profile data moves into its own model, this may be easier and more
    # efficient.
    inv_host, created = InventoryHost.objects.update_or_create(
        id=host_id,
        defaults={
            'display_name': display_name,
            'account': account,
            'org_id': org_id,
            'tags': tags,
            'groups': groups,
            'created': created,
            'updated': updated,
            'insights_id': insights_id,
            'stale_timestamp': stale_timestamp,
            'stale_warning_timestamp': stale_warning_timestamp,
            'culled_timestamp': culled_timestamp,
            'per_reporter_staleness': per_reporter_staleness,
            'system_profile': system_profile,
        }
    )
    if created:
        prometheus.INVENTORY_HOST_CREATED.inc()
        action = 'Created'
    else:
        prometheus.INVENTORY_HOST_UPDATED.inc()
        action = 'Updated'
    logger.debug(
        "%s Inventory host %s account %s org_id %s",
        action, inv_host.id, account, org_id
    )

    # Also add the Host record
    host_data = {
        'account': account,
        'org_id': org_id,
        # branch_id not in Inventory create/update message?
    }
    if satellite_id:
        host_data['satellite_id'] = satellite_id
    host_obj, created = Host.objects.update_or_create(
        inventory_id=inv_host.id,
        defaults=host_data
    )
    action = 'Created' if created else 'Updated'
    logger.debug(
        "%s Host %s account %s org_id %s",
        action, host_obj.inventory_id, account, org_id
    )


#############################################################################
def handle_deleted_event(message: dict[str, JsonValue]):
    """
    Handle a 'deleted' event message.

    Delete events are of the form:
    {
        "type": "delete",
        "id": "<host id>",
        "timestamp": "<delete timestamp>",
        "account": "<account number>",
        "org_id": "<org_id>",
        "insights_id": "<insights id>",
        "request_id": "<request id>",
        "subscription_manager_id": "<subscription_manager_id>",
        "initiated_by_frontend": "<initiated_by_frontend>",
        "platform_metadata": "<metadata_json_doc>",
        "metadata": {
            "request_id": "<request_id>",
        },
    }

    """
    logger.info("Handling 'deleted' event")

    try:
        request_id = message['request_id']
        inventory_id = message['id']
        account = message.get('account')  # optional
        org_id = message['org_id']
    except KeyError as missing_key:
        key_name = str(missing_key).strip("'")
        if key_name == 'request_id':
            request_id = 'unknown request_id'
        else:
            request_id = message['request_id']
        return log_missing_key(request_id, 'delete', key_name)

    payload_info = {
        'request_id': request_id,
        'inventory_id': inventory_id,
        'account': account,
        'org_id': org_id,
        'source': 'inventory'
    }
    logger.info(
        "Received DELETE event from Inventory for host %s.",
        inventory_id, extra=payload_info
    )

    # Delete Host object and related records - CurrentReport, HostAck,
    # SatMaintenanceAction, and Upload
    deleted_records = Host.objects.filter(
        inventory_id=inventory_id, org_id=org_id
    ).delete()
    logger.info("Deleted %d records based on Host: %s.", *deleted_records)
    # Delete InventoryHost record
    deleted_records = InventoryHost.objects.filter(
        id=inventory_id, org_id=org_id
    ).delete()
    logger.info("Deleted %d records based on InventoryHost: %s.", *deleted_records)
    prometheus.INVENTORY_HOST_DELETED.inc()


#############################################################################
# Helper functions for thread pool integration


def make_async_handler(handler_func, executor):
    """
    Wraps a handler to submit it to the thread pool executor.
    Handler executes asynchronously while wrapper returns immediately.
    """
    def wrapped_handler(topic, message):
        future = executor.submit(handler_func, topic, message)
        future.add_done_callback(on_thread_done)
        logger.debug("Submitted %s to executor", handler_func.__name__)
    return wrapped_handler


def on_thread_done(future):
    """Callback for completed futures to catch exceptions"""
    try:
        future.result()
    except Exception:
        logger.exception("Future %s hit exception", future)


# Main command


class Command(BaseCommand):
    help = "Manage InventoryHost table replication from Inventory Event messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Advisor Inventory replication service starting up')

        receiver = KafkaDispatcher()
        receiver.register_handler(kafka_settings.INVENTORY_TOPIC, handle_inventory_event)

        def terminate(signum: int, _):
            logger.info("Signal %d received, triggering shutdown", signum)
            receiver.quit = True

        _ = signal.signal(signal.SIGTERM, terminate)
        _ = signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Advisor Inventory replication service shutting down')
