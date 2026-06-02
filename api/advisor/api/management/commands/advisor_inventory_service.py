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

from django.conf import settings
# NB: it would be better if we imported the topics directly, because that
# detects a name error at compile time rather than run time (cf Rusty's API
# design manifesto, level 9 is better than level 5).
# Reference: https://gist.github.com/mjball/9cd028ac793ae8b351df1379f1e721f9
from django.core.management.base import BaseCommand

from advisor_logging import logger
from feature_flags import (
    feature_flag_is_enabled, FLAG_INVENTORY_EVENT_REPLICATION
)
from api.models import AdvisorInventoryHost, Host  # pyright: ignore[reportImplicitRelativeImport]

from kafka_utils import JsonValue, KafkaDispatcher  # , send_kafka_message


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

    if settings.INVENTORY_EVENT_REPLICATION:
        # If the environment variable is set, always process the event.
        pass
    elif not feature_flag_is_enabled(FLAG_INVENTORY_EVENT_REPLICATION):
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
        last_check_in = host['last_check_in']
        insights_id = host['insights_id']
        satellite_id = host.get('satellite_id')  # optional
        # No branch_id ?
        # Sadly the staleness fields are still mandatory even though we
        # should not use them.
        stale_timestamp = host['stale_timestamp']
        system_profile_field = host['system_profile']
        reporter = host['reporter']
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

    if not insights_id:
        logger.error(
            "Request %s: Inventory %s event has null or empty insights_id for host %s",
            request_id, event_type, host_id
        )
        prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
        return

    system_profile_raw: dict[str, JsonValue] = system_profile_field
    os_info = system_profile_raw.get('operating_system', {})
    bootc = system_profile_raw.get('bootc_status', {})
    bootc_booted = bootc.get('booted', {}) if isinstance(bootc, dict) else {}

    workloads = system_profile_raw.get('workloads', {})
    workloads = workloads if isinstance(workloads, dict) else {}

    workspace_id = groups[0].get('id') if groups else None
    workspace_name = groups[0].get('name') if groups else None

    inv_host, was_created = AdvisorInventoryHost.objects.update_or_create(
        org_id=org_id,
        inventory_id=host_id,
        defaults={
            'display_name': display_name,
            'account': account,
            'tags': tags,
            'workspace_id': workspace_id,
            'workspace_name': workspace_name,
            'created': created,
            'updated': updated,
            'last_check_in': last_check_in,
            'insights_id': insights_id,
            'stale_timestamp': stale_timestamp,
            'reporter': reporter,
            'per_reporter_staleness': per_reporter_staleness,
            'os_name': os_info.get('name') if isinstance(os_info, dict) else None,
            'os_major': os_info.get('major') if isinstance(os_info, dict) else None,
            'os_minor': os_info.get('minor') if isinstance(os_info, dict) else None,
            'host_type': system_profile_raw.get('host_type'),
            'bootc_booted_image': bootc_booted.get('image') if isinstance(bootc_booted, dict) else None,
            'bootc_booted_image_digest': bootc_booted.get('image_digest') if isinstance(bootc_booted, dict) else None,
            'owner_id': system_profile_raw.get('owner_id') or None,
            'rhc_client_id': system_profile_raw.get('rhc_client_id') or None,
            'workloads': workloads,
            'system_update_method': system_profile_raw.get('system_update_method'),
        }
    )
    if was_created:
        prometheus.INVENTORY_HOST_CREATED.inc()
        action = 'Created'
    else:
        prometheus.INVENTORY_HOST_UPDATED.inc()
        action = 'Updated'
    logger.debug(
        "%s Inventory host %s account %s org_id %s",
        action, inv_host.inventory_id, account, org_id
    )

    # Also add the Host record
    host_data = {
        'account': account,
        'org_id': org_id,
        # branch_id not in Inventory create/update message?
    }
    if satellite_id:
        host_data['satellite_id'] = satellite_id
    host_obj, was_created = Host.objects.update_or_create(
        inventory_id=inv_host.inventory_id,
        defaults=host_data
    )
    action = 'Created' if was_created else 'Updated'
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
    # Delete AdvisorInventoryHost record
    deleted_records = AdvisorInventoryHost.objects.filter(
        inventory_id=inventory_id, org_id=org_id
    ).delete()
    logger.info("Deleted %d records based on AdvisorInventoryHost: %s.", *deleted_records)
    prometheus.INVENTORY_HOST_DELETED.inc()


# Main command


class Command(BaseCommand):
    help = "Manage InventoryHost table replication from Inventory Event messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Advisor Inventory replication service starting up')
        settings.KAFKA_SETTINGS.update({'group.id': settings.GROUP_ID})
        receiver = KafkaDispatcher()
        receiver.register_handler(settings.INVENTORY_EVENTS_TOPIC, handle_inventory_event)

        def terminate(signum: int, _):
            logger.info("Signal %d received, triggering shutdown", signum)
            receiver.quit = True

        _ = signal.signal(signal.SIGTERM, terminate)
        _ = signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Advisor Inventory replication service shutting down')
