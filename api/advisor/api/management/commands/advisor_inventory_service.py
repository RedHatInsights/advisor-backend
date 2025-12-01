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

# from django.conf import settings
from project_settings import kafka_settings
from django.core.management.base import BaseCommand

from advisor_logging import logger
from api.models import InventoryHost, Host  # pyright: ignore[reportImplicitRelativeImport]

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

    match message['type']:
        case 'delete':
            handle_deleted_event(message)
        case 'created' | 'updated':
            handle_created_event(message)
        case msg_type:
            logger.error("Inventory event: Unknown message type: %s", msg_type)


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
    logger.info(f"Handling '{message['type']}' event")

    # Maybe this is a weird way of handling checking the keys, but ... it
    # saves writing what amounts to an exception handler.
    request_id = 'Unknown'
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
        satellite_id = host['satellite_id']
        # No branch_id ?
        # Sadly the staleness fields are still mandatory even though we
        # should not use them.
        stale_timestamp = host['stale_timestamp']
        stale_warning_timestamp = host['stale_warning_timestamp']
        culled_timestamp = host['culled_timestamp']
        system_profile_field = host['system_profile']
        per_reporter_staleness = host['per_reporter_staleness']
    except KeyError as key_name:
        logger.error(
            "Request %s: Inventory event did not contain required key '%s'",
            request_id, key_name
        )
        prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
        return

    # These are the particular fields that Advisor and Tasks uses
    system_profile: dict[str, JsonValue] = {
        key: system_profile_field[key]
        for key in (
            'ansible', 'bootc_status', 'host_type', 'mssql', 'operating_system',
            'owner_id', 'rhc_client_id', 'sap', 'sap_system', 'sap_sids',
            # need to phase out sap_system and sap_sids in favour of sap structure.
            'system_update_method',
        ) if key in system_profile_field
    }

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
    host_obj, created = Host.objects.update_or_create(
        inventory_id=inv_host.id,
        defaults={
            'account': inv_host.account,
            'org_id': inv_host.org_id,
            'satellite_id': satellite_id,
            # branch_id not in Inventory create/update message?
        }
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
        request_id = message['request_id']
    except KeyError as missing_key:
        logger.error(
            "Inventory event did not contain required key %s",
            missing_key
        )
        prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
        return

    payload_info = {
        'request_id': request_id,
        'inventory_id': inventory_id,
        'account': account,
        'org_id': org_id,
        'source': 'inventory'
    }
    logger.info("Received DELETE event from Inventory.", extra=payload_info)

    # Delete Host object and related records - CurrentReport, HostAck,
    # SatMaintenanceAction, and Upload
    deleted_records = Host.objects.filter(
        inventory_id=inventory_id, org_id=org_id, current=True
    ).delete()
    logger.info("Deleted %d records based on Host: %s.", *deleted_records)
    # Delete InventoryHost record
    deleted_records = InventoryHost.objects.filter(
        id=inventory_id, org_id=org_id
    ).delete()
    logger.info("Deleted %d records based on InventoryHost: %s.", *deleted_records)
    prometheus.INVENTORY_HOST_DELETED.inc()


# Main command


class Command(BaseCommand):
    help = "Updates the job and executed task states based on Kafka messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Tasks service starting up')

        receiver = KafkaDispatcher()
        receiver.register_handler(kafka_settings.INVENTORY_TOPIC, handle_inventory_event)

        def terminate(signum, frame):
            logger.info("Signal %d received, triggering shutdown", signum)
            receiver.quit = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Tasks service shutting down')
