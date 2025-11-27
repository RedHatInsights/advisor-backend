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
from typing import Any

from django.conf import settings
from project_settings import kafka_settings
from django.core.management.base import BaseCommand

import payload_tracker

from advisor_logging import logger
from api.models import InventoryHost, Host

from tasks.kafka_utils import send_event_message, KafkaDispatcher, send_kakfa_message


# From service/utils.py
def traverse_keys(d: dict[str, dict | str], keys: list[str], default: str | None = None):
    """
    Allows you to look up a 'path' of keys in nested dicts without knowing
    whether each key exists
    """
    key = keys.pop(0)
    item = d.get(key, default)
    if len(keys) == 0:
        return item
    return traverse_keys(item, keys, default)


def handle_inventory_event(topic: str, message) -> None:
    """
    Handle inventory events.

    The inventory event messages are documented at:
    https://inscope.corp.redhat.com/docs/default/component/host-based-inventory/#created-event
    """
    if 'type' not in message:
        logger.error("Message received on topic %s with no 'type' field", topic)
        return

    if message['type'] == 'delete':
        handle_delete_event(message)
    elif message['type'] == 'created' or message['type'] == 'updated':
        handle_update_event(message)
    else:
        logger.error(
            "Inventory event: Unknown message type: %s", message['type']
        )



def handle_created_event(message: dict[str, Any]):
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
    try:
        metadata = message['metadata']
        request_id = metadata['request_id']
        host = message['host']
        host_id = message['id']
        display_name = host['display_name']
        account = host.get('account_number')  # optional
        org_id = host['org_id']
        tags = host['tags']
        groups = host['groups']
        created = host['created']
        updated = host['updated']
        insights_id = host['insights_id']
        satellite_id = host['satellite_id']
        # No branch_id ?
        # Do we care about the staleness timestamp fields, when we only use
        # the per_reporter_staleness field?
        per_reporter_staleness = host['per_reporter_staleness']
    except KeyError as key_name:
        logger.error(
            "Request %s: Inventory event did not contain required key '%s'",
            request_id, key_name
        )
        prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
        payload_tracker.bad_payload(
            'inventory', message, f'Inventory event missing {key_name} key'
        )
        return

    # Create or update the inventory host, without setting the system_profile
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
            'per_reporter_staleness': per_reporter_staleness
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
    payload_tracker.good_payload('inventory', message)

    # Now update the system_profile from the message, only changing the fields
    # we care about in Advisor and Tasks.
    # This would also suit an environment in which the system_profile was
    # separated out into a different model.
    system_profile_updated = False
    # These are the particular fields that Advisor and Tasks uses
    for item in (
        'ansible', 'bootc_status', 'host_type', 'mssql', 'operating_system',
        'owner_id', 'rhc_client_id', 'sap', 'sap_system', 'sap_sids',
        # need to phase out sap_system and sap_sids in favour of sap structure.
        'system_update_method',
    ):
        if item in message:
            # copy all items across, but only update if the value has changed.
            system_profile[item] = message[item]
            if message[item] != inv_host.system_profile[item]:
                system_profile_updated = True
        if system_profile_updated:
            inv_host.system_profile = system_profile
            inv_host.save()
            logger.info("Updated system profile for host %s", inv_host.id)

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
        action, inv_host.id, account, org_id
    )


def handle_deleted_event(message):
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
        metadata = message['metadata']
        request_id = metadata['request_id']
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
        payload_tracker.bad_payload(
            'inventory', message, 'Inventory event missing keys.'
        )
        return

    payload_info = {
        'request_id': request_id,
        'inventory_id': inventory_id,
        'account': account,
        'org_id': org_id,
        'source': 'inventory'
    }

    payload_tracker.payload_status(
        'received', 'Received DELETE event from Inventory.', payload_info
    )
    logger.info("Received DELETE event from Inventory.", extra=payload_info)

    # Delete Host object and related records - CurrentReport, HostAck,
    # SatMaintenanceAction, and Upload
    deleted_records = Host.objects.filter(
        host_id=inventory_id, org_id=org_id, current=True
    ).delete()
    logger.info("Deleted %d records based on Host: %s.", *deleted_records)
    # Delete InventoryHost record
    deleted_records = InventoryHost.objects.filter(
        host_id=inventory_id, org_id=org_id
    ).delete()
    logger.info("Deleted %d records based on InventoryHost: %s.", *deleted_records)


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
            logger.info("SIGTERM received, triggering shutdown")
            receiver.quit = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Tasks service shutting down')
