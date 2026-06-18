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

import operator
from dataclasses import dataclass
from functools import reduce
from typing import Any

import prometheus
import signal
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils.dateparse import parse_datetime

from advisor_logging import logger
from feature_flags import (
    feature_flag_is_enabled, FLAG_INVENTORY_EVENT_REPLICATION
)
from api.models import AdvisorInventoryHost, Host

from kafka_utils import JsonValue, KafkaDispatcher


@dataclass
class ParsedInventoryHost:
    host_id: str
    display_name: str
    account: str | None
    org_id: str
    tags: list[Any]
    workspace_id: str | None
    workspace_name: str | None
    created: str
    updated: str
    last_check_in: str
    insights_id: str
    satellite_id: str | None
    stale_timestamp: str
    reporter: str
    per_reporter_staleness: dict[str, Any]
    os_name: str | None
    os_major: int | None
    os_minor: int | None
    host_type: str | None
    bootc_booted_image: str | None
    bootc_booted_image_digest: str | None
    owner_id: str | None
    rhc_client_id: str | None
    workloads: dict[str, Any]
    system_update_method: str | None

    def to_advisor_model(self) -> AdvisorInventoryHost:
        return AdvisorInventoryHost(
            inventory_id=self.host_id,
            org_id=self.org_id,
            display_name=self.display_name,
            account=self.account,
            tags=self.tags,
            workspace_id=self.workspace_id,
            workspace_name=self.workspace_name,
            created=self.created,
            updated=self.updated,
            last_check_in=parse_datetime(self.last_check_in),
            insights_id=self.insights_id,
            stale_timestamp=parse_datetime(self.stale_timestamp),
            reporter=self.reporter,
            per_reporter_staleness=self.per_reporter_staleness,
            os_name=self.os_name,
            os_major=self.os_major,
            os_minor=self.os_minor,
            host_type=self.host_type,
            bootc_booted_image=self.bootc_booted_image,
            bootc_booted_image_digest=self.bootc_booted_image_digest,
            owner_id=self.owner_id,
            rhc_client_id=self.rhc_client_id,
            workloads=self.workloads,
            system_update_method=self.system_update_method,
        )

    def to_host_model(self) -> Host:
        return Host(
            inventory_id=self.host_id,
            account=self.account,
            org_id=self.org_id,
            satellite_id=self.satellite_id or None,
        )


@dataclass
class ParsedDeleteEvent:
    inventory_id: str
    org_id: str


def _filter_stale_events(upserts: list[ParsedInventoryHost]) -> list[ParsedInventoryHost]:
    """Filter out events older than what's already in the DB."""
    deduped: dict[tuple, ParsedInventoryHost] = {}
    for item in upserts:
        key = (item.org_id, item.host_id)
        if key not in deduped or item.last_check_in > deduped[key].last_check_in:
            deduped[key] = item
    unique = list(deduped.values())

    existing = AdvisorInventoryHost.objects.filter(
        reduce(operator.or_, (
            Q(org_id=item.org_id, inventory_id=item.host_id)
            for item in unique
        ))
    ).values_list('org_id', 'inventory_id', 'last_check_in')

    existing_ts = {
        (org_id, str(inv_id)): last_check_in
        for org_id, inv_id, last_check_in in existing
    }

    fresh = [
        item for item in unique
        if (item.org_id, item.host_id) not in existing_ts
        or parse_datetime(item.last_check_in) > existing_ts[(item.org_id, item.host_id)]
    ]

    stale_count = len(unique) - len(fresh)
    if stale_count:
        logger.info("Filtered out %d stale events from batch", stale_count)

    return fresh


def handle_inventory_event(topic: str, messages: list[dict[str, JsonValue]]) -> None:
    """
    Handle a batch of inventory events.
    """
    if settings.INVENTORY_EVENT_REPLICATION:
        pass
    elif not feature_flag_is_enabled(FLAG_INVENTORY_EVENT_REPLICATION):
        logger.info(
            "Received %d Inventory events - feature flag not enabled, ignoring",
            len(messages)
        )
        return

    logger.info("Processing batch of %d inventory events", len(messages))

    upserts: list[ParsedInventoryHost] = []
    created_count = 0
    updated_count = 0
    delete_data: list[ParsedDeleteEvent] = []

    for message in messages:
        try:
            if 'type' not in message:
                logger.error("Message received on topic %s with no 'type' field", topic)
                prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
                continue

            match message['type']:
                case 'created':
                    parsed = parse_created_event(message)
                    if parsed is not None:
                        upserts.append(parsed)
                        created_count += 1
                case 'updated':
                    parsed = parse_created_event(message)
                    if parsed is not None:
                        upserts.append(parsed)
                        updated_count += 1
                case 'delete':
                    parsed = parse_deleted_event(message)
                    if parsed is not None:
                        delete_data.append(parsed)
                case msg_type:
                    logger.error("Inventory event: Unknown message type: %s", msg_type)
        except Exception:
            logger.exception("Failed to parse inventory event, skipping")
            continue

    if upserts:
        # TOCTOU: a concurrent write between this check and bulk_upsert_hosts
        # could be overwritten. Low risk (Kafka partitions by host ID) and
        # self-correcting on the next event.
        upserts = _filter_stale_events(upserts)

    if upserts:
        logger.debug("Starting bulk upsert of %d hosts (%d created, %d updated)",
                      len(upserts), created_count, updated_count)
        bulk_upsert_hosts(upserts)
        logger.debug("Bulk upsert committed successfully")
        prometheus.INVENTORY_HOST_CREATED.inc(created_count)
        prometheus.INVENTORY_HOST_UPDATED.inc(updated_count)

    if delete_data:
        logger.debug("Starting bulk delete of %d hosts", len(delete_data))
        bulk_delete_hosts(delete_data)
        logger.debug("Bulk delete committed successfully")
        prometheus.INVENTORY_HOST_DELETED.inc(len(delete_data))


def log_missing_key(request_id: str, event_type: str, key_name: str):
    logger.error(
        "Request %s: Inventory %s event did not contain required key '%s'",
        request_id, event_type, key_name
    )
    prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()


def parse_created_event(message: dict[str, JsonValue]) -> ParsedInventoryHost | None:
    """
    Validate and extract fields from a created/updated event message.
    Returns a ParsedInventoryHost, or None if validation fails.
    """
    event_type: str = str(message['type'])
    host_data = message.get('host', {}) or {}
    org_id = host_data.get('org_id')
    host_id = host_data.get('id')
    logger.info("Handling '%s' event for org=%s, host_id=%s", event_type, org_id, host_id)

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
        last_check_in = host['last_check_in']
        insights_id = host['insights_id']
        satellite_id = host.get('satellite_id')  # optional
        stale_timestamp = host['stale_timestamp']
        system_profile_field = host['system_profile']
        reporter = host['reporter']
        per_reporter_staleness = host['per_reporter_staleness']
    except KeyError as key_name:
        key_name = str(key_name).strip("'")
        if key_name == 'metadata':
            request_id = 'metadata'
        elif key_name == 'request_id':
            request_id = 'unknown request_id'
        log_missing_key(request_id, event_type, key_name)
        return None

    if not insights_id:
        logger.error(
            "Request %s: Inventory %s event has null or empty insights_id for host %s",
            request_id, event_type, host_id
        )
        prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
        return None

    system_profile_raw: dict[str, JsonValue] = system_profile_field
    os_info = system_profile_raw.get('operating_system', {})
    bootc = system_profile_raw.get('bootc_status', {})
    bootc_booted = bootc.get('booted', {}) if isinstance(bootc, dict) else {}

    workloads = system_profile_raw.get('workloads', {})
    workloads = workloads if isinstance(workloads, dict) else {}

    workspace_id = groups[0].get('id') if groups else None
    workspace_name = groups[0].get('name') if groups else None

    return ParsedInventoryHost(
        host_id=host_id,
        display_name=display_name,
        account=account,
        org_id=org_id,
        tags=tags,
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        created=created,
        updated=updated,
        last_check_in=last_check_in,
        insights_id=insights_id,
        satellite_id=satellite_id,
        stale_timestamp=stale_timestamp,
        reporter=reporter,
        per_reporter_staleness=per_reporter_staleness,
        os_name=os_info.get('name') if isinstance(os_info, dict) else None,
        os_major=os_info.get('major') if isinstance(os_info, dict) else None,
        os_minor=os_info.get('minor') if isinstance(os_info, dict) else None,
        host_type=system_profile_raw.get('host_type'),
        bootc_booted_image=bootc_booted.get('image') if isinstance(bootc_booted, dict) else None,
        bootc_booted_image_digest=bootc_booted.get('image_digest') if isinstance(bootc_booted, dict) else None,
        owner_id=system_profile_raw.get('owner_id') or None,
        rhc_client_id=system_profile_raw.get('rhc_client_id') or None,
        workloads=workloads,
        system_update_method=system_profile_raw.get('system_update_method'),
    )


def parse_deleted_event(message: dict[str, JsonValue]) -> ParsedDeleteEvent | None:
    """
    Validate and extract fields from a delete event message.
    Returns a ParsedDeleteEvent, or None if validation fails.
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
        log_missing_key(request_id, 'delete', key_name)
        return None

    logger.info(
        "Received DELETE event from Inventory for host %s.",
        inventory_id,
        extra={
            'request_id': request_id,
            'inventory_id': inventory_id,
            'account': account,
            'org_id': org_id,
            'source': 'inventory'
        }
    )

    return ParsedDeleteEvent(
        inventory_id=inventory_id,
        org_id=org_id,
    )


def bulk_upsert_hosts(upserts: list[ParsedInventoryHost]) -> None:
    """Bulk upsert AdvisorInventoryHost and Host records."""
    inv_instances = [item.to_advisor_model() for item in upserts]
    AdvisorInventoryHost.objects.bulk_create(
        inv_instances,
        update_conflicts=True,
        unique_fields=['org_id', 'inventory_id'],
        update_fields=[
            'display_name', 'account', 'tags', 'workspace_id', 'workspace_name',
            'created', 'updated', 'last_check_in', 'insights_id', 'stale_timestamp',
            'reporter', 'per_reporter_staleness', 'os_name', 'os_major', 'os_minor',
            'host_type', 'bootc_booted_image', 'bootc_booted_image_digest',
            'owner_id', 'rhc_client_id', 'workloads', 'system_update_method',
        ],
    )
    logger.debug("Bulk upserted %d AdvisorInventoryHost records", len(inv_instances))

    host_instances = [item.to_host_model() for item in upserts]
    Host.objects.bulk_create(
        host_instances,
        update_conflicts=True,
        unique_fields=['inventory_id'],
        update_fields=['account', 'org_id', 'satellite_id'],
    )
    logger.debug("Bulk upserted %d Host records", len(host_instances))


def bulk_delete_hosts(deletes: list[ParsedDeleteEvent]) -> None:
    """Bulk delete Host and AdvisorInventoryHost records."""
    requested = len(deletes)
    delete_q = Q()
    for item in deletes:
        delete_q |= Q(inventory_id=item.inventory_id, org_id=item.org_id)

    deleted_hosts = Host.objects.filter(delete_q).delete()
    logger.info("Batch deleted %d records based on Host: %s.", *deleted_hosts)

    deleted_inv = AdvisorInventoryHost.objects.filter(delete_q).delete()
    logger.info("Batch deleted %d records based on AdvisorInventoryHost: %s.", *deleted_inv)

    deleted_count = deleted_inv[0]
    missing = requested - deleted_count
    if missing > 0:
        logger.warning(
            "Delete mismatch: requested=%d, deleted=%d, missing=%d",
            requested, deleted_count, missing
        )
        prometheus.INVENTORY_HOST_DELETE_MISSING.inc(missing)


class Command(BaseCommand):
    help = "Manage InventoryHost table replication from Inventory Event messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Advisor Inventory replication service starting up')
        settings.KAFKA_SETTINGS.update({
            'group.id': settings.GROUP_ID,
            'enable.auto.commit': False,
            'enable.auto.offset.store': False,
        })
        receiver = KafkaDispatcher()
        receiver.register_handler(settings.INVENTORY_EVENTS_TOPIC, handle_inventory_event, batch=True)

        def terminate(signum: int, _):
            logger.info("Signal %d received, triggering shutdown", signum)
            receiver.quit = True

        _ = signal.signal(signal.SIGTERM, terminate)
        _ = signal.signal(signal.SIGINT, terminate)
        receiver.receive(batch_size=settings.INVENTORY_BATCH_SIZE)
        logger.info('Advisor Inventory replication service shutting down')
