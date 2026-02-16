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
from django.db.models import Exists, OuterRef
from django.utils import timezone
from project_settings import kafka_settings

import build_info
import payload_tracker
import reports as report_hooks
import thread_storage
import utils
from advisor_logging import logger
from api.models import (
    Ack, CurrentReport, Host, InventoryHost,
    Rule, SystemType, Upload, UploadSource
)
from feature_flags import (
    feature_flag_is_enabled, FLAG_INVENTORY_EVENT_REPLICATION
)
from kafka_utils import JsonValue, KafkaDispatcher


#############################################################################
# Inventory event handler


@prometheus.INSIGHTS_ADVISOR_SERVICE_INVENTORY_EVENTS_ELAPSED.time()
def handle_inventory_event(topic: str, message: dict[str, JsonValue]) -> None:
    """
    Handle inventory events from platform.inventory.events topic.

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
# Engine results and rule hits handlers


@prometheus.INSIGHTS_ADVISOR_SERVICE_HANDLE_ENGINE_RESULTS.time()
def handle_engine_results(topic: str, engine_results: dict[str, JsonValue]) -> None:
    """
    Handle engine results received from the shared engine instance.
    This comes in on platform.engine.results topic.
    """
    # Clean threading cruft and start function metrics
    utils.clean_threading_cruft()
    engine_results_started = time.time()
    thread_storage.set_value('engine_results_started', engine_results_started)
    thread_storage.set_value('engine_results_error', 0)
    logger.debug("Handling engine results %s", engine_results)

    # Required engine results keys
    # Account number has been removed as it is no longer required, only optional
    key_paths = {
        "engine_reports": ["results", "reports"],
        "system_data": ["results", "system"],
        "platform_data": ["input", "platform_metadata"],
        "request_id": ["input", "platform_metadata", "request_id"],
        "inventory_uuid": ["input", "host", "id"],
        "org_id": ["input", "platform_metadata", "org_id"]
    }

    def send_bad_payload_msg(data: dict[str, str], null_keys: list[str]):
        payload_info = {
            'source': 'insights-client',
            'request_id': data.get('request_id'),
            'account': utils.traverse_keys(engine_results, ["input", "host", "account"]),
            'org_id': data.get('org_id'),
            'inventory_id': data.get('inventory_uuid')
        }
        missing_paths = ",".join(["/".join(key_paths[key]) for key in null_keys])
        payload_tracker.bad_payload('insights-client', payload_info, missing_paths)
        logger.error(
            "Key paths not found/null in engine results at paths: %s",
            missing_paths
        )
        return None

    data = {key: utils.traverse_keys(engine_results, key_path)
                 for key, key_path in key_paths.items()}
    null_keys = [key for key, val in data.items() if val is None]
    if len(null_keys):
        return send_bad_payload_msg(data, null_keys)

    # get host and platform data
    try:
        engine_reports = data.get('engine_reports')
        system_data = data.get('system_data')
        platform_data = data.get('platform_data')
        request_id = data.get('request_id')
        inventory_uuid = data.get('inventory_uuid')
        account = utils.traverse_keys(engine_results, ["input", "host", "account"])
        org_id = data.get('org_id')
    except Exception:
        return send_bad_payload_msg(data, null_keys)

    # attempt to get the system ID for easy debugging/lookup
    # this is not necessarily guaranteed or required
    # so we dont include it in the above "key_paths"
    system_id = system_data.get('system_id')
    if system_id:
        thread_storage.set_value('system_id', system_id)

    # send processing metrics
    thread_storage.set_value('request_id', request_id)
    thread_storage.set_value('inventory_id', inventory_uuid)
    thread_storage.set_value('source', 'insights-client')
    thread_storage.set_value('account', account)
    thread_storage.set_value('org_id', org_id)
    payload_tracker.payload_status('received', 'Processing engine results')
    logger.info("Processing engine results for Inventory ID %s on account %s and org_id %s",
                inventory_uuid, account, org_id)

    # system type and produce code information
    system_type = system_data.get('type')
    system_product = system_data.get('product')
    db_system_type = SystemType.objects.filter(
        role=system_type,
        product_code=system_product
    ).first()

    if not db_system_type:
        thread_storage.set_value('engine_results_error', 1)
        thread_storage.set_value('engine_results_error_msg', 'missing system_type')
        engine_results_finished = time.time()
        engine_results_elapsed = engine_results_finished - engine_results_started
        thread_storage.set_value('engine_results_finished', engine_results_finished)
        thread_storage.set_value('engine_results_elapsed', engine_results_elapsed)
        logger.error(
            f"Unable to get system type {system_product} / "
            f"{system_type} from DB - load fixtures!"
        )
        payload_tracker.payload_status('invalid', 'Invalid system type.')
        return False

    # add reports to the database
    satellite_managed = platform_data.get('satellite_managed', False)
    satellite_id = system_data.get('remote_leaf', None)
    if satellite_id == -1:
        satellite_id = None
    branch_id = system_data.get('remote_branch', None)
    if branch_id == -1:
        branch_id = None

    if create_db_reports(
        engine_reports, inventory_uuid, account, org_id, db_system_type, 'insights-client',
        satellite_managed, satellite_id, branch_id,
    ):
        engine_results_finished = time.time()
        engine_results_elapsed = engine_results_finished - engine_results_started
        thread_storage.set_value('engine_results_finished', engine_results_finished)
        thread_storage.set_value('engine_results_elapsed', engine_results_elapsed)
        return True
    else:
        engine_results_finished = time.time()
        engine_results_elapsed = engine_results_finished - engine_results_started
        thread_storage.set_value('engine_results_error', 1)
        thread_storage.set_value('engine_results_error_msg', 'Failure processing engine results.')
        thread_storage.set_value('engine_results_finished', engine_results_finished)
        thread_storage.set_value('engine_results_elapsed', engine_results_elapsed)
        payload_tracker.payload_status('error', 'Failure processing engine results.')
        logger.error('Failure processing engine results.')
        return False


@prometheus.INSIGHTS_ADVISOR_SERVICE_RULE_HITS_ELAPSED.time()
def handle_rule_hits(topic: str, rule_hits_json: dict[str, JsonValue]) -> None:
    """
    Handle third-party rule hits from platform.insights.rule-hits topic.
    """
    utils.clean_threading_cruft()

    rule_hits_started = time.time()
    thread_storage.set_value('rule_hits_started', rule_hits_started)
    thread_storage.set_value('rule_hits_error', 0)

    required_keys = ['org_id', 'source', 'host_product', 'host_role', 'inventory_id', 'hits']
    missing_keys = [key for key in required_keys if key not in rule_hits_json]
    if missing_keys:
        rule_hits_finished = time.time()
        thread_storage.set_value('rule_hits_finished', rule_hits_finished)
        thread_storage.set_value('rule_hits_elapsed', rule_hits_finished - rule_hits_started)
        thread_storage.set_value('rule_hits_error', 1)
        thread_storage.set_value('rule_hits_error_msg', 'missing_keys')
        prometheus.THIRD_PARTY_RULE_HIT_MISSING_KEYS.inc()
        payload_info = {'request_id': 'third-party'}
        for key in required_keys:
            if key in rule_hits_json:
                payload_info[key] = rule_hits_json[key]
        payload_tracker.payload_status('invalid',
                       f"Third party rule hits did not contain valid keys {required_keys}",
                       payload_info)
        logger.error(f"Third party rule hits did not contain valid keys {required_keys}")
        return False

    thread_storage.set_value('request_id', 'third-party')
    thread_storage.set_value('inventory_id', rule_hits_json['inventory_id'])
    thread_storage.set_value('source', rule_hits_json['source'])
    thread_storage.set_value('account', rule_hits_json.get('account'))
    thread_storage.set_value('org_id', rule_hits_json['org_id'])
    payload_tracker.payload_status('processing', 'Beginning rule hit analysis.')

    system_type = None
    rule_hits_json['host_role'] = rule_hits_json['host_role'].lower()
    rule_hits_json['host_product'] = rule_hits_json['host_product'].lower()
    system_type = SystemType.objects.filter(
        role=rule_hits_json['host_role'],
        product_code=rule_hits_json['host_product']
    ).first()

    if not system_type:
        thread_storage.set_value('rule_hits_error', 1)
        thread_storage.set_value('rule_hits_error_msg', 'missing system_type')
        rule_hits_finished = time.time()
        thread_storage.set_value('rule_hits_finished', rule_hits_finished)
        thread_storage.set_value('rule_hits_elapsed', rule_hits_finished - rule_hits_started)
        logger.error(
            f"Unable to get system type {rule_hits_json['host_product']} / "
            f"{rule_hits_json['host_role']} from DB - load fixtures!"
        )
        payload_tracker.payload_status('invalid', 'Invalid system type.')
        return False
    else:
        logger.debug("Valid system type found for system type:%s, system product:%s.",
            rule_hits_json['host_product'],
            rule_hits_json['host_role'])

    logger.debug("Generating reports for Inventory ID:%s, Account:%s, Org ID: %s.",
                rule_hits_json['inventory_id'], rule_hits_json.get('account'), rule_hits_json['org_id'])
    payload_tracker.payload_status('processing', 'Creating reports.')
    if create_db_reports(rule_hits_json['hits'], rule_hits_json['inventory_id'],
                      rule_hits_json.get('account'), rule_hits_json['org_id'],
                      system_type, rule_hits_json['source']):
        rule_hits_finished = time.time()
        thread_storage.set_value('rule_hits_finished', rule_hits_finished)
        thread_storage.set_value('rule_hits_elapsed', rule_hits_finished - rule_hits_started)
    else:
        rule_hits_finished = time.time()
        thread_storage.set_value('rule_hits_finished', rule_hits_finished)
        thread_storage.set_value('rule_hits_elapsed', rule_hits_finished - rule_hits_started)
        thread_storage.set_value('rule_hits_error', 1)
        thread_storage.set_value('rule_hits_error_msg', "Error processing third party rule hits.")
        extra_info = {}
        for key in required_keys:
            if key in rule_hits_json:
                extra_info[key] = rule_hits_json[key]
        logger.error("Error processing third party rule hits.", extra=extra_info)
    return True


#############################################################################
@prometheus.INSIGHTS_ADVISOR_SERVICE_DB_ELAPSED.time()
def create_db_reports(
    reports, inventory_uuid, account, org_id, system_type, source,
    satellite_managed=None, satellite_id=None, branch_id=None,
):
    """
    Create all the reports for a given inventory host from engine results or rule hits.

    This function:
    - Creates/updates Host records
    - Creates/updates Upload records
    - Creates/updates CurrentReport records
    - Handles autoack logic for new accounts
    - Filters reports by RHEL version
    - Triggers webhooks and remediations
    """
    # Satisfy the DB's requirement that this field be a non-null boolean
    if not satellite_managed:
        satellite_managed = False
    else:
        satellite_managed = True

    new_report_objs = []
    existing_report_objs = []
    webhook_report_rule_objs = []
    db_started = time.time()
    thread_storage.set_value('db_started', db_started)
    thread_storage.set_value('db_error', 0)

    logger.debug(f"Retrieving upload source type for {source}")
    upload_source = None
    upload_source_created = None

    def log_db_failure(message, get_exception=False):
        if get_exception:
            the_error = traceback.format_exc()
            message += f': {the_error}'
        db_finished = time.time()
        db_elapsed = db_finished - db_started
        thread_storage.set_value('db_finished', db_finished)
        thread_storage.set_value('db_elapsed', db_elapsed)
        thread_storage.set_value('db_error', 1)
        thread_storage.set_value('db_error_msg', message)
        prometheus.INSIGHTS_ADVISOR_DB_ERRORS.inc()
        payload_tracker.payload_status('error', message)
        logger.error(message)

    # Create/Update Host information
    try:
        # search for an existing host
        host_obj = Host.objects.filter(inventory_id=inventory_uuid).first()

        def update_host(host_obj, **kwargs):
            """
            Update the host with a set of key=value pairs.  If the field value
            is different from the key value, the host_obj's field is updated.
            A list of updated fields is returned.
            """
            updated_fields = list()
            for key, value in kwargs.items():
                if value and getattr(host_obj, key) != value:
                    setattr(host_obj, key, value)
                    updated_fields.append(key)
            return updated_fields

        # if no host was found, create a new one
        if not host_obj:
            # Good point to check if this is a new account and if so, add
            # autoacked rules for them.  We assume a new account if no
            # existing (current) uploads from that account.  Since the latest
            # upload is always the current one, the only situation in which
            # an account can have only non-current uploads is if they send a
            # delete for every single host they have; here, and in the
            # sat-compat API, we only delete current uploads, not historic.
            # However, since we only create the acks if they don't already
            # exist, we don't need to worry about that rare case.
            if not Upload.objects.filter(org_id=org_id, current=True).exists():
                logger.debug(
                    "No uploads for account %s org_id %s - assuming new account, creating autoacks",
                    account, org_id
                )
                new_acks = []
                autoack_rules = Rule.objects.filter(
                    tags__name=settings.AUTOACK['TAG'], ack__isnull=True
                )
                for autoack_rule in autoack_rules:
                    new_acks.append(Ack(
                        rule=autoack_rule, account=account, org_id=org_id,
                        justification=settings.AUTOACK['JUSTIFICATION'],
                        created_by=settings.AUTOACK['CREATED_BY']
                    ))
                if new_acks:
                    Ack.objects.bulk_create(new_acks)
                    logger.debug("Created %d new acks", len(new_acks))

            host_obj = Host(inventory_id=inventory_uuid, account=account, org_id=org_id)
            update_host(
                host_obj,
                satellite_id=satellite_id, branch_id=branch_id
            )
            host_obj.save()

        # if a host object was found and we are updating information
        elif host_obj:
            updated_fields = update_host(
                host_obj,
                satellite_id=satellite_id, branch_id=branch_id
            )

            if updated_fields:
                host_obj.save(update_fields=updated_fields)

    except Exception:
        log_db_failure('Could not create host', get_exception=True)
        return False

    try:
        with transaction.atomic():
            # lock on system uuid to avoid race conditions
            Host.objects.select_for_update().get(inventory_id=inventory_uuid)

            # Get the current reports before we archive them
            # so that we can filter for webhooks
            db_reports = CurrentReport.objects.filter(
                host=inventory_uuid, org_id=org_id
            ).order_by('rule__rule_id')
            db_report_values = list(db_reports.values(
                'id', 'rule_id', 'rule__active', 'rule__total_risk',
                'rule__description', 'rule__publish_date', 'rule__rule_id',
                'rule__reboot_required', 'impacted_date'
            ).annotate(
                has_incident=Exists(Rule.objects.filter(
                    id=OuterRef('rule'), tags__name='incident'))
            ))
            logger.debug("Got DB reports %s", db_report_values)

            upload_source, upload_source_created = UploadSource.objects.get_or_create(name=source)

            if not upload_source:
                raise Exception('upload source is missing')

            # Update existing or create new upload
            upload, created = Upload.objects.update_or_create(
                host_id=inventory_uuid,
                org_id=org_id,
                source=upload_source,
                defaults={
                    'account': account,
                    'checked_on': timezone.now(),
                    'is_satellite': satellite_managed,
                    'system_type': system_type
                }
            )
            message = "Created new" if created else "Updated existing"
            logger.debug(
                f"{message} upload for system UUID (inventory ID) "
                f"{inventory_uuid} with ID {upload.id} ready for (up to) "
                f"{len(reports)} reports"
            )

            # Filter out reports/rules for non-rhel systems (if turned on)
            report_rule_ids = [x['rule_id'] for x in reports]
            logger.debug("Getting report rule IDs %s", report_rule_ids)
            if settings.FILTER_OUT_NON_RHEL:
                if any(r_id in settings.FILTER_OUT_NON_RHEL_RULE_ID for r_id in report_rule_ids):
                    logger.debug("Filtering out non rhel rule id %s",
                                 settings.FILTER_OUT_NON_RHEL_RULE_ID)
                    report_rule_ids = settings.FILTER_OUT_NON_RHEL_RULE_ID

            # Filter out reports/rules for RHEL6 systems to only include ones to upgrade
            if settings.FILTER_OUT_RHEL6:
                reported_rhel6_rules = list(set(report_rule_ids).intersection(set(settings.FILTER_OUT_RHEL6_RULE_IDS)))
                if reported_rhel6_rules:
                    logger.debug("Filtering out rhel6 rule id %s", reported_rhel6_rules)
                    report_rule_ids = reported_rhel6_rules

            logger.debug("Final report rule IDs %s", report_rule_ids)
            report_rules = Rule.objects.filter(rule_id__in=report_rule_ids).values(
                'id', 'rule_id', 'active', 'total_risk', 'description',
                'publish_date', 'reboot_required'
            ).annotate(
                has_incident=Exists(Rule.objects.filter(id=OuterRef('id'), tags__name='incident'))
            ).order_by('rule_id')
            logger.debug("Report rules from database %s", report_rules)
            report_rules_map = dict((i['rule_id'], i) for i in report_rules)
            logger.debug("Report rules map %s", report_rules_map)

            now = timezone.now()
            db_report_rules = [dbr['rule_id'] for dbr in db_report_values]
            for report in reports:
                # Get rule object for report
                if report['rule_id'] in report_rules_map:
                    rule = report_rules_map[report['rule_id']]
                    logger.debug(f"Using rule: {rule}")

                    # Get the impacted_date for this report rule from the DB
                    # If it exists and isn't None, use its impacted date for the new report, otherwise use now()
                    impacted_date = now
                    db_report_impacted_date = [dbr['impacted_date'] for dbr in db_report_values
                                               if dbr['rule_id'] == rule['id']]
                    if db_report_impacted_date and db_report_impacted_date[0]:
                        impacted_date = db_report_impacted_date[0]

                    created = True
                    report_obj = CurrentReport(
                        rule_id=rule['id'], upload=upload, details=report["details"],
                        host_id=inventory_uuid, account=account, org_id=org_id,
                        impacted_date=impacted_date)

                    if rule['id'] in db_report_rules:
                        created = False
                        existing_report_objs.append(report_obj)
                    else:
                        new_report_objs.append(report_obj)

                    logger.debug("%s current report object rule_id: %s, "
                                 "inventory_id: %s, account: %s, org_id: %s",
                                 "Creating" if created else "Updating", rule['rule_id'], inventory_uuid, account, org_id)
                    if kafka_settings.WEBHOOKS_TOPIC or kafka_settings.REMEDIATIONS_HOOK_TOPIC:
                        webhook_report_rule_objs.append(rule)
                else:
                    logger.debug(
                        f"Rule {report['rule_id']} not found in DB - content refresh needed!")
                    prometheus.INSIGHTS_ADVISOR_MISSING_CONTENT.inc()
            logger.debug("Final generated reports %s", new_report_objs + existing_report_objs)
            num_report_objs = len(new_report_objs) + len(existing_report_objs)

            # Bulk insert new reports
            CurrentReport.objects.bulk_create(new_report_objs)
            # Update existing reports
            for existing_report in existing_report_objs:
                CurrentReport.objects.filter(
                    rule_id=existing_report.rule_id,
                    host_id=existing_report.host_id,
                    account=existing_report.account,
                    org_id=existing_report.org_id
                ).update(
                    upload=existing_report.upload,
                    details=existing_report.details,
                    impacted_date=existing_report.impacted_date
                )
            # And (bulk) delete any db_reports that weren't in the report
            delete_db_reports = [dbr['rule__rule_id'] for dbr in db_report_values
                                 if dbr['rule__rule_id'] not in report_rule_ids]
            if delete_db_reports:
                logger.debug("Deleting current report object(s) rule_id(s): %s, "
                             "inventory_id: %s, account: %s, org_id: %s",
                             delete_db_reports, inventory_uuid, account, org_id)
                db_reports.filter(rule__rule_id__in=delete_db_reports).delete()

            # Trigger the webhook report comparisons
            # figure out which reports are NEW
            # figure out which reports are resolved
            if kafka_settings.WEBHOOKS_TOPIC or kafka_settings.REMEDIATIONS_HOOK_TOPIC:
                # Fetch some of these fields from the InventoryHost object
                # Catch errors and do not fail entire upload on this
                try:
                    report_hooks.trigger_report_hooks(
                        host_obj.inventory, webhook_report_rule_objs, db_report_values
                    )
                except:
                    logger.exception("Error sending Report Hooks",
                                     extra={'inventory_id': inventory_uuid, 'account': account, 'org_id': org_id})
                    the_error = traceback.format_exc()
                    payload_tracker.payload_status('error', the_error)

            # update prometheus stats
            prometheus.INSIGHTS_ADVISOR_SUCCESSFUL_REQUESTS.inc()

            # set thread storage values for kibana
            db_finished = time.time()
            thread_storage.set_value('db_finished', db_finished)
            thread_storage.set_value('db_elapsed', db_finished - db_started)
            payload_msg = f'Successfully logged {num_report_objs} reports.'
            payload_tracker.payload_status('success', payload_msg)
            logger.info(
                f"Logged {num_report_objs} report{'' if num_report_objs == 1 else 's'}"
                f" for system UUID (inventory ID) {inventory_uuid} in account {account} and org_id {org_id}",
                extra={'db_duration': db_finished - db_started})
    except Exception:
        log_db_failure("Failed to process upload", get_exception=True)
        return False
    return True


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
    help = "Advisor service for processing engine results, rule hits, and inventory events"

    def handle(self, *args, **options):
        """
        Run the Advisor service continuously until interrupted by SIGTERM.
        """
        # Initialize logging
        logger.info('Advisor Service starting up')

        # Log build information for Prometheus
        prometheus.ADVISOR_SERVICE_VERSION.info(build_info.get_build_info())

        # Initialize thread pool executor
        executor = BoundedExecutor(0, settings.THREAD_POOL_SIZE)
        logger.info('Started thread pool with %d workers', settings.THREAD_POOL_SIZE)

        # Start Prometheus server if enabled
        if not settings.DISABLE_PROMETHEUS:
            logger.debug('Starting Prometheus server')
            future = executor.submit(prometheus.start_prometheus)
            future.add_done_callback(on_thread_done)

        # Setup initial prometheus metrics
        prometheus.INSIGHTS_ADVISOR_STATUS.state('starting')
        prometheus.INSIGHTS_ADVISOR_UP.set(1)

        # Create Kafka dispatcher
        receiver = KafkaDispatcher()

        # Register async handlers (wrapped to use thread pool)
        receiver.register_handler(
            kafka_settings.ENGINE_RESULTS_TOPIC,
            make_async_handler(handle_engine_results, executor)
        )
        receiver.register_handler(
            kafka_settings.RULE_HITS_TOPIC,
            make_async_handler(handle_rule_hits, executor)
        )
        receiver.register_handler(
            kafka_settings.INVENTORY_TOPIC,
            make_async_handler(handle_inventory_event, executor)
        )

        # Setup signal handlers
        def terminate(signum, _):
            logger.info("Signal %d received, triggering shutdown", signum)
            receiver.quit = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)

        # Run receiver loop
        prometheus.INSIGHTS_ADVISOR_STATUS.state('running')
        receiver.receive()

        # Cleanup
        prometheus.INSIGHTS_ADVISOR_UP.set(0)
        prometheus.INSIGHTS_ADVISOR_STATUS.state('stopped')
        executor.shutdown()

        logger.info('Advisor Service shutting down')
