#!/usr/bin/env python

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

# Import system libraries
import time
import datetime
import json
import os
import signal
import traceback
import logging
from bounded_executor import BoundedExecutor

# Import app libraries
from confluent_kafka import Consumer, KafkaError
import settings
import advisor_logging
import thread_storage
import payload_tracker
import prometheus
import reports as report_hooks
import utils
import build_info

# Setup Django database models
import django
from django.utils import timezone
from django.db import OperationalError, InterfaceError, transaction
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()
import api.models as db  # noqa

# Import Kafka settings
import project_settings.kafka_settings as kafka_settings
kafka_settings.KAFKA_SETTINGS.update({'group.id': settings.GROUP_ID})

# Handle sigterms so process shuts down cleanly only after flushing messages to kafka
_sigterm_received = False

# Setup logging
advisor_logging.initialize_logging()
logger = logging.getLogger(settings.APP_NAME)

# Assign build information for Prometheus stats
prometheus.ADVISOR_SERVICE_VERSION.info(build_info.get_build_info())

# Setup initial prometheus metrics state
prometheus.INSIGHTS_ADVISOR_STATUS.state('initialized')


# Assign the sigterm handler function
def terminate(signum, frame):
    global _sigterm_received
    logger.info("SIGTERM received, triggering shutdown")
    _sigterm_received = True


signal.signal(signal.SIGTERM, terminate)

# Setup Consumer
c = Consumer(kafka_settings.KAFKA_SETTINGS)


# Debug function for kafka handlers
def print_assignment(consumer, partitions):
    logger.debug('Assignment: %s', partitions)


@prometheus.INSIGHTS_ADVISOR_SERVICE_HANDLE_ENGINE_RESULTS.time()
def handle_engine_results(engine_results):
    """
    Handle all engine results received from the shared engine instance
    This comes in on platform.engine.results
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

    def bad_payload(data, null_keys):
        payload_info = {'source': 'insights-client',
                        'request_id': data.get('request_id'),
                        'account': utils.traverse_keys(engine_results, ["input", "host", "account"]),  # This should be None if not present (aka optional)
                        'org_id': data.get('org_id'),
                        'inventory_id': data.get('inventory_uuid')}
        payload_tracker.bad_payload('insights-client', payload_info)
        missing_paths = ["/".join(key_paths[key]) for key in null_keys]
        logger.error("Key paths not found/null in engine results at paths: %s",
                     ",".join(missing_paths))
        return False

    data = {key: utils.traverse_keys(engine_results, key_path)
                 for key, key_path in key_paths.items()}
    null_keys = [key for key, val in data.items() if val is None]
    if len(null_keys):
        return bad_payload(data, null_keys)

    # get host and platform data
    try:
        engine_reports = data.get('engine_reports')
        system_data = data.get('system_data')
        platform_data = data.get('platform_data')
        request_id = data.get('request_id')
        inventory_uuid = data.get('inventory_uuid')
        account = utils.traverse_keys(engine_results, ["input", "host", "account"])  # This should be None if not present (aka optional) and will not throw an exception
        org_id = data.get('org_id')
    except Exception:
        return bad_payload(data, null_keys)

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
    try:
        db_system_type = db.SystemType.objects.filter(
            role=system_type,
            product_code=system_product
        ).first()
    except (OperationalError, InterfaceError):
        logger.error("Hit DB error fetching system type - will flush connections and retry")
        django.db.close_old_connections()
        db_system_type = db.SystemType.objects.filter(
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


@prometheus.INSIGHTS_ADVISOR_SERVICE_DB_ELAPSED.time()
def create_db_reports(
    reports, inventory_uuid, account, org_id, system_type, source,
    satellite_managed=None, satellite_id=None, branch_id=None,
):
    """
    Create all the reports
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
        host_obj = db.Host.objects.filter(inventory_id=inventory_uuid).first()

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
            if not db.Upload.objects.filter(org_id=org_id, current=True).exists():
                logger.debug(
                    "No uploads for account %s org_id %s- assuming new account, creating autoacks",
                    account, org_id
                )
                new_acks = []
                autoack_rules = db.Rule.objects.filter(
                    tags__name=settings.AUTOACK['TAG'], ack__isnull=True
                )
                for autoack_rule in autoack_rules:
                    # if not db.Ack.objects.filter(rule=autoack_rule, org_id=org_id).exists():
                    # now handled by ack__isnull above
                    new_acks.append(db.Ack(
                        rule=autoack_rule, account=account, org_id=org_id,
                        justification=settings.AUTOACK['JUSTIFICATION'],
                        created_by=settings.AUTOACK['CREATED_BY']
                    ))
                if new_acks:
                    db.Ack.objects.bulk_create(new_acks)
                    logger.debug("Created %d new acks", len(new_acks))

            host_obj = db.Host(inventory_id=inventory_uuid, account=account, org_id=org_id)
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
            db.Host.objects.select_for_update().get(inventory_id=inventory_uuid)

            # Get the current reports before we archive them
            # so that we can filter for webhooks
            db_reports = db.CurrentReport.objects.filter(
                host=inventory_uuid, org_id=org_id
            ).order_by('rule__rule_id')
            db_report_values = list(db_reports.values(
                'id', 'rule_id', 'rule__active', 'rule__total_risk',
                'rule__description', 'rule__publish_date', 'rule__rule_id',
                'rule__reboot_required', 'impacted_date'
            ).annotate(
                has_incident=db.Exists(db.Rule.objects.filter(
                    id=db.OuterRef('rule'), tags__name='incident'))
            ))
            logger.debug("Got DB reports %s", db_report_values)

            upload_source, upload_source_created = db.UploadSource.objects.get_or_create(name=source)

            if not upload_source:
                raise Exception('upload source is missing')

            # Update existing or create new upload
            upload, created = db.Upload.objects.update_or_create(
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
            report_rules = db.Rule.objects.filter(rule_id__in=report_rule_ids).values(
                'id', 'rule_id', 'active', 'total_risk', 'description',
                'publish_date', 'reboot_required'
            ).annotate(
                has_incident=db.Exists(db.Rule.objects.filter(id=db.OuterRef('id'), tags__name='incident'))
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
                    report_obj = db.CurrentReport(
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
            db.CurrentReport.objects.bulk_create(new_report_objs)
            # Update existing reports
            for existing_report in existing_report_objs:
                db.CurrentReport.objects.filter(
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


@prometheus.INSIGHTS_ADVISOR_SERVICE_RULE_HITS_ELAPSED.time()
def handle_rule_hits(rule_hits_json):
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
    try:
        system_type = db.SystemType.objects.filter(
            role=rule_hits_json['host_role'],
            product_code=rule_hits_json['host_product']
        ).first()
    except (OperationalError, InterfaceError):
        logger.error("Hit DB error fetching system type - will flush connections and retry")
        django.db.close_old_connections()
        system_type = db.SystemType.objects.filter(
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


@prometheus.INSIGHTS_ADVISOR_SERVICE_INVENTORY_EVENTS_ELAPSED.time()
def handle_inventory_event(inventory_json_msg):
    # clean any old thread cruft and start the timer
    utils.clean_threading_cruft()
    inventory_event_started = time.time()
    thread_storage.set_value('inventory_event_started', inventory_event_started)
    thread_storage.set_value('inventory_event_error', 0)

    def inventory_event_finished(error=None, log_db=False):
        inventory_event_finished = time.time()
        thread_storage.set_value('inventory_event_finished', inventory_event_finished)
        inventory_event_elapsed = inventory_event_finished - inventory_event_started
        thread_storage.set_value('inventory_event_elapsed', inventory_event_elapsed)
        if error:
            thread_storage.set_value('inventory_event_error', 1)
            thread_storage.set_value('inventory_event_error_msg', error)
        if log_db:
            inventory_json_msg['db_duration'] = inventory_event_elapsed

    def inventory_event_success(success_msg, payload_info):
        inventory_event_finished(None, True)
        logger.info(success_msg, extra=payload_info)
        payload_tracker.payload_status('success', success_msg, payload_info)

    def check_for_keys(required_keys):
        missing_keys = [key for key in required_keys if key not in inventory_json_msg]
        if missing_keys:
            inventory_event_finished('missing_keys')
            prometheus.INVENTORY_EVENT_MISSING_KEYS.inc()
            logger.error(f"Inventory event did not contain valid keys {required_keys}",
                         extra=inventory_json_msg)
            payload_tracker.bad_payload('inventory', inventory_json_msg,
                                        'Inventory event missing keys.')
            raise ValueError(f'Invalid keys. Required: {required_keys}')

    def inventory_event_error(payload_info, error_msg, last_error, last_error_msg):
        inventory_event_finished(last_error_msg)
        logger.error(error_msg, extra=inventory_json_msg)
        payload_tracker.payload_status('error', error_msg, payload_info)
        prometheus.INVENTORY_EVENT_ERROR.inc()
        raise last_error

    # determine the inventory event type
    event_type = inventory_json_msg.get('type')
    if not event_type:
        raise ValueError('Inventory event does not contain event type.')

    # handle delete events
    if event_type == 'delete':

        # check for missing payload keys and reject
        required_keys = ['id', 'org_id', 'request_id', 'type', 'timestamp']
        check_for_keys(required_keys)

        # get event information
        inventory_id = inventory_json_msg['id']
        account = inventory_json_msg.get('account')
        org_id = inventory_json_msg['org_id']
        request_id = inventory_json_msg['request_id']
        payload_info = {'request_id': request_id,
                        'inventory_id': inventory_id,
                        'account': account,
                        'org_id': org_id,
                        'source': 'inventory'}

        payload_tracker.payload_status('received',
                                       'Received DELETE event from Inventory.',
                                       payload_info)
        logger.info("Received DELETE event from Inventory.",
                    extra=payload_info)

        # Delete UPLOAD records for inventory ID
        last_error = None
        last_error_msg = None
        for _ in range(0, settings.DB_RETRY_CONSTANT):
            try:
                logger.debug(f"Setting uploads for {inventory_id} as non-current",
                             extra=inventory_json_msg)
                db.Upload.objects.filter(host_id=inventory_id,
                                         org_id=org_id, current=True).delete()
                break
            except (OperationalError, InterfaceError) as e:
                last_error = e
                last_error_msg = traceback.format_exc()
                logger.error("Hit DB error setting upload to non-current - "
                             "will flush connections and retry", extra=inventory_json_msg)
                django.db.close_old_connections()
        else:
            error_msg = f"Error setting uploads to non-current for {inventory_id}: {last_error_msg}"
            inventory_event_error(payload_info, error_msg, last_error, last_error_msg)

        # current reports are deleted
        last_error = None
        last_error_msg = None
        for _ in range(0, settings.DB_RETRY_CONSTANT):
            try:
                logger.debug(f"Deleting current reports for {inventory_id}",
                             extra=inventory_json_msg)
                db.CurrentReport.objects.filter(host=inventory_id, org_id=org_id).delete()
                break
            except (OperationalError, InterfaceError) as e:
                last_error = e
                last_error_msg = traceback.format_exc()
                logger.error("Hit DB error deleting current reports - "
                             "will flush connections and retry", extra=inventory_json_msg)
                django.db.close_old_connections()
        else:
            error_msg = f"Error deleting current reports for {inventory_id}: {last_error_msg}"
            inventory_event_error(payload_info, error_msg, last_error, last_error_msg)

        # host acks are deleted
        last_error = None
        last_error_msg = None
        for _ in range(0, settings.DB_RETRY_CONSTANT):
            try:
                logger.debug(f"Deleting Host Acks for {inventory_id}",
                             extra=inventory_json_msg)
                db.HostAck.objects.filter(host_id=inventory_id, org_id=org_id).delete()
                break
            except (OperationalError, InterfaceError) as e:
                last_error = e
                last_error_msg = traceback.format_exc()
                logger.error("Hit DB error deleting host acks - "
                             "will flush connections and retry", extra=inventory_json_msg)
                django.db.close_old_connections()
        else:
            error_msg = f"Error deleting host acks for {inventory_id}: {last_error_msg}"
            inventory_event_error(payload_info, error_msg, last_error, last_error_msg)

        # Set finished metrics
        success_msg = f"Succesfully DELETED records for {inventory_id} in account {account} org_id {org_id}."
        inventory_event_success(success_msg, payload_info)

    # We currently do nothing for updated events
    # Leaving as a placeholder so we know 'updated' events do still come in
    # if event_type == 'updated':


def start():
    # Log the startup settings
    logger.debug("Starting Advisor Service using the following settings:")
    for key in dir(settings):
        logger.debug('%s: %s', key, getattr(settings, key))

    # Log the startup environment
    logger.debug("Starting Advisor Service using the following environment:")
    for key, val in globals().items():
        logger.debug('%s(%s): %s', key, type(key), val)

    # Start thread pool executor
    logger.debug("Starting thread pool executor.")
    executor = BoundedExecutor(0, int(settings.THREAD_POOL_SIZE))

    # Start prometheus
    if not settings.DISABLE_PROMETHEUS:
        logger.debug('Starting Insights Advisor Prometheus Server')
        submit_to_executor(executor, prometheus.start_prometheus)

    # Setup Prometheus stats
    logger.debug("Setting advisor status to 'starting'")
    prometheus.INSIGHTS_ADVISOR_STATUS.state('starting')

    # Subscribe to our topics
    topic_subscriptions = [kafka_settings.ENGINE_RESULTS_TOPIC,
                           kafka_settings.INVENTORY_EVENTS_TOPIC,
                           kafka_settings.RULE_HITS_TOPIC]
    logger.debug("Subscribing to Kafka topics %s" %
        (topic_subscriptions))
    c.subscribe(topic_subscriptions, on_assign=print_assignment)
    logger.debug("Subscribed to topics.")

    # Set some Prometheus stats
    prometheus.INSIGHTS_ADVISOR_UP.set(1)

    # Poll the topics we are consuming from
    logger.debug("Begin polling Kafka.")
    while not _sigterm_received:
        prometheus.INSIGHTS_ADVISOR_STATUS.state('running')
        msg = c.poll(1.0)

        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            else:
                logger.error(msg.error())
                continue

        logger.debug(
            'Received Platform Kafka message at %s from topic %s: %s',
            datetime.datetime.now().isoformat(), msg.topic(), msg.value()
        )

        # Pull engine results from shared engine topic
        if msg.topic() == kafka_settings.ENGINE_RESULTS_TOPIC:
            json_msg = None
            prometheus.INSIGHTS_ADVISOR_TOTAL_REQUESTS.inc()

            try:
                json_msg = json.loads(msg.value().decode('utf-8').strip('"'))
            except Exception:
                payload_tracker.bad_payload('insights-client', msg.value())
                logger.exception("Malformed JSON error for engine results.")
                continue

            if json_msg:
                submit_to_executor(executor, handle_engine_results, json_msg)

        # Request third party rule hit
        if msg.topic() == kafka_settings.RULE_HITS_TOPIC:
            json_msg = None
            prometheus.THIRD_PARTY_RULE_HIT_REQUEST_RECEIVED.inc()
            logger.debug("Received third party rule hits request.")

            try:
                json_msg = json.loads(msg.value().decode('utf-8').strip('"'))
            except Exception:
                payload_tracker.bad_payload(msg.topic(), msg.value())
                logger.exception("Malformed JSON error for third party rule hit.")

            if json_msg:
                payload_info = {'request_id': 'third-party'}
                for key in ['inventory_id', 'source', 'account', 'org_id']:
                    if key in json_msg:
                        payload_info[key] = json_msg[key]
                payload_tracker.payload_status('processing',
                               'Submitting to pool for rule hit analysis.',
                               payload_info)
                submit_to_executor(executor, handle_rule_hits, json_msg)

        # Listen to inventory events
        # DELETE any associated records for a system
        if msg.topic() == kafka_settings.INVENTORY_EVENTS_TOPIC:
            json_msg = None
            prometheus.INVENTORY_EVENTS_TOPIC_RECEIVED.inc()
            logger.debug("Received inventory event request")

            try:
                json_msg = json.loads(msg.value().decode('utf-8').strip('"'))
            except Exception:
                payload_tracker.bad_payload(msg.topic(), msg.value())
                logger.exception("Malformed JSON error for inventory event.")

            if json_msg:
                submit_to_executor(executor, handle_inventory_event, json_msg)

    # Set some Prometheus stats
    prometheus.INSIGHTS_ADVISOR_UP.set(0)
    prometheus.INSIGHTS_ADVISOR_STATUS.state('stopped')

    # Shut down executor
    executor.shutdown()
    # Close consumer connection
    c.close()


def submit_to_executor(executor, fn, *args, **kwargs):
    future = executor.submit(fn, *args, **kwargs)
    logger.debug("Submitted to executor, future: %s", future)
    future.add_done_callback(on_thread_done)


def on_thread_done(future):
    try:
        future.result()
    except Exception:
        logger.exception("Future %s hit exception", future)


if __name__ == "__main__":
    logger.info('Starting Insights Advisor Service')
    start()
