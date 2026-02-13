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

from bounded_executor import BoundedExecutor
import datetime
import json
import os
import signal
import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from kafka_utils import producer, report_delivery_callback

from advisor_logging import logger
from api.models import (
    CurrentReport, Rule, RuleCategory, RuleImpact, Ruleset, SystemType, Upload,
)


settings.KAFKA_SETTINGS.update({'group.id': settings.SERVICE_GROUP_ID})

# Handle sigterms so process shuts down cleanly only after flushing messages to kafka
_sigterm_received = False

# Setup logging
advisor_logging.initialize_logging()
logger = logging.getLogger(settings.SERVICE_APP_NAME)

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


# From service/utils.py
def traverse_keys(d: dict, keys: List[str], default=None):
    """
    Allows you to look up a 'path' of keys in nested dicts without knowing
    whether each key exists
    """
    key = keys.pop(0)
    item = d.get(key, default)
    if len(keys) == 0:
        return item
    return traverse_keys(item, keys, default)


def payload_tracker_update(
    org_id: str, request_id: str, system_id: str, inventory_id: str,
    status: str, status_msg: str
):
    """
    Send a payload tracker update via Kafka.

    Status is one of ('received', 'processing', 'invalid', 'success', 'error').
    'received', and one of 'success' or 'error', are required.
    Message shoud contain:
    {
        'service': 'The services name processing the payload', (required)
        # 'source': 'This is indicative of a third party rule hit analysis. (not Insights Client)',
        # 'account': 'The RH associated account',
        'org_id': 'The RH associated org id', (required)
        'request_id': 'The ID of the payload (This should be a UUID)', (required)
        'inventory_id': 'The ID of the entity in terms of the inventory (This should be a UUID)',
        'system_id': 'The ID of the entity in terms of the actual system (This should be a UUID)',
        'status': 'received|processing|success|error|etc', (required)
        'status_msg': 'Information relating to the above status, should more verbiage be needed (in the event of an error)',
        'date': 'Timestamp for the message relating to the status above. (This should be in RFC3339 UTC format: "2022-03-17T16:56:10Z")' (required)
    }
    Project at https://github.com/RedHatInsights/payload-tracker-go/tree/master
    """
    payload: dict[str, str] = {
        'service': settings.APP_NAME,
        'org_id': org_id,
        'request_id': request_id,
        'inventory_id': inventory_id,
        'system_id': system_id,
        'status': status,
        'status_msg': status_msg,
        'date': datetime.datetime.now(datetime.timezone.utc).isoformat()
        # or timezone.now().isoformat() ?
    }
    payload_msg = json.dumps(payload).encode('utf-8')
    producer.produce(
        settings.PAYLOAD_TRACKER_TOPIC, payload_msg,
        callback=report_delivery_callback
    )


def update_host(payload: dict) -> Host:
    """
    Updates the host information in the database from the message payload.

    Returns a Host object.
    """
    # Implement the logic to update the host information here
    pass


def handle_engine_results(topic: str, message: dict):
    """
    The Insights Engine sends us results of rule processing on a system, which
    we turn into an Upload and zero or more CurrentReports.  Each CurrentReport
    tries to find the previous CurrentReport for the same rule and system, in
    order to track the time at which this report first impacted the system.

    This function makes sure that the data we need later is provided, and then
    hands off to
    """
    engine_results_started = time.time()

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
                        'org_id': data.get('org_id'),
                        'inventory_id': data.get('inventory_uuid')}
        payload_tracker.bad_payload('insights-client', payload_info)
        missing_paths = ["/".join(key_paths[key]) for key in null_keys]
        _ = logger.error(
            "Key paths not found/null in engine results at paths: %s",
            ",".join(missing_paths)
        )
        return False

    data = {
        key: traverse_keys(engine_results, key_path)
        for key, key_path in key_paths.items()
    }
    null_keys = [key for key, val in data.items() if val is None]
    if null_keys:
        return bad_payload(data, null_keys)
    engine_reports = data.get('engine_reports')
    system_data = data.get('system_data')
    platform_data = data.get('platform_data')
    request_id = data.get('request_id')
    inventory_uuid = data.get('inventory_uuid')
    org_id = data.get('org_id')

    payload_tracker.payload_status('received', 'Processing engine results')
    _ = logger.info(
        "Processing engine results for Inventory ID %s on org_id %s",
        inventory_uuid, accountorg_id
    )

    # Proposal here: divide this into functions:
    # - host / system updates - returns a Host?
    # - upload / report updates

    # system type and produce code information
    system_type = system_data.get('type')
    system_product = system_data.get('product')
    try:
        db_system_type = SystemType.objects.get(
            role=system_type,
            product_code=system_product
        )
    except SystemType.DoesNotExist:
        # thread_storage.set_value('engine_results_error', 1)
        # thread_storage.set_value('engine_results_error_msg', 'missing system_type')
        engine_results_finished = time.time()
        engine_results_elapsed = engine_results_finished - engine_results_started
        # thread_storage.set_value('engine_results_finished', engine_results_finished)
        # thread_storage.set_value('engine_results_elapsed', engine_results_elapsed)
        _ = logger.error(
            "Unable to get system type %s / %s from DB - load fixtures!",
            system_product, system_type
        )
        payload_tracker.payload_status('invalid', 'Invalid system type.')
        return False




def handle_inventory_event(topic, message):
def handle_rule_hits(topic, message):


class Command(BaseCommand):
    help = "Updates the job and executed task states based on Kafka messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Tasks service starting up')

        receiver = KafkaDispatcher()

        receiver.register_handler(settings.ENGINE_RESULTS_TOPIC, handle_engine_results)
        receiver.register_handler(settings.INVENTORY_EVENTS_TOPIC, handle_inventory_event)
        receiver.register_handler(settings.RULE_HITS_TOPIC, handle_rule_hits)

        def terminate(signum, frame):
            logger.info("SIGTERM received, triggering shutdown")
            receiver.quit = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Tasks service shutting down')
