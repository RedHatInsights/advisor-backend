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

import json
import logging
from django.conf import settings
import traceback
import datetime
import thread_storage
from typing import Optional
import prometheus

# Import kafka stuff
import project_settings.kafka_settings as kafka_settings

logger = logging.getLogger(settings.APP_NAME)

# Setup producer to communicate with payload tracker - use DummyProducer in tests
_producer = None
if kafka_settings.PAYLOAD_TRACKER_TOPIC:
    logger.debug(f"Creating producer for payload tracker topic {kafka_settings.PAYLOAD_TRACKER_TOPIC}.")
    if settings.TESTING:
        from kafka_utils import DummyProducer
        _producer = DummyProducer(kafka_settings.KAFKA_SETTINGS)
    else:
        from confluent_kafka import Producer
        _producer = Producer(kafka_settings.KAFKA_SETTINGS)


def payload_delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        prometheus.PAYLOAD_TRACKER_DELIVERY_ERRORS.inc()
        logger.error('Payload tracker message delivery failed: {}'.format(err))
    else:
        logger.debug('Payload tracker message delivered to {} [{}]'.format(
                        msg.topic(), msg.partition()))


def bad_payload(
    source: str, payload_data: dict[str, str],
    optional_status_msg: Optional[str] = None
):
    """
    Send a message about a bad payload to the payload tracker.
    """
    if _producer is None or not kafka_settings.PAYLOAD_TRACKER_TOPIC:
        return
    try:
        if payload_data.get('request_id'):
            if optional_status_msg:
                status_msg = optional_status_msg
            else:
                the_error = traceback.format_exc()
                status_msg = f"Malformed JSON error: Error: {the_error}"
            current_time = datetime.datetime.now().isoformat()
            payload_msg = json.dumps({
                'status': 'error',
                'service': settings.APP_NAME,
                'source': source,
                'account': payload_data.get('account'),
                'org_id': payload_data.get('org_id'),
                'inventory_id': payload_data.get('id'),
                'request_id': payload_data.get('request_id'),
                'status_msg': status_msg,
                'date': str(current_time)
            })
            logger.debug(f"Sending payload status message {payload_msg.encode('utf-8')}")
            _producer.produce(kafka_settings.PAYLOAD_TRACKER_TOPIC, payload_msg.encode('utf-8'),
                                callback=payload_delivery_report)
            _producer.flush()
    except Exception:
        logger.exception("Hit exception sending bad payload tracker status.")


def payload_status(payload_status, payload_status_msg, payload_info=None):
    """
    Update payload tracker with the status of this payload.
    """
    if _producer is None or not kafka_settings.PAYLOAD_TRACKER_TOPIC:
        return
    payload_msg = {
        'service': settings.APP_NAME,
        'status': payload_status,
        'status_msg': payload_status_msg
    }

    if payload_info:
        payload_msg.update(payload_info)
    else:
        check_thread_keys = [
            'request_id', 'inventory_id', 'system_id', 'source', 'account', 'org_id'
        ]
        for thread_key in check_thread_keys:
            if thread_storage.get_value(thread_key):
                payload_msg[thread_key] = thread_storage.get_value(thread_key)

    current_time = datetime.datetime.now().isoformat()
    payload_msg['date'] = str(current_time)
    payload_msg = json.dumps(payload_msg)
    logger.debug(f"Sending payload status message {payload_msg.encode('utf-8')}")
    try:
        _producer.produce(kafka_settings.PAYLOAD_TRACKER_TOPIC, payload_msg.encode('utf-8'),
                            callback=payload_delivery_report)
        _producer.flush()
    except Exception:
        logger.exception("Hit exception sending payload tracker status.")
