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
import settings
import traceback
import datetime
import thread_storage
import prometheus
from confluent_kafka import Producer

# Import kafka stuff
from project_settings.settings import PAYLOAD_TRACKER_TOPIC, KAFKA_SETTINGS

logger = logging.getLogger(settings.APP_NAME)

# Setup producer to communicate with payload tracker
p = None
if PAYLOAD_TRACKER_TOPIC:
    logger.debug(f"Creating producer for payload tracker topic {PAYLOAD_TRACKER_TOPIC}.")
    p = Producer(KAFKA_SETTINGS)


def payload_delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        prometheus.PAYLOAD_TRACKER_DELIVERY_ERRORS.inc()
        logger.error('Payload tracker message delivery failed: {}'.format(err))
    else:
        logger.debug('Payload tracker message delivered to {} [{}]'.format(
                        msg.topic(), msg.partition()))


def bad_payload(source, payload_message, optional_status_msg=None):
    if p is not None and PAYLOAD_TRACKER_TOPIC:
        try:
            json_msg = json.loads(payload_message.decode('unicode_escape').strip('"'))
            if json_msg.get('request_id'):
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
                    'account': json_msg.get('account'),
                    'org_id': json_msg.get('org_id'),
                    'inventory_id': json_msg.get('id'),
                    'request_id': json_msg.get('request_id'),
                    'status_msg': status_msg,
                    'date': str(current_time)
                })
                logger.debug(f"Sending payload status message {payload_msg.encode('utf-8')}")
                p.produce(PAYLOAD_TRACKER_TOPIC, payload_msg.encode('utf-8'),
                            callback=payload_delivery_report)
                p.flush()
        except Exception:
            logger.exception("Hit exception sending bad payload tracker status.")


def payload_status(payload_status, payload_status_msg, payload_info=None):
    if p is not None and PAYLOAD_TRACKER_TOPIC:
        payload_msg = {
            'service': settings.APP_NAME,
            'status': payload_status,
            'status_msg': payload_status_msg
        }

        if payload_info:
            payload_msg.update(payload_info)
        else:
            check_thread_keys = ['request_id', 'inventory_id', 'system_id', 'source', 'account', 'org_id']
            for thread_key in check_thread_keys:
                if thread_storage.get_value(thread_key):
                    payload_msg[thread_key] = thread_storage.get_value(thread_key)

        current_time = datetime.datetime.now().isoformat()
        payload_msg['date'] = str(current_time)
        payload_msg = json.dumps(payload_msg)
        logger.debug(f"Sending payload status message {payload_msg.encode('utf-8')}")
        try:
            p.produce(PAYLOAD_TRACKER_TOPIC, payload_msg.encode('utf-8'),
                        callback=payload_delivery_report)
            p.flush()
        except Exception:
            logger.exception("Hit exception sending payload tracker status.")
