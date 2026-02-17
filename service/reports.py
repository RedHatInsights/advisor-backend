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

import os
import json
import datetime
import traceback
import logging
import settings
import prometheus
import payload_tracker
from confluent_kafka import Producer

# Import Kafka stuff
from project_settings.settings import (
    REMEDIATIONS_HOOK_TOPIC, WEBHOOKS_TOPIC, KAFKA_SETTINGS
)

# Setup Django
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()
import api.models as db  # noqa

NEW_REPORT_EVENT = "new-recommendation"
RESOLVED_REPORT_EVENT = "resolved-recommendation"

ADVISOR_URL_PREFIX = os.environ.get(
    'ADVISOR_URL_PREFIX', 'https://console.redhat.com/insights/advisor/recommendations'
)

logger = logging.getLogger(settings.APP_NAME)

p = None
if REMEDIATIONS_HOOK_TOPIC or WEBHOOKS_TOPIC:
    topics = ', '.join([t for t in [REMEDIATIONS_HOOK_TOPIC, WEBHOOKS_TOPIC] if t])
    logger.debug(f"Creating producer for topics: {topics}")
    p = Producer(KAFKA_SETTINGS)


def report_delivery_callback(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        logger.error('Webhook event message delivery failed: {}'.format(err))
    else:
        logger.debug('Webhook event message delivered to {} [{}]'.format(
            msg.topic(), msg.partition()))


def send_webhook_event(event_msg):
    if WEBHOOKS_TOPIC:
        p.poll(0)
        logger.debug("Producing webhook event msg: %s", event_msg)
        send_msg = json.dumps(event_msg).encode('utf-8')
        p.produce(WEBHOOKS_TOPIC, send_msg, callback=report_delivery_callback)
        p.flush()


def send_remediations_event(event_key, event_value):
    if REMEDIATIONS_HOOK_TOPIC:
        p.poll(0)
        logger.debug("Producing remediations event msg key %s and value %s", event_key, event_value)
        send_value = json.dumps(event_value).encode('utf-8')
        p.produce(REMEDIATIONS_HOOK_TOPIC, key=event_key, value=send_value,
                  callback=report_delivery_callback)
        p.flush()


def new_webhook_message(host_obj, event_type):
    inventory_uuid = str(host_obj.id)
    account = host_obj.account
    org_id = host_obj.org_id
    return {
        'bundle': 'rhel',
        'application': 'advisor',
        'event_type': event_type,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'account_id': account,
        'org_id': org_id,
        'context': json.dumps({
            'inventory_id': inventory_uuid,
            'hostname': host_obj.display_name,
            'display_name': host_obj.display_name,
            'rhel_version': host_obj.rhel_version,
            'tags': host_obj.tags
        }),
    }


def make_event_struct(report, field_prefix=''):
    if field_prefix != '':
        field_prefix = field_prefix + '__'
    event_payload = {
        'rule_id': report[field_prefix + 'rule_id'],
        'rule_description': report[field_prefix + 'description'],
        'total_risk': str(report[field_prefix + 'total_risk']),
        'publish_date': report[field_prefix + 'publish_date'].isoformat(),
        'rule_url': '{prefix}/{rule}/'.format(
            prefix=ADVISOR_URL_PREFIX, rule=report[field_prefix + 'rule_id'],
        ),
        'reboot_required': report[field_prefix + 'reboot_required'],
        'has_incident': report['has_incident'],
    }
    event = {
        'metadata': {},
        'payload': json.dumps(event_payload),
    }
    return event


@prometheus.INSIGHTS_ADVISOR_SERVICE_WEBHOOK_EVENTS_ELAPSED.time()
def trigger_report_hooks(inv_host_obj, report_list, db_reports):
    """
    Here we want to identify NEW reports as well as RESOLVED reports
    This will be based off of the new report list
    Whenever a NEW or RESOLVED report is found, trigger a webhook

    Cross reference report_list with reports retrieved from DB
    Want to identify new ones:
        To determine a New Report,
        Get a list of all the previous reports that are "current" for the host,
        if the old reports do not contain a report with a rule ID from the reports
        just generated then it is new
    Want to identify resolved ones:
        To determine a Resolved Report,
        Get a list of all the previous reports that are "current" for the host,
        if the old reports contain a report with a rule ID that is NOT in the reports
        just generated then it is resolved
    NOTE: "source" is relevant here. An aiops upload cannot resolve all the reports
            from an insights upload
    """
    inventory_uuid = str(inv_host_obj.id)
    account = inv_host_obj.account
    org_id = inv_host_obj.org_id
    extra = {'inventory_id': inventory_uuid, 'account': account, 'org_id': org_id}  # extra info for payload tracker
    acks_hostacks_query = db.Ack.objects.filter(account=account).values('rule_id').union(  # filter on org_id after full adoption
                            db.HostAck.objects.filter(account=account, host=inventory_uuid)  # filter on org_id after full adoption
                            .order_by().values('rule_id'))
    acks_hostacks_ids = [x['rule_id'] for x in acks_hostacks_query]
    report_ids = [x['id'] for x in report_list]
    db_rule_ids = [x['rule_id'] for x in db_reports]
    new_report_list = list(
        filter(
            lambda x: x['id'] not in db_rule_ids and x['active'] and x['id'] not in acks_hostacks_ids,
            report_list))

    def resolved_report_list_fn(x):
        return x['rule_id'] not in report_ids and x['rule__active'] and x['rule_id'] not in acks_hostacks_ids
    resolved_report_list = list(
        filter(
            lambda x: resolved_report_list_fn(x),
            db_reports))

    # send webhooks for new reports
    if len(new_report_list) > 0:
        webhook_msg = new_webhook_message(inv_host_obj, NEW_REPORT_EVENT)
        webhook_msg['events'] = [
            make_event_struct(new_report)
            for new_report in new_report_list
        ]
        try:
            send_webhook_event(webhook_msg)
        except:
            logger.exception("Error sending New Report Webhook",
                             extra={'inventory_id': inventory_uuid, 'account': account, 'org_id': org_id})
            the_error = traceback.format_exc()
            payload_tracker.payload_status('error', the_error, extra)

    # send webhooks for resolved reports
    if len(resolved_report_list) > 0:
        webhook_msg = new_webhook_message(inv_host_obj, RESOLVED_REPORT_EVENT)
        webhook_msg['events'] = [
            make_event_struct(resolved_report, field_prefix='rule')
            for resolved_report in resolved_report_list
        ]

        # Catch webhooks errors, don't want to fail the entire upload on these
        try:
            send_webhook_event(webhook_msg)
        except:
            logger.exception("Error sending Resolved Webhook",
                         extra={'inventory_id': inventory_uuid, 'account': account, 'org_id': org_id})
            the_error = traceback.format_exc()
            payload_tracker.payload_status('error', the_error, extra)

    # send reports to remediations topic
    if len(report_list) > 0:
        msg_value = {
            'host_id': inventory_uuid,
            'issues': ['advisor:' + report['rule_id'] for report in report_list]
        }
        # catch remediations events, don't want to fail the entire upload on these
        try:
            send_remediations_event(inventory_uuid, msg_value)
        except:
            logger.exception("Error sending Remediations",
                             extra={'inventory_id': inventory_uuid, 'account': account, 'org_id': org_id})
            the_error = traceback.format_exc()
            payload_tracker.payload_status('error', the_error, extra)
