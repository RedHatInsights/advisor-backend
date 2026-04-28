#!/usr/bin/env python

# Copyright 2016-2026 the Advisor Backend team at Red Hat.
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
import datetime

import settings
from confluent_kafka import Producer

from project_settings.settings import INVENTORY_VIEW_TOPIC, KAFKA_SETTINGS

logger = logging.getLogger(settings.APP_NAME)

INVENTORY_VIEW_APPLICATION = "advisor"

# Setup producer to communicate with inventory view topic
p = None
if INVENTORY_VIEW_TOPIC:
    logger.debug(
        "Creating producer for inventory view topic %s.",
        INVENTORY_VIEW_TOPIC,
    )
    p = Producer(KAFKA_SETTINGS)
else:
    logger.warning("No inventory view topic configured, skipping inventory view events.")


def inventory_view_delivery_report(err, msg):
    """Called once for each message produced to indicate delivery result.
    Triggered by poll() or flush()."""
    if err is not None:
        logger.error(
            "Inventory view message delivery failed: %s",
            err,
        )
    else:
        logger.debug(
            "Inventory view message delivered to %s [%s]",
            msg.topic(),
            msg.partition(),
        )


def send_inventory_view_event(event_data):
    """Send an inventory view event to the INVENTORY_VIEW_TOPIC.

    Args:
        event_data: dict with the payload data.
    """
    if p is None or not INVENTORY_VIEW_TOPIC:
        return
    try:
        headers = [
            ("application", bytes(INVENTORY_VIEW_APPLICATION, "utf-8")),
            ("request_id", bytes(event_data["request_id"], "utf-8")),
        ]
        payload = {
            "org_id": event_data["org_id"],
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "hosts": [
                {
                    "id": event_data["host_id"],
                    "data": event_data["data"],
                }
            ],
        }

        payload_str = json.dumps(payload).encode("utf-8")
        logger.debug("Sending inventory view message: %s", payload_str)
        p.poll(0)
        p.produce(
            topic=INVENTORY_VIEW_TOPIC,
            value=payload_str,
            headers=headers,
            callback=inventory_view_delivery_report,
        )
        p.flush()
    except Exception:
        logger.exception("Hit exception sending inventory view event.")


_rule_risks = [None, 'low', 'moderate', 'important', 'critical']


def update_inventory_view_counts(counts, rule):
    """Update the inventory view counts for the given rule.

    Args:
        counts: dict with the counts data.
        rule: dict with the rule data.
    """
    if rule.get('has_incident'):
        counts['incidents'] += 1

    severity = _rule_risks[rule.get('total_risk')]
    if severity:
        counts[severity] += 1
