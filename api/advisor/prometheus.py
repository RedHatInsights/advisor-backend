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

from django.conf import settings
from prometheus_client import start_http_server, Counter, Enum, Gauge, Histogram, Info

# Prometheus configuration
INSIGHTS_ADVISOR_UP = Gauge('insights_advisor_service_up', 'Insights Advisor Service Up')
INSIGHTS_ADVISOR_STATUS = Enum(
    'insights_advisor_service_status',
    'Current Status of Advisor Service',
    states=['initialized', 'starting', 'running', 'stopped']
)
INSIGHTS_ADVISOR_TOTAL_REQUESTS = Counter(
    'insights_advisor_service_total_requests',
    'Total Number of Received Requests'
)
INSIGHTS_ADVISOR_SUCCESSFUL_REQUESTS = Counter(
    'insights_advisor_service_successful_requests',
    'Total Number of Successful Requests'
)
INSIGHTS_ADVISOR_MISSING_CONTENT = Counter(
    'insights_advisor_missing_content',
    'Number of reports we tried processing but failed to find rule content for'
)
INSIGHTS_ADVISOR_DB_ERRORS = Counter(
    'insights_advisor_db_errors',
    'Total number of DB errors that have occurred'
)
INSIGHTS_ADVISOR_SERVICE_DB_ELAPSED = Histogram(
    'insights_advisor_service_db_elapsed',
    'Total time spent processing db calls for an archive'
)
THIRD_PARTY_RULE_HIT_REQUEST_RECEIVED = Counter(
    'insights_advisor_service_third_party_rule_hit_request_received',
    'A request that is received for a rule hit from a third party'
)
INSIGHTS_ADVISOR_SERVICE_HANDLE_ENGINE_RESULTS = Histogram(
    'insights_advisor_service_handle_engine_results',
    'Total time spent processing results received from the shared engine'
)
INSIGHTS_ADVISOR_SERVICE_RULE_HITS_ELAPSED = Histogram(
    'insights_advisor_service_rule_hits_elapsed',
    'Total time spent processing third party rule hits'
)
INSIGHTS_ADVISOR_SERVICE_WEBHOOK_EVENTS_ELAPSED = Histogram(
    'insights_advisor_service_webhook_events_elapsed',
    'Total time spent processing webhook events'
)
THIRD_PARTY_RULE_HIT_MISSING_KEYS = Counter(
    'insights_advisor_service_rule_hits_missing_keys',
    'Counter for how many rule hit requests are malformed, missing keys'
)
INVENTORY_EVENTS_TOPIC_RECEIVED = Counter(
    'insights_advisor_service_inventory_event_received',
    'A request that is received from the inventory service'
)
INSIGHTS_ADVISOR_SERVICE_INVENTORY_EVENTS_ELAPSED = Histogram(
    'insights_advisor_service_inventory_events_elapsed',
    'Total time spent processing an inventory event'
)

INVENTORY_EVENT_MISSING_KEYS = Counter(
    'insights_advisor_service_inventory_event_missing_keys',
    'Counter for how many inventory event requests are malformed, missing keys'
)
INVENTORY_EVENT_ERROR = Counter(
    'insights_advisor_service_inventory_event_error',
    'Counter for how many inventory events errored'
)
PAYLOAD_TRACKER_DELIVERY_ERRORS = Counter(
    'insights_advisor_service_payload_tracker_delivery_errors',
    'Counter for how many payload tracker messsages failed delivery'
)
ADVISOR_SERVICE_VERSION = Info(
    'insights_advisor_service_version',
    'Release and versioning information'
)


def start_prometheus():
    start_http_server(settings.PROMETHEUS_PORT)
