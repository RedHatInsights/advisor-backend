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

from prometheus_client import Counter

# Prometheus configuration
INVENTORY_EVENT_MISSING_KEYS = Counter(
    'insights_advisor_api_inventory_event_missing_keys',
    'Counter for how many inventory event requests are malformed, missing keys'
)
INVENTORY_EVENT_MALFORMED = Counter(
    'insights_advisor_api_inventory_event_malformed',
    'Counter for inventory events that failed validation or parsing'
)
INVENTORY_EVENT_INSIGHTS_ONLY_FILTERED = Counter(
    'insights_advisor_api_inventory_event_insights_only_filtered',
    'Counter for inventory events filtered out due to missing or nil insights_id'
)
INVENTORY_HOST_UPSERTED = Counter(
    'insights_advisor_api_inventory_host_upserted',
    'Count how many inventory hosts were upserted'
)
INVENTORY_HOST_DELETED = Counter(
    'insights_advisor_api_inventory_host_deleted',
    'Count how many inventory hosts were deleted'
)
INVENTORY_HOST_DELETE_MISSING = Counter(
    'insights_advisor_api_inventory_host_delete_missing',
    'Count how many inventory host delete events had no matching record in the DB'
)
