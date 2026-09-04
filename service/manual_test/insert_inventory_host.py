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

"""
Utility to insert a host dict into the local Advisor inventory tables.

Usage from another script:
    from insert_inventory_host import insert_host
    insert_host(host_data_dict)

Or standalone:
    python insert_inventory_host.py fake_engine_result_rhel.json

The host dict should match the shape found in engine result JSON files
(i.e. input.host) or inventory messages (i.e. host).
"""

import json
import os
import sys
from datetime import timedelta

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project_settings.settings")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'api', 'advisor'))
django.setup()

from django.utils import timezone

from api.management.commands.advisor_inventory_service import (
    NIL_UUID,
    ParsedInventoryHost,
    bulk_upsert_hosts,
    parse_created_event,
)


def insert_host(host_data):
    """Insert or update a host in the local Advisor inventory tables.

    Args:
        host_data: Engine-result or Inventory host data.
    """
    required_fields = ('id', 'org_id', 'display_name', 'insights_id')
    missing_fields = [field for field in required_fields if not host_data.get(field)]
    if missing_fields:
        raise ValueError(
            f"Host data is missing required identity field(s): {', '.join(missing_fields)}"
        )
    if str(host_data['insights_id']).lower() == NIL_UUID:
        raise ValueError("Host data insights_id must not be the nil UUID")

    now = timezone.now()
    now_string = now.isoformat()
    stale_timestamp = (now + timedelta(days=1)).isoformat()
    stale_warning_timestamp = (now + timedelta(days=7)).isoformat()
    culled_timestamp = (now + timedelta(days=14)).isoformat()

    normalized_host = dict(host_data)
    normalized_host.update({
        'created': host_data.get('created') or now_string,
        'updated': host_data.get('updated') or now_string,
        'last_check_in': host_data.get('last_check_in') or now_string,
        'stale_timestamp': stale_timestamp,
        'stale_warning_timestamp': stale_warning_timestamp,
        'culled_timestamp': culled_timestamp,
        'reporter': host_data.get('reporter') or 'puptoo',
        'tags': host_data.get('tags') or [],
        'groups': host_data.get('groups') or [],
        'system_profile': host_data.get('system_profile') or {},
    })

    per_reporter_staleness = dict(host_data.get('per_reporter_staleness') or {})
    puptoo_staleness = dict(per_reporter_staleness.get('puptoo') or {})
    puptoo_staleness.update({
        'last_check_in': normalized_host['last_check_in'],
        'stale_timestamp': stale_timestamp,
        'stale_warning_timestamp': stale_warning_timestamp,
        'culled_timestamp': culled_timestamp,
    })
    per_reporter_staleness['puptoo'] = puptoo_staleness
    normalized_host['per_reporter_staleness'] = per_reporter_staleness

    event = {
        'type': 'created',
        'metadata': {'request_id': 'manual-inventory-host-insert'},
        'host': normalized_host,
    }
    parsed_host = parse_created_event(event)
    if not isinstance(parsed_host, ParsedInventoryHost):
        raise ValueError("Host data could not be normalized into a valid Inventory created event")

    bulk_upsert_hosts([parsed_host])
    print(f"Host {host_data['id']} inserted into the local Advisor inventory tables")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python insert_inventory_host.py <engine_result.json>')
        sys.exit(1)

    this_dir = os.path.dirname(os.path.realpath(__file__))
    filepath = os.path.join(this_dir, os.path.basename(sys.argv[1]))

    with open(filepath) as f:
        data = json.load(f)

    # Support both engine result format (input.host) and inventory format (host)
    if 'input' in data and 'host' in data['input']:
        host = data['input']['host']
    elif 'host' in data:
        host = data['host']
    else:
        print('Could not find host data in JSON file')
        sys.exit(1)

    try:
        insert_host(host)
    except ValueError as error:
        print(f'Could not insert host: {error}', file=sys.stderr)
        sys.exit(1)
