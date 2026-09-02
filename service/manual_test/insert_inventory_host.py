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
Utility to upsert a host dict into AdvisorInventoryHost.

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
from datetime import datetime, timezone

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project_settings.settings")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'api', 'advisor'))
django.setup()

from django.utils.dateparse import parse_datetime  # noqa: E402
from api.models import AdvisorInventoryHost  # noqa: E402


def _parse_dt(value, default):
    if value is None:
        return default
    if isinstance(value, datetime):
        return value
    parsed = parse_datetime(value)
    return parsed if parsed is not None else default


def insert_host(host_data):
    """Insert or update a host in advisor_inventory_host.

    Args:
        host_data: dict with at least 'id', 'org_id', and 'display_name'.
    """
    now = datetime.now(timezone.utc)
    sp = host_data.get('system_profile') or {}
    if not isinstance(sp, dict):
        sp = {}
    os_info = sp.get('operating_system', {})
    if not isinstance(os_info, dict):
        os_info = {}
    groups = host_data.get('groups') or []
    g0 = groups[0] if groups else {}
    if not isinstance(g0, dict):
        g0 = {}
    bootc = sp.get('bootc_status', {})
    bootc_booted = bootc.get('booted', {}) if isinstance(bootc, dict) else {}
    if not isinstance(bootc_booted, dict):
        bootc_booted = {}
    workloads = sp.get('workloads', {})
    workloads = workloads if isinstance(workloads, dict) else {}

    host_id = host_data['id']
    org_id = host_data['org_id']
    AdvisorInventoryHost.objects.update_or_create(
        inventory_id=host_id,
        org_id=org_id,
        defaults={
            'account': host_data.get('account'),
            'display_name': host_data['display_name'],
            'tags': host_data.get('tags', []),
            'workspace_id': g0.get('id'),
            'workspace_name': g0.get('name'),
            'workspace_ungrouped': g0.get('ungrouped'),
            'updated': _parse_dt(host_data.get('updated'), now),
            'created': _parse_dt(host_data.get('created'), now),
            'last_check_in': now,
            'stale_timestamp': _parse_dt(host_data.get('stale_timestamp'), now),
            'insights_id': host_data.get('insights_id'),
            'reporter': host_data.get('reporter', 'puptoo'),
            'per_reporter_staleness': host_data.get('per_reporter_staleness') or {},
            'os_name': os_info.get('name'),
            'os_major': os_info.get('major'),
            'os_minor': os_info.get('minor'),
            'host_type': sp.get('host_type'),
            'bootc_booted_image': bootc_booted.get('image'),
            'bootc_booted_image_digest': bootc_booted.get('image_digest'),
            'owner_id': sp.get('owner_id') or None,
            'rhc_client_id': sp.get('rhc_client_id') or None,
            'workloads': workloads,
            'system_update_method': sp.get('system_update_method'),
            'infrastructure_type': sp.get('infrastructure_type'),
            'bios_release_date': sp.get('bios_release_date'),
            'bios_vendor': sp.get('bios_vendor'),
            'bios_version': sp.get('bios_version'),
            'release': sp.get('release'),
        },
    )
    print(f"Host {host_id} upserted into advisor_inventory_host")


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

    insert_host(host)
