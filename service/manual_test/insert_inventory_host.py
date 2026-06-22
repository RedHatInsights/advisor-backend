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
Utility to insert a host dict into the local inventory.hosts_table.

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

import psycopg2
from psycopg2.extras import Json
from django.conf import settings

_db = settings.DATABASES['default']
DB_HOST = _db['HOST']
DB_PORT = _db['PORT'] or '5432'
DB_NAME = _db['NAME']
DB_USER = _db['USER']
DB_PASSWORD = _db['PASSWORD']


def insert_host(host_data):
    """Insert or update a host in inventory.hosts_table.

    Args:
        host_data: dict with at least 'id', 'org_id', and 'display_name'.
    """
    now = datetime.now(timezone.utc)
    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD
        )
    except psycopg2.OperationalError as e:
        print(f"Could not connect to database: {e}")
        print(f"Cannot insert host {host_data['display_name']} into inventory.hosts_table and so the API can't display it.")
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO inventory.hosts_table (
                    id, account, org_id, display_name, tags, groups,
                    updated, created, last_check_in, stale_timestamp,
                    system_profile, reporter, per_reporter_staleness,
                    insights_id
                ) VALUES (
                    %(id)s, %(account)s, %(org_id)s, %(display_name)s,
                    %(tags)s, %(groups)s, %(updated)s, %(created)s,
                    %(last_check_in)s, %(stale_timestamp)s,
                    %(system_profile)s, %(reporter)s,
                    %(per_reporter_staleness)s, %(insights_id)s
                )
                ON CONFLICT (id) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    tags = EXCLUDED.tags,
                    groups = EXCLUDED.groups,
                    updated = EXCLUDED.updated,
                    stale_timestamp = EXCLUDED.stale_timestamp,
                    system_profile = EXCLUDED.system_profile,
                    reporter = EXCLUDED.reporter,
                    per_reporter_staleness = EXCLUDED.per_reporter_staleness
            """, {
                'id': host_data['id'],
                'account': host_data.get('account'),
                'org_id': host_data['org_id'],
                'display_name': host_data['display_name'],
                'tags': Json(host_data.get('tags', [])),
                'groups': Json(host_data.get('groups', [])),
                'updated': host_data.get('updated') or now,
                'created': host_data.get('created') or now,
                'last_check_in': now,
                'stale_timestamp': host_data.get('stale_timestamp') or now,
                'system_profile': Json(host_data.get('system_profile', {})),
                'reporter': host_data.get('reporter', 'puptoo'),
                'per_reporter_staleness': Json(
                    host_data.get('per_reporter_staleness', {})
                ),
                'insights_id': host_data.get('insights_id'),
            })
        conn.commit()
        print(f"Host {host_data['id']} inserted into inventory.hosts_table")
    finally:
        conn.close()


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