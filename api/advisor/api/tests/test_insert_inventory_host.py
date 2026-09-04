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

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from unittest.mock import patch

from django.test import TestCase

ROOT = Path(__file__).resolve().parents[4]
sys.path.append(str(ROOT / 'service'))

from manual_test import insert_inventory_host
from api.models import AdvisorInventoryHost, Host


HOST_ID = '57c4c38b-a8c6-4289-9897-223681fd804d'
INSIGHTS_ID = '45bdd8ce-36e6-4861-a4dd-cd69af79f6f1'
WORKSPACE_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
SATELLITE_ID = 'ffeeddcc-bbaa-9988-7766-554433221120'


class InsertInventoryHostTests(TestCase):
    @patch.object(insert_inventory_host.timezone, 'now')
    def test_insert_host_normalizes_and_upserts_inventory(self, now_mock):
        now = datetime(2026, 9, 4, 12, 30, tzinfo=timezone.utc)
        now_mock.return_value = now
        old_timestamp = '2020-02-12T12:30:21+00:00'
        host_data = {
            'id': HOST_ID,
            'org_id': '9876543',
            'account': '1234567',
            'display_name': 'manual.example.com',
            'insights_id': INSIGHTS_ID,
            'satellite_id': SATELLITE_ID,
            'created': None,
            'updated': None,
            'last_check_in': None,
            'stale_timestamp': old_timestamp,
            'stale_warning_timestamp': old_timestamp,
            'culled_timestamp': old_timestamp,
            'reporter': None,
            'tags': None,
            'groups': [{
                'id': WORKSPACE_ID,
                'name': 'manual-workspace',
                'ungrouped': False,
            }],
            'system_profile': {
                'operating_system': {'name': 'RHEL', 'major': 9, 'minor': 6},
                'host_type': 'edge',
                'infrastructure_type': 'virtual',
                'bios_vendor': 'Red Hat',
                'workloads': {'sap': {'sap_system': True}},
            },
            'per_reporter_staleness': {
                'puptoo': {
                    'stale_timestamp': old_timestamp,
                    'check_in_succeeded': True,
                },
                'rhsm-system-profile-bridge': {'stale_timestamp': old_timestamp},
            },
        }

        insert_inventory_host.insert_host(host_data)

        inventory_host = AdvisorInventoryHost.objects.get(
            inventory_id=HOST_ID,
            org_id='9876543',
        )
        self.assertEqual(inventory_host.created, now)
        self.assertEqual(inventory_host.updated, now)
        self.assertEqual(inventory_host.last_check_in, now)
        self.assertEqual(inventory_host.stale_timestamp, now + timedelta(days=1))
        self.assertEqual(inventory_host.reporter, 'puptoo')
        self.assertEqual(inventory_host.tags, [])
        self.assertEqual(str(inventory_host.workspace_id), WORKSPACE_ID)
        self.assertEqual(inventory_host.workspace_name, 'manual-workspace')
        self.assertIs(inventory_host.workspace_ungrouped, False)
        self.assertEqual(inventory_host.os_name, 'RHEL')
        self.assertEqual(inventory_host.os_major, 9)
        self.assertEqual(inventory_host.os_minor, 6)
        self.assertEqual(inventory_host.host_type, 'edge')
        self.assertEqual(inventory_host.infrastructure_type, 'virtual')
        self.assertEqual(inventory_host.bios_vendor, 'Red Hat')
        self.assertEqual(inventory_host.workloads, {'sap': {'sap_system': True}})

        puptoo_staleness = inventory_host.per_reporter_staleness['puptoo']
        self.assertEqual(puptoo_staleness['last_check_in'], now.isoformat())
        self.assertEqual(
            puptoo_staleness['stale_timestamp'],
            (now + timedelta(days=1)).isoformat(),
        )
        self.assertEqual(
            puptoo_staleness['stale_warning_timestamp'],
            (now + timedelta(days=7)).isoformat(),
        )
        self.assertEqual(
            puptoo_staleness['culled_timestamp'],
            (now + timedelta(days=14)).isoformat(),
        )
        self.assertIs(puptoo_staleness['check_in_succeeded'], True)
        self.assertIn(
            'rhsm-system-profile-bridge',
            inventory_host.per_reporter_staleness,
        )

        host = Host.objects.get(inventory_id=HOST_ID)
        self.assertEqual(host.org_id, '9876543')
        self.assertEqual(host.account, '1234567')
        self.assertEqual(str(host.satellite_id), SATELLITE_ID)

        updated_data = dict(host_data)
        updated_data['display_name'] = 'renamed.example.com'
        updated_data['groups'] = []
        insert_inventory_host.insert_host(updated_data)

        self.assertEqual(
            AdvisorInventoryHost.objects.filter(inventory_id=HOST_ID).count(),
            1,
        )
        self.assertEqual(Host.objects.filter(inventory_id=HOST_ID).count(), 1)
        inventory_host.refresh_from_db()
        self.assertEqual(inventory_host.display_name, 'renamed.example.com')
        self.assertIsNone(inventory_host.workspace_id)
        self.assertIsNone(inventory_host.workspace_name)

    def test_insert_host_rejects_invalid_identity(self):
        cases = [
            (
                {'org_id': '9876543', 'display_name': 'missing-id', 'insights_id': INSIGHTS_ID},
                'missing required identity field\\(s\\): id',
            ),
            (
                {
                    'id': HOST_ID,
                    'org_id': '9876543',
                    'display_name': 'nil-insights-id',
                    'insights_id': '00000000-0000-0000-0000-000000000000',
                },
                'insights_id must not be the nil UUID',
            ),
        ]
        for host_data, error in cases:
            with self.subTest(host_data=host_data):
                with self.assertRaisesRegex(ValueError, error):
                    insert_inventory_host.insert_host(host_data)
