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

from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from api.management.commands.purge_nil_insights_id_hosts import NIL_UUID
from api.models import AdvisorInventoryHost, Host
from api.tests import constants


VALID_INSIGHTS_ID = 'aabbccdd-1122-3344-5566-778899001122'


class TestPurgeNilInsightsIdHosts(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def _create_nil_host(self, host_id, org_id=constants.standard_org):
        """Helper to create a host with nil insights_id in both tables."""
        now = timezone.now()
        AdvisorInventoryHost.objects.create(
            inventory_id=host_id,
            org_id=org_id,
            display_name=f'nil-host-{host_id[:8]}',
            account=constants.standard_acct,
            tags=[],
            updated=now,
            created=now,
            last_check_in=now,
            stale_timestamp=now,
            insights_id=NIL_UUID,
            reporter='puptoo',
            per_reporter_staleness={},
        )
        Host.objects.update_or_create(
            inventory_id=host_id,
            defaults={
                'account': constants.standard_acct,
                'org_id': org_id,
            }
        )

    def _create_valid_host(self, host_id, org_id=constants.standard_org):
        """Helper to create a host with a valid insights_id."""
        now = timezone.now()
        AdvisorInventoryHost.objects.create(
            inventory_id=host_id,
            org_id=org_id,
            display_name=f'valid-host-{host_id[:8]}',
            account=constants.standard_acct,
            tags=[],
            updated=now,
            created=now,
            last_check_in=now,
            stale_timestamp=now,
            insights_id=VALID_INSIGHTS_ID,
            reporter='puptoo',
            per_reporter_staleness={},
        )
        Host.objects.update_or_create(
            inventory_id=host_id,
            defaults={
                'account': constants.standard_acct,
                'org_id': org_id,
            }
        )

    def test_no_nil_hosts_exits_early(self):
        """Command exits early with success when no nil insights_id hosts exist."""
        out = StringIO()
        with self.assertLogs(logger='advisor-log', level='INFO') as logs:
            call_command('purge_nil_insights_id_hosts', stdout=out)

        self.assertIn("No hosts with nil insights_id found", out.getvalue())
        self.assertTrue(
            any("nothing to purge" in line for line in logs.output)
        )

    def test_purges_nil_hosts(self):
        """Command deletes hosts with nil insights_id from both tables."""
        nil_host_id = '11111111-1111-1111-1111-111111111111'
        self._create_nil_host(nil_host_id)

        self.assertTrue(
            AdvisorInventoryHost.objects.filter(inventory_id=nil_host_id).exists()
        )
        self.assertTrue(Host.objects.filter(inventory_id=nil_host_id).exists())

        out = StringIO()
        with self.assertLogs(logger='advisor-log', level='INFO'):
            call_command('purge_nil_insights_id_hosts', stdout=out)

        self.assertFalse(
            AdvisorInventoryHost.objects.filter(inventory_id=nil_host_id).exists()
        )
        self.assertFalse(Host.objects.filter(inventory_id=nil_host_id).exists())
        self.assertIn("Purge complete", out.getvalue())

    def test_does_not_delete_valid_hosts(self):
        """Command leaves hosts with valid insights_id untouched."""
        nil_host_id = '22222222-2222-2222-2222-222222222222'
        valid_host_id = '33333333-3333-3333-3333-333333333333'
        self._create_nil_host(nil_host_id)
        self._create_valid_host(valid_host_id)

        out = StringIO()
        with self.assertLogs(logger='advisor-log', level='INFO'):
            call_command('purge_nil_insights_id_hosts', stdout=out)

        self.assertFalse(
            AdvisorInventoryHost.objects.filter(inventory_id=nil_host_id).exists()
        )
        self.assertTrue(
            AdvisorInventoryHost.objects.filter(inventory_id=valid_host_id).exists()
        )
        self.assertTrue(Host.objects.filter(inventory_id=valid_host_id).exists())

    def test_dry_run_does_not_delete(self):
        """Dry run reports counts but does not delete anything."""
        nil_host_id = '44444444-4444-4444-4444-444444444444'
        self._create_nil_host(nil_host_id)

        out = StringIO()
        with self.assertLogs(logger='advisor-log', level='INFO'):
            call_command('purge_nil_insights_id_hosts', '--dry-run', stdout=out)

        self.assertIn("Dry run", out.getvalue())
        self.assertTrue(
            AdvisorInventoryHost.objects.filter(inventory_id=nil_host_id).exists()
        )
        self.assertTrue(Host.objects.filter(inventory_id=nil_host_id).exists())

    def test_batch_size_processes_all(self):
        """Command with small batch size still processes all nil hosts."""
        host_ids = [
            '55555555-5555-5555-5555-555555555551',
            '55555555-5555-5555-5555-555555555552',
            '55555555-5555-5555-5555-555555555553',
        ]
        for hid in host_ids:
            self._create_nil_host(hid)

        out = StringIO()
        with self.assertLogs(logger='advisor-log', level='INFO'):
            call_command('purge_nil_insights_id_hosts', '--batch-size=2', stdout=out)

        for hid in host_ids:
            self.assertFalse(
                AdvisorInventoryHost.objects.filter(inventory_id=hid).exists()
            )
            self.assertFalse(Host.objects.filter(inventory_id=hid).exists())

        self.assertIn("Purge complete", out.getvalue())
