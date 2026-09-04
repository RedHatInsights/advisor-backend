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

from datetime import timedelta

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from api.models import AdvisorInventoryHost, Host
from api.tests import constants, replicate_to_advisor_inventory


class ImportContentTestCase(TestCase):
    fixtures = [
        'basic_test_ruleset', 'system_types', 'rule_categories',
        'upload_sources', 'basic_test_data'
    ]

    def setUp(self):
        super().setUp()
        replicate_to_advisor_inventory()

    def test_delete_hosts_command(self):
        orig_full_host_count = Host.objects.count()
        self.assertEqual(orig_full_host_count, 11)
        orig_aih_count = AdvisorInventoryHost.objects.count()
        self.assertEqual(orig_aih_count, 10)

        # Because we haven't done a staleness update here, all hosts
        # will be stale.  But this should not delete any Host objects,
        # because they still have an equivalent AdvisorInventoryHost object.
        call_command('delete_stale_api_hosts')

        # Now, the orphaned host 09 (no matching AdvisorInventoryHost) should be deleted.
        self.assertEqual(Host.objects.count(), 10)
        self.assertEqual(AdvisorInventoryHost.objects.count(), orig_aih_count)

        # Simulate AdvisorInventoryHost records being culled
        stale_cull_date = timezone.now() - timedelta(days=28)
        deleted_count = AdvisorInventoryHost.objects.filter(
            org_id=constants.standard_org, updated__lt=stale_cull_date,
        ).delete()[0]
        self.assertGreater(deleted_count, 0)

        update_aih_count = AdvisorInventoryHost.objects.count()
        self.assertLess(update_aih_count, orig_aih_count)

        # Now call the command again...
        call_command('delete_stale_api_hosts')

        # And hosts should have been deleted as well
        update_host_count = Host.objects.count()
        self.assertLess(update_host_count, orig_full_host_count)
        self.assertEqual(update_host_count, update_aih_count)


class AdvisorInventoryDeleteStaleTestCase(TestCase):
    """Tests delete_stale_api_hosts with AdvisorInventoryHost behind feature flag."""
    fixtures = [
        'basic_test_ruleset', 'system_types', 'rule_categories',
        'upload_sources', 'basic_test_data'
    ]

    def setUp(self):
        super().setUp()
        replicate_to_advisor_inventory()

    def test_delete_hosts_command_local(self):
        """Orphaned hosts are deleted using advisor_inventory_host join."""
        orig_host_count = Host.objects.count()
        self.assertEqual(orig_host_count, 11)
        orig_aih_count = AdvisorInventoryHost.objects.count()
        self.assertEqual(orig_aih_count, 10)

        call_command('delete_stale_api_hosts')

        # Orphaned host 09 (no matching InventoryHost/AdvisorInventoryHost) deleted
        self.assertEqual(Host.objects.count(), 10)
        self.assertEqual(AdvisorInventoryHost.objects.count(), orig_aih_count)

        # Remove some AdvisorInventoryHost records to simulate culling
        stale_cull_date = timezone.now() - timedelta(days=28)
        deleted_count = AdvisorInventoryHost.objects.filter(
            org_id=constants.standard_org, updated__lt=stale_cull_date,
        ).delete()[0]
        self.assertGreater(deleted_count, 0)

        update_aih_count = AdvisorInventoryHost.objects.count()
        self.assertLess(update_aih_count, orig_aih_count)

        call_command('delete_stale_api_hosts')

        update_host_count = Host.objects.count()
        self.assertLess(update_host_count, orig_host_count)
        self.assertEqual(update_host_count, update_aih_count)
