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

from api.models import Host, InventoryHost


class ImportContentTestCase(TestCase):
    fixtures = [
        'basic_test_ruleset', 'system_types', 'rule_categories',
        'upload_sources', 'basic_test_data'
    ]

    def test_delete_hosts_command(self):
        orig_full_host_count = Host.objects.count()
        self.assertEqual(orig_full_host_count, 10)
        orig_ihost_count = InventoryHost.objects.count()
        self.assertEqual(orig_ihost_count, 10)
        # We should not just have the same counts, but the same hosts - test
        # via explicit inner join
        orig_match_host_count = Host.objects.exclude(inventory__display_name=None).count()
        self.assertEqual(
            orig_match_host_count, 9,
            Host.objects.exclude(inventory_id__in=InventoryHost.objects.values_list('id'))
        )

        # Because we haven't done a staleness update here, all Inventory
        # hosts will be stale.  But this should not delete any Host objects,
        # because they still have an equivalent InventoryHost object.
        call_command('delete_stale_api_hosts')

        # Now, the orphaned host 09 should be deleted.
        self.assertEqual(Host.objects.count(), orig_match_host_count)
        self.assertEqual(InventoryHost.objects.count(), orig_ihost_count)

        # Simulate Inventory hosts being culled - just in one account so
        # some remain.
        stale_cull_date = timezone.now() - timedelta(days=28)
        InventoryHost.objects.exclude(org_id='9988776').filter(
            updated__lt=stale_cull_date,
        ).delete()

        # Note that update_stale_dates() does not delete...

        update_ihost_count = InventoryHost.objects.count()
        self.assertLess(update_ihost_count, orig_ihost_count)
        self.assertGreater(update_ihost_count, 0)
        self.assertEqual(Host.objects.count(), orig_match_host_count)

        # Now call the command again...
        call_command('delete_stale_api_hosts')

        # And hosts should have been deleted as well
        update_host_count = Host.objects.count()
        self.assertEqual(update_host_count, update_ihost_count)
        self.assertLess(update_host_count, orig_full_host_count)
