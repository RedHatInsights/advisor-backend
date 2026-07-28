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
from itertools import batched

from django.core.management.base import BaseCommand
from django.utils import timezone

from api.models import Host
from feature_flags import feature_flag_is_enabled, FLAG_READ_LOCAL_INVENTORY


class Command(BaseCommand):
    help = 'Delete stale API host data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days', '--culled-days', type=int, default=14,
            help="Cull systems not updated in this many days (before now)"
        )
        parser.add_argument(
            '-b', '--batch', type=int, default=1000,
            help="Delete this many hosts at a time (to avoid large lock times)"
        )

    def handle(self, *args, **options):
        stale_cull_date = timezone.now() - timedelta(days=options['days'])
        use_local = feature_flag_is_enabled(FLAG_READ_LOCAL_INVENTORY)

        if use_local:
            raw_hosts = Host.objects.raw(
                """
                SELECT h.system_uuid
                FROM api_host h
                LEFT OUTER JOIN advisor_inventory_host aih
                  ON aih.inventory_id = h.system_uuid AND aih.org_id = h.org_id
                WHERE updated_at < %s AND aih.inventory_id IS NULL
                """,
                [stale_cull_date]
            )
        else:
            raw_hosts = Host.objects.raw(
                """
                SELECT h.system_uuid
                FROM api_host h
                LEFT OUTER JOIN inventory.hosts ih ON ih.id = h.system_uuid
                WHERE updated_at < %s AND ih.id IS NULL
                """,
                [stale_cull_date]
            )

        # Host has no FK or Relationship to AdvisorInventoryHost that
        # supports isnull lookups, and Host.inventory (OneToOneField to
        # InventoryHost) uses on_delete=DO_NOTHING with db_constraint=False
        # — no cascade either way.  Raw SQL identifies orphans; Django
        # handles deletion following all the foreign keys.
        for host_batch in batched(raw_hosts, options['batch']):
            Host.objects.filter(inventory__in=host_batch).delete()
