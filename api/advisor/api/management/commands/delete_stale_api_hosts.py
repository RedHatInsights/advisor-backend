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
        # Delete all hosts this many days older than now
        stale_cull_date = timezone.now() - timedelta(days=options['days'])
        # Only delete hosts without a matching inventory record, because
        # there's no point deleting a Host if it's still in Inventory.
        # And sadly because there's no direct ForeignKey relationship
        # between Host and InventoryHost, the Relationship doesn't really
        # support the 'isnull=True' / =None kind of assertion that creates a
        # LEFT OUTER JOIN in the SQL.  So we have to do it this way.
        raw_hosts = Host.objects.raw(
            """
            SELECT h.system_uuid
            FROM api_host h
            LEFT OUTER JOIN inventory.hosts ih ON ih.id = h.system_uuid
            WHERE updated_at < %s AND ih.id IS NULL
            """,
            [stale_cull_date]
        )
        # But let Django do the correct deletion following all the foreign
        # keys:
        for host_batch in batched(raw_hosts, options['batch']):
            Host.objects.filter(inventory__in=host_batch).delete()
