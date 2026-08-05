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

from itertools import batched

from django.core.management.base import BaseCommand
from django.db import transaction

from advisor_logging import logger
from api.models import AdvisorInventoryHost, Host

NIL_UUID = '00000000-0000-0000-0000-000000000000'


class Command(BaseCommand):
    help = "Purge hosts with nil insights_id (00000000-0000-0000-0000-000000000000) from AdvisorInventoryHost and Host tables"

    def add_arguments(self, parser):
        parser.add_argument(
            '-b', '--batch-size', type=int, default=1000,
            help="Delete this many hosts per transaction (default: 1000)"
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help="Report how many hosts would be deleted without actually deleting"
        )

    def handle(self, *args, **options):
        batch_size = options['batch_size']
        dry_run = options['dry_run']

        nil_hosts = AdvisorInventoryHost.objects.filter(insights_id=NIL_UUID)
        count = nil_hosts.count()

        if count == 0:
            logger.info("No hosts found with nil insights_id — nothing to purge")
            self.stdout.write(self.style.SUCCESS("No hosts with nil insights_id found. Done."))
            return

        logger.info("Found %d AdvisorInventoryHost record(s) with nil insights_id", count)
        self.stdout.write(f"Found {count} host(s) with nil insights_id.")

        if dry_run:
            self.stdout.write(self.style.WARNING(
                f"Dry run: would delete {count} AdvisorInventoryHost and associated Host records."
            ))
            return

        inventory_ids = list(
            nil_hosts.values_list('inventory_id', flat=True)
        )

        total_advisor_deleted = 0
        total_host_deleted = 0

        for batch in batched(inventory_ids, batch_size):
            batch_list = list(batch)
            with transaction.atomic():
                host_deleted_count, _ = Host.objects.filter(
                    inventory_id__in=batch_list
                ).delete()
                total_host_deleted += host_deleted_count

                advisor_deleted_count, _ = AdvisorInventoryHost.objects.filter(
                    inventory_id__in=batch_list, insights_id=NIL_UUID
                ).delete()
                total_advisor_deleted += advisor_deleted_count

            logger.info(
                "Batch purged %d AdvisorInventoryHost + %d Host records",
                advisor_deleted_count, host_deleted_count
            )

        logger.info(
            "Purge complete: deleted %d AdvisorInventoryHost and %d Host records total",
            total_advisor_deleted, total_host_deleted
        )
        self.stdout.write(self.style.SUCCESS(
            f"Purge complete: deleted {total_advisor_deleted} AdvisorInventoryHost "
            f"and {total_host_deleted} Host records."
        ))
