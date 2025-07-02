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

from django.core.management.base import BaseCommand

from api.tests import update_stale_dates


class Command(BaseCommand):
    """
    Freshen all hosts (as done in tests).
    """
    def add_arguments(self, parser):
        parser.add_argument(
            '--days', '-d', type=float, default=60.0,
            help='Put (fresh) hosts this many days into the future'
        )

    def handle(self, *args, **options):
        days = options['days']
        update_stale_dates(days)
