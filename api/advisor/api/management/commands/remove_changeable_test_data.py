from django.core.management.base import BaseCommand
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

from api.models import (
    Ack, HostAck, CurrentReport,
    Pathway, RuleRating
)
from sat_compat.models import SatMaintenance


class Command(BaseCommand):

    def handle(self, *args, **options):
        # Delete all these and rely on the fixture loading to replace them
        accounts = ('1234567', '1122334', '1000000')
        Ack.objects.filter(account__in=accounts).delete()
        CurrentReport.objects.filter(account__in=accounts).delete()
        HostAck.objects.filter(account__in=accounts).delete()
        Pathway.objects.all().delete()
        RuleRating.objects.filter(account__in=accounts).delete()
        SatMaintenance.objects.filter(account__in=accounts).delete()
