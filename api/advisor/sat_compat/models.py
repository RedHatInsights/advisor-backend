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

from django.db import models
from django.utils import timezone

from api.models import TimestampedModel

##############################################################################
# Satellite 6 specific models
#
# These are only here to emulate Satellite 6's use of Insights Classic.  These
# models should *not* be ported anywhere else: all efforts should be made to:
# 1. Have Satellite use the Insights Advisor API.
# 2. Have Satellite regularly download and manage Insights data itself rather
#    than merely being a pass-through for the Advisor API.
##############################################################################


class SatMaintenanceAction(models.Model):
    """
    The action to remedy one rule, either on all systems or one in particular.
    """
    plan = models.ForeignKey(
        'SatMaintenance', related_name='actions',
        on_delete=models.CASCADE, db_index=False
    )
    rule = models.ForeignKey('api.Rule', on_delete=models.CASCADE)
    host = models.ForeignKey('api.Host', on_delete=models.CASCADE)
    playbook = models.ForeignKey('api.Playbook', on_delete=models.CASCADE, null=True)
    done = models.BooleanField(default=False)


class SatMaintenance(TimestampedModel):
    """
    A plan for maintenance to be performed on a specific Satellite.
    """
    SUGGESTION_CHOICES = [
        ('P', 'proposed'), ('A', 'accepted'), ('R', 'rejected')
    ]

    account = models.CharField(max_length=10)  # Account is always present on Satellite requests
    org_id = models.CharField(max_length=10)  # Org ID is always present on Satellite requests
    branch_id = models.UUIDField(db_index=True)  # The ID of the Satellite
    name = models.CharField(max_length=255, null=True)
    suggestion = models.CharField(
        max_length=1, choices=SUGGESTION_CHOICES, null=True
    )
    description = models.CharField(max_length=255, null=True)
    start = models.DateTimeField(null=True)
    end = models.DateTimeField(null=True)
    created_by = models.CharField(max_length=80, null=True)
    silenced = models.BooleanField(default=False)
    hidden = models.BooleanField(default=False)
    allow_reboot = models.BooleanField(default=False)

    def overdue(self):
        """
        Do we have a start time, and should we have already started?
        """
        return self.start is not None and self.start > timezone.now()

    def __str__(self):
        return f"Maintenance Plan {self.pk} for account {self.account} and org {self.org_id}"
