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

from django.db import models
from django.test import TestCase
from django.utils import timezone

from api.models import AdvisorInventoryHost, CurrentReport, Host, stale_systems_q
from api.tests import constants


class HostModelTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data'
    ]

    def test_host_properties(self):
        h = Host.objects.get(inventory_id=constants.host_03_uuid)
        self.assertEqual(h.account, '1234567')
        self.assertEqual(h.rhel_version, '7.5')
        self.assertEqual(str(h), constants.host_03_uuid)

    def test_inventory_id_is_system_uuid_primary_key(self):
        field = Host._meta.get_field('inventory_id')

        self.assertIsInstance(field, models.UUIDField)
        self.assertIs(Host._meta.pk, field)
        self.assertEqual(field.column, 'system_uuid')
        self.assertFalse(field.is_relation)
        self.assertFalse(field.serialize)

    def test_stale_systems_q_uses_org_and_inventory_id(self):
        report = CurrentReport.objects.filter(
            org_id=constants.standard_org,
        ).first()
        inventory_host = AdvisorInventoryHost.objects.get(
            org_id=constants.standard_org,
            inventory_id=report.host_id,
        )
        inventory_host.per_reporter_staleness = {
            'puptoo': {
                'stale_warning_timestamp': str(timezone.now() + timedelta(days=1)),
            },
        }
        inventory_host.save(update_fields=['per_reporter_staleness'])

        reports = CurrentReport.objects.filter(
            stale_systems_q(constants.standard_org),
            pk=report.pk,
        )
        _, params = reports.query.sql_with_params()
        self.assertIn(constants.standard_org, params)
        self.assertTrue(reports.exists())

        inventory_host.per_reporter_staleness = {
            'puptoo': {
                'stale_warning_timestamp': str(timezone.now() - timedelta(days=1)),
            },
        }
        inventory_host.save(update_fields=['per_reporter_staleness'])
        self.assertFalse(reports.exists())
