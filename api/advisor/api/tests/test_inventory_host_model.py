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

import datetime
import uuid

import pytz
from django.test import TestCase

from api.models import AdvisorInventoryHost
from api.tests import constants


class AdvisorInventoryHostTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    def test_host_properties(self):
        host = AdvisorInventoryHost.objects.get(inventory_id=constants.host_01_uuid)
        self.assertEqual(str(host), "{dn} ({id})".format(
            dn=constants.host_01_name, id=constants.host_01_uuid))
        self.assertEqual(host.id, uuid.UUID(constants.host_01_uuid))
        self.assertEqual(host.account, "1234567")
        self.assertEqual(host.org_id, "9876543")
        self.assertEqual(host.display_name, constants.host_01_name)
        self.assertEqual(host.updated, datetime.datetime(2018, 12, 4, 5, 15, 38, tzinfo=pytz.UTC))
        self.assertEqual(host.created, datetime.datetime(2020, 1, 1, 6, 0, tzinfo=pytz.UTC))
        self.assertEqual(host.stale_timestamp, datetime.datetime(2020, 1, 1, 6, 0, tzinfo=pytz.UTC))
        self.assertEqual(host.os_name, "RHEL")
        self.assertEqual(host.os_major, 7)
        self.assertEqual(host.os_minor, 5)
        self.assertEqual(host.system_update_method, "dnf")
        self.assertEqual(host.bios_vendor, "Dell Inc.")
        self.assertEqual(host.infrastructure_type, "physical")
        self.assertEqual(host.workloads, {
            'sap': {
                'sap_system': True,
                'sids': ['E01', 'E02'],
                'instance_number': '00',
                'version': '2.00.122.04.1478575636'
            },
            'crowdstrike': {
                'falcon_aid': 'abc123def456',
                'falcon_backend': 'bpf',
                'falcon_version': '7.14.0'
            },
            'satellite': {
                'type': 'server',
                'version': '6.17.6.1'
            }
        })

    def test_rhel_version(self):
        host = AdvisorInventoryHost.objects.get(inventory_id=constants.host_01_uuid)
        host.os_name = None
        host.os_major = None
        host.os_minor = None
        self.assertEqual(host.rhel_version, 'Unknown system version')
        host.os_name = 'RHEL'
        self.assertEqual(host.rhel_version, 'Unknown RHEL version')
        host.os_major = 8
        self.assertEqual(host.rhel_version, '8')
        host.os_minor = 2
        self.assertEqual(host.rhel_version, '8.2')

    def test_host_tag_filter(self):
        hosts = AdvisorInventoryHost.objects.filter(
            tags__contains=[{"key": "location", "value": "SLC", "namespace": "AWS"}]
        )
        self.assertIn(constants.host_ht_01_uuid, [str(host.id) for host in hosts])
