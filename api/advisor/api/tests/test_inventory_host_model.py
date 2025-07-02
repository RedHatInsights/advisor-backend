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

from api.models import InventoryHost
from api.tests import constants


class InventoryHostTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    def test_host_properties(self):
        host = InventoryHost.objects.get(id=constants.host_01_uuid)
        self.assertEqual(str(host), "{dn} ({id})".format(
            dn=constants.host_01_name, id=constants.host_01_uuid))
        self.assertEqual(host.id, uuid.UUID(constants.host_01_uuid))
        self.assertEqual(host.account, "1234567")
        self.assertEqual(host.org_id, "9876543")
        self.assertEqual(host.display_name, constants.host_01_name)
        self.assertEqual(host.updated, datetime.datetime(2018, 12, 4, 5, 15, 38, tzinfo=pytz.UTC))
        self.assertEqual(host.created, datetime.datetime(2020, 1, 1, 6, 0, tzinfo=pytz.UTC))
        self.assertEqual(host.stale_timestamp, datetime.datetime(2020, 1, 1, 6, 0, tzinfo=pytz.UTC))
        self.assertEqual(host.stale_warning_timestamp, datetime.datetime(2020, 1, 2, 6, 0, tzinfo=pytz.UTC))
        self.assertEqual(host.culled_timestamp, datetime.datetime(2020, 1, 8, 6, 0, tzinfo=pytz.UTC))
        self.assertEqual(host.system_profile, {
            'arch': 'x86_64', 'bios_vendor': 'Dell Inc.', 'bios_version':
            '2.8.0', 'bios_release_date': '13/06/2017', 'cores_per_socket':
            8, 'infrastructure_type': 'physical', 'insights_client_version':
            '3.0.14', 'insights_egg_version': '3.0.182-1',
            'number_of_sockets': 2, 'os_release': constants.rhel_release,
            'operating_system': {'major': 7, 'minor': 5, 'name': 'RHEL'},
            'sap_system': True, 'satellite_managed': True,
            'owner_id': '55df28a7-d7ef-48c5-bc57-8967025399b1',
            'system_memory_bytes': 134927265792, 'sap_sids': ['E01', 'E02'],
            'system_update_method': 'dnf',
        })

    def test_rhel_version(self):
        # Muck about with the system profile's operating system value to
        # test various permutations
        host = InventoryHost.objects.get(id=constants.host_01_uuid)
        del host.system_profile['operating_system']
        self.assertEqual(host.rhel_version, 'Unknown system version')
        host.system_profile['operating_system'] = {}
        self.assertEqual(host.rhel_version, 'Unknown OS version')
        host.system_profile['operating_system']['name'] = 'RHEL'
        self.assertEqual(host.rhel_version, 'Unknown RHEL version')
        host.system_profile['operating_system']['major'] = 8
        self.assertEqual(host.rhel_version, '8')
        host.system_profile['operating_system']['minor'] = 2
        self.assertEqual(host.rhel_version, '8.2')

    def test_host_tag_filter(self):
        hosts = InventoryHost.objects.filter(
            tags__contains=[{"key": "location", "value": "SLC", "namespace": "AWS"}]
        )
        self.assertIn(constants.host_ht_01_uuid, [str(host.id) for host in hosts])
