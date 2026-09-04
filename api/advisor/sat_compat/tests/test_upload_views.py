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

from django.test import TestCase
from django.urls import reverse

from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing


class UploaderTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_ping_view(self):
        response = self.client.get('/r/insights//')
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.content.decode(), 'lub-dub')

        response = self.client.get('/r/insights/')
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.content.decode(), 'lub-dub')

    def test_system_views(self):
        # Not sure that the Insights Client fetches this but just for
        # completeness
        response = self.client.get(
            reverse('sat-compat-v1-systems-list'),
            **auth_header_for_testing(system_opts=constants.host_04_system_data),
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # v1 list is not paginated
        sys_list = response.json()
        self.assertIsInstance(sys_list, list)
        # Should be only host 4
        self.assertEqual(sys_list[0]['toString'], constants.host_04_name)
        self.assertEqual(sys_list[0]['system_id'], constants.host_04_inid)  # Insights client ID
        self.assertEqual(len(sys_list), 1)

        # But the Insights Client checks the system's detail to see if it's
        # registered.
        response = self.client.get(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_04_inid},
            ),
            # data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing(system_opts=constants.host_04_system_data)
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        sys_detail = response.json()
        self.assertIsInstance(sys_detail, dict)
        self.assertEqual(sys_detail['toString'], constants.host_04_name)
        self.assertEqual(sys_detail['system_id'], constants.host_04_inid)  # Insights client ID

        # Systems can't see other systems
        response = self.client.get(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_03_inid},
            ),
            data={'branch_id': constants.remote_branch_lc},
            **auth_header_for_testing(system_opts=constants.host_04_system_data)
        )
        self.assertEqual(response.status_code, 404)

        # This view is denied to unauthenticated users
        response = self.client.get(reverse(
            'sat-compat-v1-systems-detail',
            kwargs={'uuid': constants.host_01_inid},
        ))
        self.assertEqual(response.status_code, 403)
