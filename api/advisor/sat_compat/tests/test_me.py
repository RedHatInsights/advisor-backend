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

from api.permissions import auth_header_for_testing
from api.tests import constants


class MeTestCase(TestCase):

    def test_me_view(self):
        # Completely simple
        response = self.client.get('/r/insights/me', **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {'account_number': '1234567', 'org_id': '9876543'})

    def test_me_view_cert_auth(self):
        # Should make no difference but just in case
        response = self.client.get(
            '/r/insights/me',
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertEqual(json_data, {'account_number': '1234567', 'org_id': '9876543'})
