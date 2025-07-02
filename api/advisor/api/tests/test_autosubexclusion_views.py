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


class AutosubExclusionViewTestCase(TestCase):
    fixtures = [
        'autosub_exclusion_account_list',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_pathway_retrieve(self):
        response = self.client.get(reverse('autosubexclusion-detail', args=[constants.first_exclusion['org_id']]),
                                   **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 200)

        exclusion_page = response.json()

        self.assertEqual(exclusion_page['org_id'], constants.first_exclusion['org_id'])
        self.assertEqual(exclusion_page['account'], constants.first_exclusion['account'])

    def test_pathway_list(self):
        response = self.client.get(reverse('autosubexclusion-list'), **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Test the exclusion page and pagination
        exclusion_page = response.json()

        self.assertIn('meta', exclusion_page)
        self.assertEqual(exclusion_page['meta']['count'], 313)
        self.assertIsInstance(exclusion_page['meta'], dict)
        self.assertIn('links', exclusion_page)
        self.assertIsInstance(exclusion_page['links'], dict)
        self.assertIn('data', exclusion_page)
        self.assertIsInstance(exclusion_page['data'], list)

        # We should see the exclusions we expect to see,
        exclusion_list = exclusion_page['data']
        self.assertEqual(len(exclusion_list), 10)

    def test_pathway_sorting(self):
        # Sort by org_id level ASC
        response = self.client.get(
            reverse('autosubexclusion-list'),
            data={'sort': 'org_id'},
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        exclusion_page = response.json()
        self.assertIn('data', exclusion_page)
        self.assertIsInstance(exclusion_page['data'], list)
        exclusion_list = exclusion_page['data']

        self.assertEqual(len(exclusion_list), 10)
        self.assertEqual(exclusion_list[0]['org_id'], constants.first_exclusion['org_id'])

        # Sort by org_id level DESC
        response = self.client.get(
            reverse('autosubexclusion-list'),
            data={'sort': '-org_id'},
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        exclusion_page = response.json()
        self.assertIn('data', exclusion_page)
        self.assertIsInstance(exclusion_page['data'], list)
        exclusion_list = exclusion_page['data']

        self.assertEqual(len(exclusion_list), 10)
        self.assertEqual(exclusion_list[0]['org_id'], constants.last_exclusion['org_id'])

        # Invalid sort criteria
        response = self.client.get(
            reverse('autosubexclusion-list'),
            data={'sort': 'darth_vader'},
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        self.assertEqual(response.status_code, 400)

    def test_pathway_create(self):
        # Post a new subscription exclusion org_id should return that record
        # Should return a 400 with an invalid org_id
        # Should return a 200 with a valid org_id
        new_exclusion = {
            'org_id': '9876543',
            'account': '1234567'
        }
        # test 403 with no permissions
        # notice the user headers do not contain any valid credentials
        response = self.client.post(reverse('autosubexclusion-list'),
                                    data=new_exclusion,
                                    **auth_header_for_testing())
        self.assertEqual(response.status_code, 403)

        # test the 400 first
        # notice this does not contain an org_id
        response = self.client.post(reverse('autosubexclusion-list'),
                                    data={
                                        'account': new_exclusion['account'],
                                    },
                                    **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 400)

        # test the 200
        response = self.client.post(reverse('autosubexclusion-list'),
                                    data=new_exclusion,
                                    **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_pathway_destroy(self):
        # test that all of the exclusions have been loaded
        response = self.client.get(reverse('autosubexclusion-list'), **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Test the exclusion page and pagination
        exclusion_page = response.json()

        self.assertIn('meta', exclusion_page)
        self.assertIsInstance(exclusion_page['meta'], dict)
        self.assertIn('links', exclusion_page)
        self.assertIsInstance(exclusion_page['links'], dict)
        self.assertIn('data', exclusion_page)
        self.assertIsInstance(exclusion_page['data'], list)

        # We should see the exclusions we expect to see,
        exclusion_list = exclusion_page['data']
        self.assertEqual(len(exclusion_list), 10)
        self.assertEqual(exclusion_page['meta']['count'], 313)

        # test that the exclusion can be retrieved
        response = self.client.get(reverse('autosubexclusion-detail', args=[constants.first_exclusion['org_id']]),
                                   **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 200)

        exclusion_page = response.json()

        self.assertEqual(exclusion_page['org_id'], constants.first_exclusion['org_id'])
        self.assertEqual(exclusion_page['account'], constants.first_exclusion['account'])

        # test destroy with no permissions
        response = self.client.delete(reverse('autosubexclusion-detail', args=[constants.delete_exclusion['org_id']]),
                                      **auth_header_for_testing())
        # Get back 403 - no permissions
        self.assertEqual(response.status_code, 403)

        # destroy one exclusion
        response = self.client.delete(reverse('autosubexclusion-detail', args=[constants.delete_exclusion['org_id']]),
                                      **auth_header_for_testing(user_opts={'is_internal': True}))
        # Get back 204 - no content.
        self.assertEqual(response.status_code, 204)

        # test the new exclusions list
        response = self.client.get(reverse('autosubexclusion-list'),
                                      **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Test the pathway page and pagination
        exclusion_page = response.json()

        self.assertIn('meta', exclusion_page)
        self.assertIsInstance(exclusion_page['meta'], dict)
        self.assertIn('links', exclusion_page)
        self.assertIsInstance(exclusion_page['links'], dict)
        self.assertIn('data', exclusion_page)
        self.assertIsInstance(exclusion_page['data'], list)

        # We should see the exclusions we expect to see,
        exclusions_list = exclusion_page['data']
        self.assertEqual(len(exclusions_list), 10)
        self.assertEqual(exclusion_page['meta']['count'], 312)

        # test that the one exclusion can't be retrieved
        response = self.client.get(reverse('autosubexclusion-detail', args=[constants.delete_exclusion['org_id']]),
                                   **auth_header_for_testing(user_opts={'is_internal': True}))
        self.assertEqual(response.status_code, 404)
