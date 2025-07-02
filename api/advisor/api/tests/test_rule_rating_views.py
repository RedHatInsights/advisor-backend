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

from api.permissions import auth_header_for_testing
from api.tests import constants


class RuleRatingViewsTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule'
    ]

    other_test_auth = auth_header_for_testing(username='other-test')
    svc_acct_header = auth_header_for_testing(service_account=constants.service_account)

    def test_rule_rating_model(self):
        from api.models import RuleRating
        rr = RuleRating.objects.get(id=1)
        self.assertEqual(str(rr), "rhn-support-test gave 1 to test|Active_rule")

    def _response_is_good(self, response, expected_code=200):
        # Good response status is 200
        self.assertEqual(response.status_code, expected_code)
        # Standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Test content is decodable as JSON
        self.assertTrue(response.json, "Response cannot be decoded as json")
        return response.json()

    def _response_is_paginated(self, json_data):
        self.assertIsInstance(json_data, dict)
        self.assertEqual(sorted(json_data.keys()), ['data', 'links', 'meta'])
        self.assertIsInstance(json_data['meta'], dict)
        self.assertEqual(sorted(json_data['meta'].keys()), ['count'])
        self.assertIsInstance(json_data['links'], dict)
        self.assertEqual(
            sorted(json_data['links'].keys()), ['first', 'last', 'next', 'previous']
        )
        self.assertIsInstance(json_data['data'], list)

    def test_rule_rating_list(self):
        # We expect no ratings for a user that has not rated anything:
        response = self.client.get(
            reverse('rulerating-list'), **self.other_test_auth
        )
        ratings_page = self._response_is_good(response)
        self._response_is_paginated(ratings_page)
        self.assertEqual(len(ratings_page['data']), 0)

        # But we expect ratings from the 'testing' user
        response = self.client.get(
            reverse('rulerating-list'),
            **auth_header_for_testing()
        )
        ratings_page = self._response_is_good(response)
        self._response_is_paginated(ratings_page)
        rating_list = ratings_page['data']
        # Listing ordered (by default) on Insights rule ID
        self.assertEqual(
            rating_list,
            [
                {'rule': constants.acked_rule, 'rating': -1},
                {'rule': constants.active_rule, 'rating': 1},
            ]
        )

    def test_rule_rating_detail(self):
        # We expect to not find a rating for a user that doesn't have nay
        # ratings.
        response = self.client.get(
            reverse('rulerating-detail', kwargs={'rule': constants.active_rule}),
            **self.other_test_auth
        )
        self.assertEqual(response.status_code, 404)

        # But we expect ratings from the 'testing' user
        response = self.client.get(
            reverse('rulerating-detail', kwargs={'rule': constants.active_rule}),
            **auth_header_for_testing()
        )
        detail = self._response_is_good(response)
        self.assertEqual(detail, {'rule': constants.active_rule, 'rating': 1})
        # but we get a 404 for a rule we haven't rated
        response = self.client.get(
            reverse('rulerating-detail', kwargs={'rule': 'Second_Rule'}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    def test_rule_rating_creation(self):
        # Create a new rating as another test user:
        rating_data = {'rule': constants.active_rule, 'rating': 1}
        response = self.client.post(
            reverse('rulerating-list'), data=rating_data,
            **self.other_test_auth
        )
        # Created successfully
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        new_rating = response.json()
        self.assertEqual(new_rating, rating_data)

        # And we should now see that result in our list
        response = self.client.get(
            reverse('rulerating-list'), **self.other_test_auth
        )
        ratings_page = self._response_is_good(response)
        self._response_is_paginated(ratings_page)
        self.assertEqual(len(ratings_page['data']), 1)
        self.assertEqual(ratings_page['data'][0], rating_data)

        # We should get a 400 for a rule that doesn't exist - validation error
        response = self.client.post(
            reverse('rulerating-list'),
            data={'rule': 'Nonexistent_rule', 'rating': 1},
            **self.other_test_auth
        )
        self.assertEqual(response.status_code, 400)
        # We should get a 400 for an existing but inactive rule - validation error
        response = self.client.post(
            reverse('rulerating-list'),
            data={'rule': constants.inactive_rule, 'rating': 1},
            **self.other_test_auth
        )
        self.assertEqual(response.status_code, 400)

        # Updating a rule as the rhn-support-test user:
        updated_rating_data = {'rule': constants.active_rule, 'rating': 0}
        # Setting a rule's rating to zero does not delete that rating:
        response = self.client.post(
            reverse('rulerating-list'), data=updated_rating_data,
            **auth_header_for_testing()
        )
        # Updated successfully - status 200
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        new_rating = response.json()
        self.assertEqual(new_rating, updated_rating_data)
        response = self.client.get(
            reverse('rulerating-list'), **auth_header_for_testing()
        )
        ratings_page = self._response_is_good(response)
        self._response_is_paginated(ratings_page)
        self.assertEqual(len(ratings_page['data']), 2)
        # Acked, then Active:
        self.assertEqual(ratings_page['data'][1], updated_rating_data)

        # Updating a rule from a service account
        updated_rating_data = {'rule': constants.active_rule, 'rating': 1}
        # Setting a rule's rating to zero does not delete that rating:
        response = self.client.post(
            reverse('rulerating-list'), data=updated_rating_data,
            **self.svc_acct_header
        )
        # A new rating for this user
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        new_rating = response.json()
        self.assertEqual(new_rating, updated_rating_data)

    def test_rule_all_ratings_list(self):
        # Normal people shouldn't be able to see this:
        response = self.client.get(
            reverse('rulerating-all-ratings'),
            **auth_header_for_testing(user_opts={'is_internal': False})
        )
        self.assertEqual(response.status_code, 403)

        # But internal users can see the data, regardless of username
        response = self.client.get(
            reverse('rulerating-all-ratings'),
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        ratings_page = self._response_is_good(response)
        self._response_is_paginated(ratings_page)
        rating_list = ratings_page['data']
        # Listing ordered (by default) on Insights rule ID then username
        self.assertEqual(
            rating_list,
            [
                {
                    'rule': constants.acked_rule, 'rating': -1,
                    "created_at": "2019-10-21T04:29:12Z",
                    "updated_at": "2019-10-21T04:29:12Z",
                    "rated_by": "rhn-support-test", "account": "1234567",
                    "org_id": "9876543"
                },
                {
                    'rule': constants.acked_rule, 'rating': -1,
                    "created_at": "2019-10-21T04:29:12Z",
                    "updated_at": "2019-10-21T04:29:12Z",
                    "rated_by": "testing", "account": "1234567",
                    "org_id": "9876543"
                },
                {
                    'rule': constants.active_rule, 'rating': 1,
                    "created_at": "2019-10-21T04:29:11Z",
                    "updated_at": "2019-10-21T04:29:11Z",
                    "rated_by": "rhn-support-test", "account": "1234567",
                    "org_id": "9876543"
                },
                {
                    'rule': constants.active_rule, 'rating': 1,
                    "created_at": "2019-10-21T04:29:11Z",
                    "updated_at": "2019-10-21T04:29:11Z",
                    "rated_by": "testing", "account": "1234567",
                    "org_id": "9876543"
                },
            ]
        )

    def test_rule_rating_stats(self):
        # Normal people shouldn't be able to see this:
        response = self.client.get(
            reverse('rulerating-stats'),
            **auth_header_for_testing(user_opts={'is_internal': False})
        )
        self.assertEqual(response.status_code, 403)

        # But internal users can see the data, regardless of username
        response = self.client.get(
            reverse('rulerating-stats'),
            **auth_header_for_testing(user_opts={'is_internal': True})
        )
        ratings_page = self._response_is_good(response)
        self._response_is_paginated(ratings_page)
        rating_list = ratings_page['data']
        # Listing ordered (by default) on Insights rule ID
        # Unrated rules are not listed
        self.assertEqual(
            rating_list,
            [
                {
                    'rule': constants.acked_rule,
                    'total_ratings': 2,
                    'total_positive': 0,
                    'total_negative': 2,
                },
                {
                    'rule': constants.active_rule,
                    'total_ratings': 2,
                    'total_positive': 2,
                    'total_negative': 0,
                },
            ]
        )
