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

from api.models import Ack, Rule
from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing


class StatsTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Return JSON content, or fail!
        return response.json()

    def test_stats_list(self):
        # Test that we get an API view of the stats list
        response = self.client.get(reverse('stats-list'), **auth_header_for_testing())
        index = self._response_is_good(response)
        self.assertIn('overview', index)
        self.assertIn('reports', index)
        self.assertIn('rules', index)
        self.assertIn('systems', index)

    def test_overview_stats(self):
        response = self.client.get(reverse('stats-overview'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        # Systems in account 1234567: 1, 3, 4, 5, 6
        # Systems 1, 3, 4 and 6 should have reports of current, non-acked rules
        self.assertEqual(
            stats,
            {
                'pathways': 1,
                'incidents': 0,
                'critical': 0,
                'important': 0
            }
        )

    def test_rules_stats(self):
        response = self.client.get(reverse('stats-rules'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        # There are two rules - active and secondary - that impact systems
        self.assertEqual(stats, {
            'total': 2,
            # Both are at total risk 1
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            # test|Active_rule is Availability, test|Second_rule is Performance
            'category': {
                'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0
            }
        })

        # Test system_profile filter - accepted but doesn't change rule output
        response = self.client.get(
            reverse('stats-rules'),
            data={'filter[system_profile][sap_system]': 'False'},
            **auth_header_for_testing()
        )
        stats = self._response_is_good(response)
        self.assertEqual(stats, {
            'total': 2,
            # Both are at total risk 1
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            # Active_rule is Availability, Second_rule is Performance
            'category': {
                'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0
            }
        })

    def test_reports_stats(self):
        response = self.client.get(reverse('stats-reports'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        # Current uploads for account 1234567:
        # Report 07 Upload 03 Sys 03 TR 1 Cat Performance  Rule test|Second_rule
        # Report 08 Upload 04 Sys 01 TR 1 Cat Availability Rule test|Active_rule
        # Report 11 Upload 06 Sys 04 TR 1 Cat Availability Rule test|Active_rule
        # Report 12 Upload 06 Sys 04 TR 1 Cat Performance  Rule test|Second_rule
        # Report 17 Upload 03 Sys 03 TR 1 Cat Availability Rule test|Active_rule
        # Report 21 Upload 12 Sys 06 TR 1 Cat Availability Rule test|Active_rule
        # test|Active_rule is total risk 1, Availability category
        # test|Second_rule is total risk 1, Performance category
        self.assertEqual(stats, {
            'total': 6,
            'total_risk': {'1': 6, '2': 0, '3': 0, '4': 0},
            # test|Active_rule is Availability (1), test|Second_rule is Performance (4),
            # with three and two reports respectively.
            'category': {
                'Availability': 4, 'Performance': 2, 'Security': 0, 'Stability': 0
            }
        })

        # Test system profile filtering - report counts will change
        response = self.client.get(
            reverse('stats-reports'),
            data={'filter[system_profile][sap_system]': 'False'},
            **auth_header_for_testing()
        )
        stats = self._response_is_good(response)
        # Systems 1, 4, 5, 8, 9 and A are SAP systems, 3 and 6 are *non*-SAP
        self.assertEqual(stats, {
            'total': 3,
            'total_risk': {'1': 3, '2': 0, '3': 0, '4': 0},
            'category': {
                'Availability': 2, 'Performance': 1, 'Security': 0, 'Stability': 0
            }
        })

    def test_systems_stats(self):
        response = self.client.get(reverse('stats-systems'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        # Systems in account 1234567: 1, 3, 4, 5, 6
        # Systems 1, 3, 4 and 6 should have reports of current, non-acked rules
        self.assertEqual(
            stats,
            {
                'total': 4,
                'category': {
                    'Availability': 4,
                    'Performance': 2,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 4, '2': 0, '3': 0, '4': 0}
            }
        )

        # Test system profile filtering - host counts will change
        response = self.client.get(
            reverse('stats-systems'),
            data={'filter[system_profile][sap_system]': 'False'},
            **auth_header_for_testing()
        )
        stats = self._response_is_good(response)
        # Systems in account 1234567: 1, 3, 4, 5, 6
        # Systems 1, 4, 5, 8, 9 and A are SAP systems
        # Systems 1, 3, 4 and 6 should have reports of current, non-acked rules
        self.assertEqual(
            stats,
            {
                'total': 2,
                'category': {
                    'Availability': 2,
                    'Performance': 1,
                    'Security': 0,
                    'Stability': 0
                },
                'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0}
            }
        )


class StatsAfterAckTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def setUp(self):
        # Acknowledge the test|Active_rule.
        self.ack = Ack(
            rule=Rule.objects.get(rule_id=constants.active_rule),
            account='1234567', org_id='9876543'
        )
        self.ack.save()

    def tearDown(self):
        # Delete our ack because it won't be reset by fixtures.
        self.ack.delete()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Return JSON content, or fail!
        return response.json()

    def test_rules_stats_after_ack(self):
        # Now we should see different stats
        response = self.client.get(reverse('stats-rules'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        # There is one rule - secondary - that impacts systems
        self.assertEqual(stats, {
            'total': 1,
            # It is at total risk 1
            'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0},
            # test|Second_rule is Performance
            'category': {
                'Availability': 0, 'Performance': 1, 'Security': 0, 'Stability': 0
            }
        })

    def test_reports_stats_after_ack(self):
        # Now we should see different stats
        response = self.client.get(reverse('stats-reports'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        # Upload 03 System 03 Rule test|Active_rule  Report 17 - acked
        # Upload 03 System 03 Rule test|Second_rule  Report 07
        # Upload 04 System 01 Rule test|Active_rule  Report 08 - acked
        # Upload 06 System 04 Rule test|Active_rule  Report 11 - acked
        # Upload 06 System 04 Rule test|Second_rule  Report 12
        # Upload 09 System 01 Rule test|Second_rule  Report 20 - host acked
        # Upload 12 System 06 Rule test|Active_rule  Report 21 - acked
        # test|Second_rule is total risk 1, Performance category
        self.assertEqual(stats, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {
                'Availability': 0, 'Performance': 2, 'Security': 0, 'Stability': 0
            }
        })

    def test_systems_stats_after_ack(self):
        # Now we should see different stats
        response = self.client.get(reverse('stats-systems'), **auth_header_for_testing())
        stats = self._response_is_good(response)

        self.assertEqual(stats, {
            'total': 2,
            'category': {
                'Availability': 0,
                'Performance': 2,
                'Security': 0,
                'Stability': 0
            },
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0}
        })


class StatsHostTagsTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        return response.json()

    def test_reports_stats(self):
        response = self.client.get(
            reverse('stats-reports'),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 7,
            'total_risk': {'1': 7, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 4, 'Performance': 3, 'Security': 0, 'Stability': 0},
        })

        # Report stats count current reports.
        # A location with three hosts, none that have the acked rule
        response = self.client.get(
            reverse('stats-reports'),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 6,
            'total_risk': {'1': 6, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 3, 'Performance': 3, 'Security': 0, 'Stability': 0},
        })

        # A group with two hosts, one of which has the acked rule
        response = self.client.get(
            reverse('stats-reports'),
            data={'tags': 'customer/security=low'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 3,
            'total_risk': {'1': 3, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 2, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # Two groups which only end up containing one host, without a rule ack
        response = self.client.get(
            reverse('stats-reports'),
            data={'tags': 'customer/environment=database,customer/environment=web'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

    def test_rules_stats(self):
        response = self.client.get(
            reverse('stats-rules'),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # Rule stats count rules affecting any included system.
        # A location with three hosts, none that have the acked rule
        response = self.client.get(
            reverse('stats-rules'),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # A group with two hosts, one of which has the acked rule
        response = self.client.get(
            reverse('stats-rules'),
            data={'tags': 'customer/security=low'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # Two groups which only end up containing one host, without a rule ack
        response = self.client.get(
            reverse('stats-rules'),
            data={'tags': 'customer/environment=database,customer/environment=web'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # A location with one host, with the acked rule (Second_Rule)
        response = self.client.get(
            reverse('stats-rules'),
            data={'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 1,
            'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 0, 'Security': 0, 'Stability': 0},
        })

    def test_systems_stats(self):
        response = self.client.get(
            reverse('stats-systems'),
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 4,
            'total_risk': {'1': 4, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 4, 'Performance': 3, 'Security': 0, 'Stability': 0},
        })

        # System stats counts systems affected by any rule
        # A location with three hosts, none that have the acked rule
        response = self.client.get(
            reverse('stats-systems'),
            data={'tags': 'AWS/location=SFO'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 3,
            'total_risk': {'1': 3, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 3, 'Performance': 3, 'Security': 0, 'Stability': 0},
        })

        # A group with two hosts, one of which has the acked rule
        response = self.client.get(
            reverse('stats-systems'),
            data={'tags': 'customer/security=low'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 2,
            'total_risk': {'1': 2, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 2, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # Two groups which only end up containing one host, without a rule ack
        response = self.client.get(
            reverse('stats-systems'),
            data={'tags': 'customer/environment=database,customer/environment=web'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 1,
            'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 1, 'Security': 0, 'Stability': 0},
        })

        # A location with one host, with the acked rule (Second_Rule)
        response = self.client.get(
            reverse('stats-systems'),
            data={'tags': 'AWS/location=SLC'},
            **auth_header_for_testing(account='1000000', org_id='1000000')
        )
        data = self._response_is_good(response)
        self.assertEqual(data, {
            'total': 1,
            'total_risk': {'1': 1, '2': 0, '3': 0, '4': 0},
            'category': {'Availability': 1, 'Performance': 0, 'Security': 0, 'Stability': 0},
        })
