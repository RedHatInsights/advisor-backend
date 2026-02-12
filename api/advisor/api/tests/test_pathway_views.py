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


class PathwayModelTestCase(TestCase):
    fixtures = [
        'resolution_risks', 'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'pathways', 'basic_test_data', 'pathways_test_data',
    ]

    def test_str(self):
        from api.models import Pathway
        pathway = Pathway.objects.get(slug=constants.first_pathway['slug'])
        self.assertEqual(str(pathway), constants.first_pathway['name'])


class PathwayViewTestCase(TestCase):
    fixtures = [
        'resolution_risks', 'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'pathways', 'basic_test_data', 'pathways_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_pathway_retrieve(self):
        response = self.client.get(reverse('pathway-detail', args=[constants.first_pathway['slug']]),
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)

        pathway_page = response.json()

        self.assertEqual(pathway_page['name'], constants.first_pathway['name'])
        self.assertEqual(pathway_page['description'], constants.first_pathway['description'])
        self.assertEqual(pathway_page['component'], constants.first_pathway['component'])
        self.assertEqual(pathway_page['resolution_risk'], constants.first_pathway['resolution_risk'])
        self.assertEqual(pathway_page['recommendation_level'], constants.first_pathway['recommendation_level'])

    def test_pathway_list(self):
        response = self.client.get(reverse('pathway-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Test the pathway page and pagination
        pathway_page = response.json()

        self.assertIn('meta', pathway_page)
        self.assertIsInstance(pathway_page['meta'], dict)
        self.assertIn('links', pathway_page)
        self.assertIsInstance(pathway_page['links'], dict)
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)

        # We should see the pathways we expect to see,
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 9)
        self.assertEqual(len(pathway_list), pathway_page['meta']['count'])
        # Check on all pathways recommendation levels - check calculation?
        # Ordering defaults to name, except networkmanager < kernel?
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])
        self.assertEqual(pathway_list[0]['recommendation_level'], 54)
        self.assertEqual(pathway_list[1]['name'], constants.reboot_required_pathway['name'])
        self.assertEqual(pathway_list[1]['recommendation_level'], 90)
        self.assertEqual(pathway_list[2]['name'], constants.incident_pathway['name'])
        self.assertEqual(pathway_list[2]['recommendation_level'], 92)
        self.assertEqual(pathway_list[3]['name'], constants.no_incident_pathway['name'])
        self.assertEqual(pathway_list[3]['recommendation_level'], 54)
        self.assertEqual(pathway_list[4]['name'], constants.first_pathway['name'])
        self.assertEqual(pathway_list[4]['recommendation_level'], constants.first_pathway['recommendation_level'])
        self.assertEqual(pathway_list[5]['name'], constants.second_pathway['name'])
        self.assertEqual(pathway_list[5]['recommendation_level'], constants.second_pathway['recommendation_level'])
        self.assertEqual(pathway_list[6]['name'], constants.third_pathway['name'])
        self.assertEqual(pathway_list[6]['recommendation_level'], constants.third_pathway['recommendation_level'])
        self.assertEqual(pathway_list[7]['name'], constants.fourth_pathway['name'])
        self.assertEqual(pathway_list[7]['recommendation_level'], constants.fourth_pathway['recommendation_level'])
        self.assertEqual(pathway_list[8]['name'], constants.fifth_pathway['name'])
        self.assertEqual(pathway_list[8]['recommendation_level'], constants.fifth_pathway['recommendation_level'])

    def test_pathway_sorting(self):
        # Sort by impacted systems count
        response = self.client.get(
            reverse('pathway-list'),
            data={'sort': '-impacted_systems_count'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 9)
        self.assertEqual(pathway_list[0]['name'], constants.first_pathway['name'])

        # Can sort even when no pathways are found
        response = self.client.get(
            reverse('pathway-list'),
            data={'sort': '-impacted_systems_count', 'category': '4'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertEqual(pathway_page['meta']['count'], 0)
        response = self.client.get(
            reverse('pathway-list'),
            data={'sort': 'recommendation_level', 'category': '4'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertEqual(pathway_page['meta']['count'], 0)

        # Sort by recommendation level ASC
        response = self.client.get(
            reverse('pathway-list'),
            data={'sort': 'recommendation_level'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']

        self.assertEqual(len(pathway_list), 9)
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])

        # Sort by recommendation level DESC
        response = self.client.get(
            reverse('pathway-list'),
            data={'sort': '-recommendation_level'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']

        self.assertEqual(len(pathway_list), 9)
        self.assertEqual(pathway_list[0]['name'], constants.third_pathway['name'])
        self.assertEqual(pathway_list[1]['name'], constants.incident_pathway['name'])

        # Invalid sort criteria
        response = self.client.get(
            reverse('pathway-list'),
            data={'sort': 'darth_vader'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400)

    def test_pathway_filters(self):
        response = self.client.get(
            reverse('pathway-list'),
            data={'reboot_required': 'yes'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 2)
        self.assertEqual(pathway_list[0]['name'], constants.reboot_required_pathway['name'])
        self.assertEqual(pathway_list[1]['name'], constants.first_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'reboot_required': 'no'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 7)
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])

        # True/false query parameters can't have an 'invalid' state as they're
        # based on 'does this contain y|yes|t|true' :-)

        response = self.client.get(
            reverse('pathway-list'),
            data={'has_incident': 'yes'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 1)

        response = self.client.get(
            reverse('pathway-list'),
            data={'has_incident': 'no'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 8)
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'filter[system_profile][sap_system]': 'True'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 4)
        self.assertEqual(pathway_list[0]['name'], constants.first_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'filter[system_profile][sap_system]': 'False'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 7)
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])

        # test categories
        response = self.client.get(
            reverse('pathway-list'),
            data={'category': '1'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 7)
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])
        self.assertEqual(pathway_list[2]['name'], constants.first_pathway['name'])
        self.assertEqual(pathway_list[2]['reboot_required'], True)
        self.assertTrue(
            all([pathway['categories'] == [constants.availability_category] for pathway in pathway_list])
        )

        response = self.client.get(
            reverse('pathway-list'),
            data={'category': '2'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 2)
        self.assertTrue(
            all([pathway['categories'] == [constants.security_category] for pathway in pathway_list])
        )

        response = self.client.get(
            reverse('pathway-list'),
            data={'category': '1,2'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 8)
        self.assertTrue(
            all([pathway['categories'] in [
                [constants.availability_category],
                [constants.security_category],
                [constants.availability_category, constants.security_category],
            ] for pathway in pathway_list])
        )

        response = self.client.get(
            reverse('pathway-list'),
            data={'category': '3'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 1)
        self.assertEqual(pathway_list[0]['name'], constants.incident_pathway['name'])
        self.assertTrue(
            all([pathway['categories'] == [constants.stability_category] for pathway in pathway_list])
        )

        response = self.client.get(
            reverse('pathway-list'),
            data={'category': '2,3'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 3)
        self.assertTrue(
            all([pathway['categories'] in [
                [constants.security_category],
                [constants.stability_category],
                [constants.security_category, constants.stability_category],
            ] for pathway in pathway_list])
        )

        response = self.client.get(
            reverse('pathway-list'),
            data={'category': '4'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 0)
        self.assertTrue(
            all([pathway['categories'] == [constants.performance_category] for pathway in pathway_list])
        )

        # test text contains
        response = self.client.get(
            reverse('pathway-list'),
            data={'text': 'test'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 2)
        self.assertEqual(pathway_list[0]['name'], constants.first_pathway['name'])
        self.assertEqual(pathway_list[1]['name'], constants.second_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'text': 'reboot'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 2)
        self.assertEqual(pathway_list[0]['name'], constants.no_reboot_required_pathway['name'])
        self.assertEqual(pathway_list[1]['name'], constants.reboot_required_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'text': 'upgrade kernel'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 1)

        response = self.client.get(
            reverse('pathway-list'),
            data={'filter[system_profile][sap_sids][contains][]': 'E02'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 4)
        self.assertEqual(pathway_list[0]['name'], constants.first_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'filter[system_profile][sap_sids][contains][]': 'E03'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 2)
        self.assertEqual(pathway_list[0]['name'], constants.incident_pathway['name'])

        response = self.client.get(
            reverse('pathway-list'),
            data={'filter[system_profile][sap_sids][contains][]': 'Mangle'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 0)

        # Test inventory groups, with only one host in the group
        response = self.client.get(
            reverse('pathway-list'),
            data={'groups': 'group_1'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 2)
        self.assertEqual(pathway_list[0]['name'], constants.first_pathway['name'])
        self.assertEqual(pathway_list[0]['impacted_systems_count'], 1)  # only one host
        self.assertEqual(pathway_list[1]['name'], constants.fifth_pathway['name'])
        self.assertEqual(pathway_list[1]['impacted_systems_count'], 1)  # only one host

    def test_pathway_systems(self):

        # Test the Pathway response
        response = self.client.get(reverse('pathway-systems', kwargs={'slug': constants.first_pathway['slug']}),
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Test the pathway page and pagination
        systems_page = response.json()

        self.assertIn('meta', systems_page)
        self.assertIsInstance(systems_page['meta'], dict)
        self.assertIn('links', systems_page)
        self.assertIsInstance(systems_page['links'], dict)
        self.assertIn('data', systems_page)
        self.assertIsInstance(systems_page['data'], list)

        # We should see the systems we expect to see,
        systems_list = systems_page['data']
        self.assertEqual(len(systems_list), 4)

        # Test filtering by systems profile
        response = self.client.get(
            reverse('pathway-systems', kwargs={'slug': constants.first_pathway['slug']}),
            data={'filter[system_profile][sap_system]': 'True'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        systems_list = response.json()['data']
        self.assertEqual(len(systems_list), 2)
        self.assertIsInstance(systems_list[0], dict)
        self.assertEqual(systems_list[0]['display_name'], constants.host_01_name)
        self.assertEqual(systems_list[1]['display_name'], constants.host_04_name)

        # Test filtering by Inventory group
        response = self.client.get(
            reverse('pathway-systems', kwargs={'slug': constants.first_pathway['slug']}),
            data={'groups': 'group_1'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        systems_list = response.json()['data']
        self.assertIsInstance(systems_list[0], dict)
        self.assertEqual(systems_list[0]['display_name'], constants.host_01_name)
        self.assertEqual(len(systems_list), 1)

    def test_pathway_rules(self):

        # Test the Pathway response
        response = self.client.get(reverse('pathway-rules', kwargs={'slug': constants.first_pathway['slug']}),
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

        # Test the pathway page and pagination
        rules_page = response.json()

        self.assertIn('meta', rules_page)
        self.assertIsInstance(rules_page['meta'], dict)
        self.assertIn('links', rules_page)
        self.assertIsInstance(rules_page['links'], dict)
        self.assertIn('data', rules_page)
        self.assertIsInstance(rules_page['data'], list)

        # We should see the rules we expect to see,
        rules_list = rules_page['data']
        self.assertEqual(len(rules_list), 3)
        self.assertEqual(rules_list[0]['rule_id'], constants.active_rule)
        self.assertEqual(rules_list[1]['rule_id'], constants.acked_rule)
        self.assertEqual(rules_list[2]['rule_id'], constants.pathway_rule_1['rule_id'])

        # test text contains
        response = self.client.get(reverse('pathway-rules', kwargs={'slug': constants.first_pathway['slug']}),
                                   data={'text': 'pathway_rule_1'},
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        pathway_page = response.json()
        self.assertIn('data', pathway_page)
        self.assertIsInstance(pathway_page['data'], list)
        pathway_list = pathway_page['data']
        self.assertEqual(len(pathway_list), 1)
        self.assertEqual(pathway_list[0]['rule_id'], constants.pathway_rule_1['rule_id'])

    def test_pathway_rule_category(self):
        # There are 2 rules in first_pathway, pathway_rule_1 and active_rule
        # Only active_rule is in category 1 (Availability)
        response = self.client.get(reverse('pathway-rules', kwargs={'slug': constants.first_pathway['slug']}),
                                   data={'category': '1'},
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        rule_page = response.json()
        rule_list = rule_page['data']
        self.assertEqual(len(rule_list), 1)
        self.assertEqual(rule_list[0]['rule_id'], constants.active_rule)
        self.assertEqual(rule_list[0]['category'], constants.availability_category)

        # Filtering on both categories 1 & 2 (Availability & Security) will return both rules
        response = self.client.get(reverse('pathway-rules', kwargs={'slug': constants.first_pathway['slug']}),
                                   data={'category': '1,2'},
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        rule_page = response.json()
        rule_list = rule_page['data']
        self.assertEqual(len(rule_list), 2)
        self.assertEqual(rule_list[0]['rule_id'], constants.active_rule)
        self.assertEqual(rule_list[1]['rule_id'], constants.pathway_rule_1['rule_id'])
        self.assertTrue(
            all([rule['category'] in [
                constants.availability_category,
                constants.security_category,
            ] for rule in rule_list])
        )

        # pathway_rule_1 is in category 2 (Security)
        response = self.client.get(reverse('pathway-rules', kwargs={'slug': constants.first_pathway['slug']}),
                                   data={'category': '2'},
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        rule_page = response.json()
        rule_list = rule_page['data']
        self.assertEqual(len(rule_list), 1)
        self.assertEqual(rule_list[0]['rule_id'], constants.pathway_rule_1['rule_id'])
        self.assertEqual(rule_list[0]['category'], constants.security_category)

        # Neither rule is in category 4 (Performance)
        response = self.client.get(reverse('pathway-rules', kwargs={'slug': constants.first_pathway['slug']}),
                                   data={'category': '4'},
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        rule_page = response.json()
        rule_list = rule_page['data']
        self.assertEqual(len(rule_list), 0)

    def test_pathway_rule_systems(self):
        response = self.client.get(
            reverse('pathway-reports', kwargs={
                'slug': constants.first_pathway['slug']
            }),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        results = response.json()
        self.assertIsInstance(results, dict)
        self.assertEqual(list(results.keys()), ['rules'])
        self.assertIsInstance(results['rules'], dict)
        for key, val in results['rules'].items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(val, list)
            self.assertTrue(all(isinstance(sys, str) for sys in val))
        # Specific tests
        self.assertIn(constants.active_rule, results['rules'])
        # Ordered by ... hits?
        self.assertEqual(results['rules'][constants.active_rule], [
            constants.host_01_uuid, constants.host_03_uuid,
            constants.host_04_uuid, constants.host_06_uuid,
        ])
        # Second rule not in pathway
        self.assertNotIn(constants.second_rule, results['rules'])

        # test text contains
        response = self.client.get(reverse('pathway-reports', kwargs={'slug': constants.first_pathway['slug']}),
                                   data={'text': 'pathway_rule_1'},
                                   **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        results = response.json()
        self.assertIsInstance(results, dict)
        self.assertEqual(list(results.keys()), ['rules'])
        self.assertIsInstance(results['rules'], dict)
        for key, val in results['rules'].items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(val, list)
            self.assertTrue(all(isinstance(sys, str) for sys in val))
        # Specific tests
        self.assertIn(constants.pathway_rule_1['rule_id'], results['rules'])

    def test_pathway_report_filters(self):
        # filter against NO host ids and NO rule ids
        response = self.client.get(
            reverse('pathway-reports', kwargs={
                'slug': constants.first_pathway['slug']
            }),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        results = response.json()

        self.assertEqual(len(results['rules'][constants.active_rule]), 4)
        self.assertEqual(len(results['rules'][constants.pathway_rule_1['rule_id']]), 2)

        # filter against host ids
        response = self.client.get(
            reverse('pathway-reports', kwargs={
                'slug': constants.first_pathway['slug']
            }),
            data={
                'host_id': ",".join([constants.host_01_uuid, constants.host_03_uuid])
            },
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        results = response.json()

        self.assertEqual(len(results['rules'][constants.active_rule]), 2)
        self.assertTrue(constants.host_01_uuid in results['rules'][constants.active_rule])
        self.assertTrue(constants.host_03_uuid in results['rules'][constants.active_rule])

        self.assertEqual(len(results['rules'][constants.pathway_rule_1['rule_id']]), 2)
        self.assertTrue(constants.host_01_uuid in results['rules'][constants.pathway_rule_1['rule_id']])
        self.assertTrue(constants.host_03_uuid in results['rules'][constants.pathway_rule_1['rule_id']])

        # filter against rule ids
        response = self.client.get(
            reverse('pathway-reports', kwargs={
                'slug': constants.first_pathway['slug']
            }),
            data={
                'rule_id': constants.active_rule
            },
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        results = response.json()

        self.assertEqual(len(results['rules']), 1)
        self.assertTrue(constants.active_rule in results['rules'])
        self.assertEqual(len(results['rules'][constants.active_rule]), 4)

        # filter against rule ids AND host ids
        response = self.client.get(
            reverse('pathway-reports', kwargs={
                'slug': constants.first_pathway['slug']
            }),
            data={
                'rule_id': constants.active_rule,
                'host_id': constants.host_01_uuid
            },
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        results = response.json()

        self.assertEqual(len(results['rules']), 1)
        self.assertTrue(constants.active_rule in results['rules'])
        self.assertEqual(len(results['rules'][constants.active_rule]), 1)
        self.assertTrue(constants.host_01_uuid in results['rules'][constants.active_rule])


class PathwayViewHostTagsTestCase(TestCase):
    fixtures = [
        'resolution_risks', 'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'pathways', 'basic_test_data', 'pathways_test_data', 'host_tag_test_data',
    ]
    header = auth_header_for_testing(account='1000000', org_id='1000000')

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_pathway_list(self):
        # Should only be one system in SLC
        response = self.client.get(
            reverse('pathway-list'),
            data={'tags': 'AWS/location=SLC'},
            **self.header
        )
        pathway_list = response.json()['data']
        self.assertEqual(pathway_list[0]['name'], constants.first_pathway['name'])
        self.assertEqual(pathway_list[0]['description'], constants.first_pathway['description'])
        self.assertEqual(pathway_list[0]['component'], constants.first_pathway['component'])
        self.assertEqual(pathway_list[0]['resolution_risk'], constants.first_pathway['resolution_risk'])
        self.assertEqual(pathway_list[0]['has_incident'], constants.first_pathway['has_incident'])
        self.assertEqual(pathway_list[0]['incident_count'], constants.first_pathway['incident_count'])
        self.assertEqual(pathway_list[0]['impacted_systems_count'], 1)

        # Nonexistent tag -> no hosts -> no impact -> no pathways shown
        response = self.client.get(
            reverse('pathway-list'),
            data={'tags': 'elephant/in=the_room'},
            **self.header
        )
        pathway_list = response.json()['data']
        self.assertEqual(pathway_list, [])

    def test_pathway_retrieve(self):
        response = self.client.get(
            reverse('pathway-detail', args=[constants.first_pathway['slug']]),
            data={'tags': 'AWS/location=SLC'},
            **self.header
        )
        self.assertEqual(response.status_code, 200)

        pathway = response.json()

        self.assertEqual(pathway['name'], constants.first_pathway['name'])
        self.assertEqual(pathway['description'], constants.first_pathway['description'])
        self.assertEqual(pathway['component'], constants.first_pathway['component'])
        self.assertEqual(pathway['resolution_risk'], constants.first_pathway['resolution_risk'])
        # Should only be two systems in SLC
        self.assertEqual(pathway['impacted_systems_count'], 1)

    def test_pathway_systems(self):

        # Test the Pathway response
        response = self.client.get(
            reverse('pathway-systems', kwargs={'slug': constants.first_pathway['slug']}),
            data={'tags': 'AWS/location=SFO'},
            **self.header
        )
        self.assertEqual(response.status_code, 200)
        systems_page = response.json()
        systems_list = systems_page['data']
        self.assertEqual(len(systems_list), 3)  # Three systems in SFO

        # Test the Pathway response
        response = self.client.get(
            reverse('pathway-systems', kwargs={'slug': constants.first_pathway['slug']}),
            data={'text': 'system02.example.biz'},
            **self.header
        )
        self.assertEqual(response.status_code, 200)
        systems_page = response.json()
        systems_list = systems_page['data']
        self.assertEqual(len(systems_list), 1)  # One system
        self.assertEqual(systems_list[0]['display_name'], 'system02.example.biz')
