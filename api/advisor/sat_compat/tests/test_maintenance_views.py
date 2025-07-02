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

import csv
import re
from json import loads
import responses

from django.test import TestCase, override_settings
from django.urls import reverse

from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing

from sat_compat.models import SatMaintenance, SatMaintenanceAction
from sat_compat.views.maintenance import TEST_PLAYBOOK

REMEDIATIONS_URL = 'http://localhost'
PLAYBOOK_URL = REMEDIATIONS_URL + '/api/remediations/v1/playbook'


class MaintenanceTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data', 'high_severity_rule', 'sat_maintenance',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_maintenance_model(self):
        # Quick test of model stringification for code coverage
        maint = SatMaintenance.objects.get(id=1)
        self.assertEqual(str(maint), "Maintenance Plan 1 for account 1234567 and org 9876543")

    def test_maintenance_list(self):
        response = self.client.get(
            reverse('sat-compat-maintenance-list'), **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        list_data = response.json()
        self.assertIsInstance(list_data, list)
        # Fixture data in 0 and 1
        self.assertEqual(len(list_data), 2)
        plan = list_data[0]
        self.assertIn('name', plan)
        self.assertEqual(plan['name'], 'Test plan')
        self.assertIn('remote_branch', plan)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(plan['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', plan)
        self.assertEqual(plan['maintenance_id'], 1)
        self.assertIn('created_by', plan)
        self.assertEqual(plan['created_by'], 'testing')
        self.assertIn('overdue', plan)
        self.assertEqual(plan['overdue'], False)
        self.assertIn('silenced', plan)
        self.assertEqual(plan['silenced'], False)
        self.assertIn('hidden', plan)
        self.assertEqual(plan['hidden'], False)
        self.assertIn('allow_reboot', plan)
        self.assertEqual(plan['allow_reboot'], True)

        # No auth, no service.
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
        )
        self.assertEqual(response.status_code, 403, response.content.decode())

    def test_maintenance_list_cert_auth(self):
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        list_data = response.json()
        self.assertIsInstance(list_data, list)
        # Fixture data in 0 and 1
        self.assertEqual(len(list_data), 2)
        plan = list_data[0]
        self.assertIn('name', plan)
        self.assertEqual(plan['name'], 'Test plan')
        self.assertIn('remote_branch', plan)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(plan['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', plan)
        self.assertEqual(plan['maintenance_id'], 1)
        self.assertIn('created_by', plan)
        self.assertEqual(plan['created_by'], 'testing')
        self.assertIn('overdue', plan)
        self.assertEqual(plan['overdue'], False)
        self.assertIn('silenced', plan)
        self.assertEqual(plan['silenced'], False)
        self.assertIn('hidden', plan)
        self.assertEqual(plan['hidden'], False)
        self.assertIn('allow_reboot', plan)
        self.assertEqual(plan['allow_reboot'], True)

    def test_maintenance_plan_get_csv(self):
        response = self.client.get(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}) + '?accept=csv',
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.csv_mime)

        # Decode CSV and test generically
        csv_data = list(csv.reader(response.content.decode().splitlines()))
        self.assertIsInstance(csv_data[0], list)
        header_list = csv_data[0]
        self.assertTrue(all(len(x) == len(header_list) for x in csv_data[1:]))
        data = [{
            header_list[index]: field
            for index, field in enumerate(row)
        } for row in csv_data[1:]]
        # Test specific data
        self.assertEqual(header_list, [
            'Hostname', 'Machine ID', 'Description', 'Category', 'Severity',
            'Article', 'Completed', 'Scheduled start (UTC)', 'Scheduled end (UTC)',
        ])
        self.assertIn('Hostname', data[0])
        self.assertEqual(data[0]['Hostname'], constants.host_01_name)
        self.assertIn('Machine ID', data[0])
        self.assertEqual(data[0]['Machine ID'], constants.host_01_inid)
        self.assertIn('Description', data[0])
        self.assertEqual(data[0]['Description'], constants.active_title)
        self.assertIn('Category', data[0])
        self.assertEqual(data[0]['Category'], 'Availability')
        self.assertIn('Severity', data[0])
        self.assertEqual(data[0]['Severity'], '1')  # Text because CSV format
        self.assertIn('Article', data[0])
        self.assertEqual(data[0]['Article'], 'https://access.redhat.com/node/1048576')
        self.assertIn('Completed', data[0])
        self.assertEqual(data[0]['Completed'], 'False')
        self.assertIn('Scheduled start (UTC)', data[0])
        self.assertEqual(data[0]['Scheduled start (UTC)'], '')
        self.assertIn('Scheduled end (UTC)', data[0])
        self.assertEqual(data[0]['Scheduled end (UTC)'], '')

    def test_maintenance_create_simple(self):
        # Simple plan with no detail yet
        response = self.client.post(
            # Special construction because post method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-list') + '?branch_id=' + constants.remote_branch_uc,
            data={'name': 'New test plan', 'add': []},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 201, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        # First check what we got back - just the ID
        self.assertIn('id', json_data)
        plan_id = json_data['id']
        self.assertEqual(list(json_data.keys()), ['id'])

        # Now check that the list contains the correct data
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        list_data = response.json()
        self.assertIsInstance(list_data, list)
        self.assertEqual(len(list_data), 3)
        # Fixture data in 0
        self.assertIn('name', list_data[0])
        self.assertEqual(list_data[0]['name'], 'Test plan')
        self.assertEqual(list_data[1]['name'], 'Dummy plan')
        # New data in 2?
        new_data = list_data[2]
        self.assertIn('name', new_data)
        self.assertEqual(new_data['name'], 'New test plan')
        self.assertIn('remote_branch', new_data)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(new_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', new_data)
        plan_id = new_data['maintenance_id']
        self.assertIn('created_by', new_data)
        self.assertEqual(new_data['created_by'], 'testing')
        self.assertIn('overdue', new_data)
        self.assertEqual(new_data['overdue'], False)
        self.assertIn('silenced', new_data)
        self.assertEqual(new_data['silenced'], False)
        self.assertIn('hidden', new_data)
        self.assertEqual(new_data['hidden'], False)
        self.assertIn('allow_reboot', new_data)
        self.assertEqual(new_data['allow_reboot'], False)

        # Now retrieve that ID
        response = self.client.get(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        item_data = response.json()
        self.assertIsInstance(item_data, dict)
        self.assertIn('name', item_data)
        self.assertEqual(item_data['name'], 'New test plan')
        self.assertIn('remote_branch', item_data)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(item_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', item_data)
        self.assertIn('created_by', item_data)
        self.assertEqual(item_data['created_by'], 'testing')
        self.assertIn('overdue', item_data)
        self.assertEqual(item_data['overdue'], False)
        self.assertIn('silenced', item_data)
        self.assertEqual(item_data['silenced'], False)
        self.assertIn('hidden', item_data)
        self.assertEqual(item_data['hidden'], False)
        self.assertIn('allow_reboot', item_data)
        self.assertEqual(item_data['allow_reboot'], False)

    def test_maintenance_create_simple_cert_auth(self):
        # Simple plan with no detail yet
        response = self.client.post(
            # Special construction because post method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-list') + '?branch_id=' + constants.remote_branch_uc,
            data={'name': 'New test plan', 'add': []},
            content_type=constants.json_mime,
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 201, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        # First check what we got back - just the ID
        self.assertIn('id', json_data)
        plan_id = json_data['id']
        self.assertEqual(list(json_data.keys()), ['id'])

        # Now check that the list contains the correct data
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        list_data = response.json()
        self.assertIsInstance(list_data, list)
        self.assertEqual(len(list_data), 3)
        # Fixture data in 0
        self.assertIn('name', list_data[0])
        self.assertEqual(list_data[0]['name'], 'Test plan')
        self.assertEqual(list_data[1]['name'], 'Dummy plan')
        # New data in 2?
        new_data = list_data[2]
        self.assertIn('name', new_data)
        self.assertEqual(new_data['name'], 'New test plan')
        self.assertIn('remote_branch', new_data)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(new_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', new_data)
        plan_id = new_data['maintenance_id']
        self.assertIn('created_by', new_data)
        self.assertEqual(new_data['created_by'], 'Certified System')
        self.assertIn('overdue', new_data)
        self.assertEqual(new_data['overdue'], False)
        self.assertIn('silenced', new_data)
        self.assertEqual(new_data['silenced'], False)
        self.assertIn('hidden', new_data)
        self.assertEqual(new_data['hidden'], False)
        self.assertIn('allow_reboot', new_data)
        self.assertEqual(new_data['allow_reboot'], False)

        # Now retrieve that ID
        response = self.client.get(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        item_data = response.json()
        self.assertIsInstance(item_data, dict)
        self.assertIn('name', item_data)
        self.assertEqual(item_data['name'], 'New test plan')
        self.assertIn('remote_branch', item_data)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(item_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', item_data)
        self.assertIn('created_by', item_data)
        self.assertEqual(item_data['created_by'], 'Certified System')
        self.assertIn('overdue', item_data)
        self.assertEqual(item_data['overdue'], False)
        self.assertIn('silenced', item_data)
        self.assertEqual(item_data['silenced'], False)
        self.assertIn('hidden', item_data)
        self.assertEqual(item_data['hidden'], False)
        self.assertIn('allow_reboot', item_data)
        self.assertEqual(item_data['allow_reboot'], False)

        # Other accounts shouldn't be able to delete it
        response = self.client.delete(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing('9988776')
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # Now delete it
        response = self.client.delete(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 204, f"Response: {response.status_code} - {response.content.decode()}")

        # And now we should have only the fixture plans
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(len(json_data), 2)
        self.assertEqual(json_data[0]['name'], 'Test plan')
        self.assertEqual(json_data[1]['name'], 'Dummy plan')

    def test_maintenance_create_destroy_with_rules(self):
        # Plan with rules and hosts
        response = self.client.post(
            # Special construction because post method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-list') + '?branch_id=' + constants.remote_branch_uc,
            data={
                'name': 'Newer test plan',
                'description': 'Test plan description',
                'start': '2020-10-29T10:50:00+11:00',
                'silenced': False,
                'hidden': True,
                'add': [
                    {'rule_id': constants.active_rule},
                    # This is a duplicate and should be ignored...
                    {'rule_id': constants.active_rule, 'system_id': constants.host_01_inid},
                    # This isn't, and should be kept...
                    {'rule_id': constants.second_rule, 'system_id': constants.host_01_inid},
                    # Action with unknown system - should not be added
                    {'rule_id': constants.second_rule, 'system_id': constants.missing_branch},
                    # Action with system not in our account - should not be added
                    {'rule_id': constants.second_rule, 'system_id': constants.host_02_inid},
                    # Action with inactive rule - should not be added
                    {'rule_id': constants.inactive_rule, 'system_id': constants.host_01_inid},
                ]
            },
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 201, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        # First check what we got back - just the ID
        self.assertIn('id', json_data)
        self.assertEqual(list(json_data.keys()), ['id'])

        # Now check that the list contains the correct data
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        list_data = response.json()
        self.assertIsInstance(list_data, list)
        self.assertEqual(len(list_data), 3)
        # Fixture data in 0 and 1
        self.assertIn('name', list_data[0])
        self.assertEqual(list_data[0]['name'], 'Test plan')
        self.assertIn('name', list_data[1])
        self.assertEqual(list_data[1]['name'], 'Dummy plan')
        # New data in 2?
        new_data = list_data[2]
        self.assertIn('name', new_data)
        self.assertEqual(new_data['name'], 'Newer test plan')
        self.assertIn('remote_branch', new_data)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(new_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', new_data)
        plan_id = new_data['maintenance_id']
        self.assertIn('created_by', new_data)
        self.assertEqual(new_data['created_by'], 'testing')
        self.assertIn('overdue', new_data)
        self.assertEqual(new_data['overdue'], False)
        self.assertIn('silenced', new_data)
        self.assertEqual(new_data['silenced'], False)
        self.assertIn('hidden', new_data)
        self.assertEqual(new_data['hidden'], True)
        self.assertIn('allow_reboot', new_data)
        self.assertEqual(new_data['allow_reboot'], False)

        # Retrieve this record
        response = self.client.get(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        item_data = response.json()
        self.assertIsInstance(item_data, dict)
        self.assertIn('name', item_data)
        self.assertEqual(item_data['name'], 'Newer test plan')
        self.assertIn('remote_branch', item_data)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(item_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', item_data)
        self.assertIn('created_by', item_data)
        self.assertEqual(item_data['created_by'], 'testing')
        self.assertIn('overdue', item_data)
        self.assertEqual(item_data['overdue'], False)
        self.assertIn('silenced', item_data)
        self.assertEqual(item_data['silenced'], False)
        self.assertIn('hidden', item_data)
        self.assertEqual(item_data['hidden'], True)
        self.assertIn('allow_reboot', item_data)
        self.assertEqual(item_data['allow_reboot'], False)

        # Here we expect that the first maintenance action has been
        # expanded out to apply to all the systems reporting that rule on
        # this Satellite - which is hosts 1 and 3.
        actions = item_data['actions']
        # Check full details of first action
        self.assertEqual(actions[0]['maintenance_id'], plan_id)
        self.assertEqual(actions[0]['system']['toString'], constants.host_01_name)
        self.assertEqual(actions[0]['system']['isCheckingIn'], True)
        self.assertEqual(actions[0]['system']['system_id'], constants.host_01_inid)
        self.assertEqual(actions[0]['system']['display_name'], constants.host_01_name)
        self.assertEqual(actions[0]['system']['hostname'], constants.host_01_name)
        self.assertEqual(actions[0]['system']['last_check_in'], '2018-12-04T05:15:38Z')
        self.assertEqual(actions[0]['system']['system_type_id'], 105)
        self.assertEqual(actions[0]['rule']['id'], constants.active_rule)
        self.assertEqual(actions[0]['rule']['description'], constants.active_title)
        self.assertEqual(actions[0]['rule']['description_html'], '<p>Active rule</p>')
        self.assertEqual(actions[0]['rule']['severity'], 'INFO')
        self.assertEqual(actions[0]['rule']['ansible'], True)
        self.assertEqual(actions[0]['rule']['ansible_fix'], False)
        self.assertEqual(actions[0]['rule']['ansible_mitigation'], False)
        self.assertEqual(actions[0]['rule']['category'], 'Availability')
        self.assertEqual(actions[0]['rule']['reboot_required'], False)
        self.assertEqual(actions[0]['rule']['rec_impact'], 1)
        self.assertEqual(actions[0]['rule']['rec_likelihood'], 1)
        self.assertEqual(actions[0]['done'], False)
        # Only important details for other actions.
        self.assertEqual(actions[1]['system']['toString'], constants.host_03_name)
        self.assertEqual(actions[1]['system']['isCheckingIn'], True)
        self.assertEqual(actions[1]['rule']['id'], constants.active_rule)
        self.assertEqual(actions[2]['system']['toString'], constants.host_01_name)
        self.assertEqual(actions[2]['system']['isCheckingIn'], True)
        self.assertEqual(actions[2]['rule']['id'], constants.second_rule)
        self.assertEqual(len(item_data['actions']), 3)

        # Other accounts shouldn't be able to delete it
        response = self.client.delete(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing('9988776')
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # Now delete it
        response = self.client.delete(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': plan_id}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 204, f"Response: {response.status_code} - {response.content.decode()}")

        # And now we should have only the fixture plans
        response = self.client.get(
            reverse('sat-compat-maintenance-list'), **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(len(json_data), 2)

        # schneeky insider check of plans and actions to make sure deleting
        # the plan also deletes its actions
        self.assertEqual(SatMaintenance.objects.count(), 2)
        # The ones we don't count are:
        # * pk=3: deleted host
        # * pk=4: deleted rule
        # * pk=5: acked rule
        self.assertEqual(SatMaintenanceAction.objects.count(), 5)

    def test_maintenance_create_errors(self):
        # POST without authentication
        response = self.client.post(
            reverse('sat-compat-maintenance-list'),
            data={'name': 'Test plan', 'add': []},
            content_type=constants.json_mime,
        )
        self.assertEqual(response.status_code, 403, f"Response: {response.status_code} - {response.content.decode()}")

        # POST without branch ID
        response = self.client.post(
            reverse('sat-compat-maintenance-list'),
            data={'name': 'Test plan', 'add': []},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertIn('Required parameter', response.content.decode())

        # POST without name
        response = self.client.post(
            reverse('sat-compat-maintenance-list') + '?branch_id=' + constants.remote_branch_uc,
            data={'add': []},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.json(), {'name': ['This field is required.']})

        # POST without list of things to add
        response = self.client.post(
            reverse('sat-compat-maintenance-list') + '?branch_id=' + constants.remote_branch_uc,
            data={'name': 'Test plan'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.json(), {'add': ['This field is required.']})

        # POST with failures in add data
        response = self.client.post(
            reverse('sat-compat-maintenance-list') + '?branch_id=' + constants.remote_branch_uc,
            data={'name': 'Test plan', 'add': [
                {'system_id': constants.host_01_inid},  # no rule_id
                {'rule_id': 'unknown rule', 'system_id': constants.host_01_inid},  # unknown rule
                {'rule_id': constants.second_rule, 'system_id': 'Foonly 3000'},  # invalid system_id
            ]},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.json(), {'add': [
            {'rule_id': ['This field is required.']},
            {'rule_id': ["Rule with ID 'unknown rule' does not exist"]},
            {'system_id': ["Must be a valid UUID."]},
        ]})

    def test_maintenance_update_simple(self):
        # No branch ID, no update.
        response = self.client.put(
            # Special construction because put method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}),
            data={'name': 'Update plan name'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

        # Can't find a nonexistent plan.
        response = self.client.put(
            # Special construction because put method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}),
            data={'name': 'Update plan name'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

        # Just update the plan's name
        response = self.client.put(
            # Special construction because put method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}) + '?branch_id=' + constants.remote_branch_uc,
            data={'name': 'Update plan name'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        # Name should be changed, and everything else is the same.
        self.assertIn('maintenance_id', json_data)
        self.assertEqual(json_data['maintenance_id'], 1)
        self.assertIn('remote_branch', json_data)
        self.assertEqual(json_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('name', json_data)
        self.assertEqual(json_data['name'], 'Update plan name')
        self.assertIn('created_by', json_data)
        self.assertEqual(json_data['created_by'], 'testing')
        self.assertIn('overdue', json_data)
        self.assertEqual(json_data['overdue'], False)
        self.assertIn('silenced', json_data)
        self.assertEqual(json_data['silenced'], False)
        self.assertIn('hidden', json_data)
        self.assertEqual(json_data['hidden'], False)
        self.assertIn('allow_reboot', json_data)
        self.assertEqual(json_data['allow_reboot'], True)
        self.assertIn('actions', json_data)
        self.assertEqual(len(json_data['actions']), 2)
        self.assertEqual(json_data['actions'][0]['id'], 1)
        self.assertEqual(json_data['actions'][0]['rule']['id'], constants.active_rule)
        self.assertEqual(json_data['actions'][0]['system']['display_name'], constants.host_01_name)
        self.assertEqual(json_data['actions'][1]['id'], 2)
        self.assertEqual(json_data['actions'][1]['rule']['id'], constants.second_rule)
        self.assertEqual(json_data['actions'][1]['system']['display_name'], constants.host_01_name)

    def test_maintenance_update_edit_actions(self):
        # Delete an existing action, update the action list to include that
        # action (redundant but valid as a test), and add a new action
        response = self.client.put(
            # Special construction because put method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}) + '?branch_id=' + constants.remote_branch_uc,
            data={
                'delete': [2],
                'actions': [1],
                'add': [
                    {'rule_id': constants.second_rule, 'system_id': constants.host_05_inid}
                ]
            },
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, dict)
        self.assertIn('maintenance_id', json_data)
        self.assertEqual(json_data['maintenance_id'], 1)
        self.assertIn('remote_branch', json_data)
        self.assertEqual(json_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('name', json_data)
        self.assertEqual(json_data['name'], 'Test plan')  # not updated as above
        self.assertIn('created_by', json_data)
        self.assertEqual(json_data['created_by'], 'testing')
        self.assertIn('overdue', json_data)
        self.assertEqual(json_data['overdue'], False)
        self.assertIn('silenced', json_data)
        self.assertEqual(json_data['silenced'], False)
        self.assertIn('hidden', json_data)
        self.assertEqual(json_data['hidden'], False)
        self.assertIn('allow_reboot', json_data)
        self.assertEqual(json_data['allow_reboot'], True)
        self.assertIn('actions', json_data)
        self.assertEqual(len(json_data['actions']), 2)
        self.assertEqual(json_data['actions'][0]['rule']['id'], constants.active_rule)
        self.assertEqual(json_data['actions'][0]['system']['display_name'], constants.host_01_name)
        self.assertEqual(json_data['actions'][1]['rule']['id'], constants.second_rule)
        self.assertEqual(json_data['actions'][1]['system']['display_name'], constants.host_05_name)

        # Failure without the branch ID
        response = self.client.put(
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}),
            data={
                'delete': [2],
                'actions': [1],
                'add': [
                    {'rule_id': constants.second_rule, 'system_id': constants.host_05_inid}
                ]
            },
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

        # If we specify an action ID that doesn't exist we should get a 400
        response = self.client.put(
            # Special construction because put method doesn't separate
            # post data from query data.
            reverse('sat-compat-maintenance-detail', kwargs={'pk': 1}) + '?branch_id=' + constants.remote_branch_uc,
            data={
                'delete': [2],
                'actions': [1, 42],
                'add': [
                    {'rule_id': constants.second_rule, 'system_id': constants.host_05_inid}
                ]
            },
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

    @override_settings(REMEDIATIONS_URL=REMEDIATIONS_URL)
    @responses.activate
    def test_get_playbook(self):
        # Set up our fake playbook response
        def check_playbook_inputs(request):
            # Hard to generalise this since it needs to only take a single
            # argument but has to have access to self for test assertions.
            try:
                json = loads(request.body)
            except ValueError:
                self.fail(f"Data '{request.body}' not passed in JSON format")
            self.assertIsInstance(json, dict)
            self.assertEqual(sorted(json.keys()), ['auto_reboot', 'issues'])
            self.assertIsInstance(json['auto_reboot'], bool)
            self.assertIsInstance(json['issues'], list)
            # General issue list testing:
            for issue in json['issues']:
                self.assertIn('id', issue)
                self.assertIsInstance(issue['id'], str)
                self.assertIn('systems', issue)
                self.assertIsInstance(issue['systems'], list)
                self.assertTrue(
                    ('resolution' in issue and isinstance(issue['resolution'], str))
                    or 'resolution' not in issue
                )
            # Specific issue list testing
            # Note that we've removed the action on a rule without a playbook
            self.assertEqual(len(json['issues']), 1)
            self.assertEqual(json['issues'][0]['id'], 'advisor:test|Active_rule')
            self.assertEqual(json['issues'][0]['systems'], [constants.host_01_uuid])
            self.assertNotIn('resolution', json['issues'][0])
            # Now return something useful for the response callback
            return (200, {'content_type': 'text/vnd-yaml'}, TEST_PLAYBOOK)

        responses.add_callback(
            responses.POST, PLAYBOOK_URL,
            callback=check_playbook_inputs,
            content_type='application/json',  # input content type here
        )

        # Check the playbook
        response = self.client.get(
            reverse('sat-compat-maintenance-playbook', kwargs={'pk': 1}),
            HTTP_ACCEPT='application/json',
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 200, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, 'application/json')
        self.assertTrue(re.match(r'attachment;filename=\"testplan-1-\d*\.yml\"',
                                 response.headers['content-disposition']))

        self.assertEqual(response.headers['Content-Type'], 'text/vnd.yaml; charset=utf-8')
        # self.assertEqual(response.content.decode(), playbook)
        responded_playbook = response.content.decode()
        self.assertIn('Red Hat Insights has recommended', responded_playbook)
        self.assertNotIn(r'\\n', responded_playbook)  # Should have CRs in it

        # Check the plays
        response = self.client.get(
            reverse('sat-compat-maintenance-plays', kwargs={'pk': 1}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json_data = response.json()
        self.assertIsInstance(json_data, list)
        # Test structure
        for action in json_data:
            self.assertIsInstance(action, dict)
            self.assertIn('system_type_id', action)
            self.assertEqual(action['system_type_id'], 105)
            self.assertIn('rule', action)
            self.assertIsInstance(action['rule'], dict)
            self.assertIn('ansible_resolutions', action)
            self.assertIsInstance(action['ansible_resolutions'], list)
        # Test specific details
        self.assertEqual(len(json_data), 1)
        self.assertEqual(json_data[0]['rule']['rule_id'], constants.active_rule)
        self.assertEqual(json_data[0]['ansible_resolutions'][0]['resolution_type'], 'fixit')
        self.assertEqual(json_data[0]['ansible_resolutions'][0]['resolution_risk'], 1)
        # No playbooks, so no Ansible resolutions...?  or should we filter
        # these out?

        # Missing maintenance plan
        response = self.client.get(
            reverse('sat-compat-maintenance-playbook', kwargs={'pk': 12}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

    @override_settings(REMEDIATIONS_URL=REMEDIATIONS_URL)
    @responses.activate
    def test_get_playbook_bad_remediations(self):
        # Set up our fake playbook response
        responses.add(
            responses.POST, PLAYBOOK_URL, status=403
        )

        # Check the playbook
        response = self.client.get(
            reverse('sat-compat-maintenance-playbook', kwargs={'pk': 1}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

    @override_settings(REMEDIATIONS_URL=REMEDIATIONS_URL)
    @responses.activate
    def test_get_playbook_remediations_connection_fail(self):
        # Set up our fake playbook response
        responses.add(
            responses.POST, PLAYBOOK_URL, body=ConnectionError("Test raises an exception")
        )

        # Check the playbook
        response = self.client.get(
            reverse('sat-compat-maintenance-playbook', kwargs={'pk': 1}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

    @responses.activate
    def test_get_playbook_no_remediations_url(self):
        # Set up our fake playbook response
        responses.add(
            responses.POST, PLAYBOOK_URL,
            body=TEST_PLAYBOOK,
            headers={'Content-Type': 'text/vnd-yaml'},
        )

        # Check the playbook
        response = self.client.get(
            reverse('sat-compat-maintenance-playbook', kwargs={'pk': 1}),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

    def test_set_playbook_for_action(self):
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': constants.active_rule, 'system_type_id': 105
            }),
            data={'resolution_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, f"Response: {response.status_code} - {response.content.decode()}")
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # The content of the response really doesn't matter here, because it
        # doesn't contain data we can check.

        # Nonexistent plan ID gets 404
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 10, 'rule_id': constants.active_rule, 'system_type_id': 105
            }),
            data={'resolution_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # Nonexistent rule ID gets 404
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': 'test|mangled_rule', 'system_type_id': 105
            }),
            data={'resolution_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # Rule that isn't in an action in this plan gets 404
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': constants.acked_rule, 'system_type_id': 105
            }),
            data={'resolution_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # Nonexistent system type gets 404
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': constants.active_rule, 'system_type_id': 86
            }),
            data={'resolution_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # system type not related to the remediation of an action gets 404
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': constants.active_rule, 'system_type_id': 404
            }),
            data={'resolution_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, f"Response: {response.status_code} - {response.content.decode()}")

        # Bad form data gets 400
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': constants.active_rule, 'system_type_id': 105
            }),
            data={'remediation_type': 'fixit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")

        # Nonexistent remediation type for this rule's playbook gets 400 (form error)
        response = self.client.put(
            reverse('sat-compat-maintenance-plays-set-playbook', kwargs={
                'pk': 1, 'rule_id': constants.active_rule, 'system_type_id': 105
            }),
            data={'resolution_type': 'mangleit'},
            content_type=constants.json_mime,
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, f"Response: {response.status_code} - {response.content.decode()}")


class MaintenanceDupInsightsIDViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'sat_maintenance', 'sat_dup_insights_id_host',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_maintenance_list(self):
        response = self.client.get(
            reverse('sat-compat-maintenance-list'), **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        list_data = response.json()
        self.assertIsInstance(list_data, list)
        # Fixture data in 0 and 1
        self.assertEqual(len(list_data), 2)
        plan = list_data[0]
        self.assertIn('name', plan)
        self.assertEqual(plan['name'], 'Test plan')
        self.assertIn('remote_branch', plan)
        # And the Satellite ID is magically transmuted to lower case
        self.assertEqual(plan['remote_branch'], constants.remote_branch_lc)
        self.assertIn('maintenance_id', plan)
        self.assertEqual(plan['maintenance_id'], 1)
        self.assertIn('created_by', plan)
        self.assertEqual(plan['created_by'], 'testing')
        self.assertIn('overdue', plan)
        self.assertEqual(plan['overdue'], False)
        self.assertIn('silenced', plan)
        self.assertEqual(plan['silenced'], False)
        self.assertIn('hidden', plan)
        self.assertEqual(plan['hidden'], False)
        self.assertIn('allow_reboot', plan)
        self.assertEqual(plan['allow_reboot'], True)

        # No auth, no service.
        response = self.client.get(
            reverse('sat-compat-maintenance-list'),
        )
        self.assertEqual(response.status_code, 403, response.content.decode())
