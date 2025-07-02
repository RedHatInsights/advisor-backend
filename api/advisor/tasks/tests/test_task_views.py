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

import responses
import yaml
from django.test import TestCase, override_settings
from django.urls import reverse

from tasks.models import Host, Task
from api.permissions import (
    auth_header_for_testing, turnpike_auth_header_for_testing
)
from api.tests import update_stale_dates
from tasks.tests import constants, task_creation_data
from tasks.tests.test_system_views import pd_connection_status_response
from tasks.utils import requirements, playbook_dispatcher_connection_status_path

INVENTORY_SERVER_URL = "http://localhost/api/inventory/v1"
PD_TEST_URL = "http://localhost/"
PD_TEST_RECIP_STATUS_URL = PD_TEST_URL + playbook_dispatcher_connection_status_path
PDAPI_PSK = 'test'

CONNECTED_REQ = requirements['system_connected']['alert']
RHEL_REQ = requirements['rhel']['alert']
KNOWN_OS_REQ = requirements['known_os']['alert']
OS_V7_REQ = requirements['os_v7']['alert']
OS_V7_V8_REQ = requirements['os_v7_v8']['alert']
CENTOS_REQ = requirements['centos']['alert']
BOOTC_REQ = requirements['bootc_image']['alert']
RHELAI_REQ = requirements['rhelai_image']['alert']
NOT_RHELAI_REQ = requirements['not_rhelai_image']['alert']


class TaskViewTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    std_auth = auth_header_for_testing()
    alt_auth = auth_header_for_testing(org_id=constants.alternate_org, account=constants.alternate_acct)
    int_auth = turnpike_auth_header_for_testing()

    def test_task_list(self):
        # No auth, no access (we need to test for RBAC)
        res = self.client.get(reverse('tasks-task-list'))
        self.assertEqual(res.status_code, 403)
        # Standard auth is good
        res = self.client.get(
            reverse('tasks-task-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        page = res.json()
        self.assertIsInstance(page, dict)
        self.assertIn('links', page)
        self.assertIsInstance(page['links'], dict)
        self.assertIn('meta', page)
        self.assertIsInstance(page['meta'], dict)
        self.assertIn('count', page['meta'])
        self.assertEqual(page['meta']['count'], 2)
        self.assertIn('data', page)
        data = page['data']
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)
        # Test all properties for first test task
        self.assertIsInstance(data[0], dict)
        self.assertIn('slug', data[0])
        self.assertEqual(data[0]['slug'], constants.task_slug)
        self.assertIn('title', data[0])
        self.assertEqual(data[0]['title'], constants.task_title)
        self.assertIn('type', data[0])
        self.assertEqual(data[0]['type'], 'Ansible')
        self.assertIn('description', data[0])
        self.assertEqual(data[0]['description'], constants.task_description)
        self.assertIn('publish_date', data[0])
        self.assertEqual(data[0]['publish_date'], constants.task_publish_date)
        self.assertNotIn('playbook', data[0])
        # Just test important differences for other tasks
        self.assertEqual(data[1]['slug'], constants.parameters_task_slug)
        self.assertIn('parameters', data[1])
        res_params = data[1]['parameters']
        self.assertIsInstance(res_params, list)
        self.assertEqual(len(res_params), 4)

        const_parameters = getattr(constants, 'parameters')
        for attribute in const_parameters[1].keys():
            self.assertIn(attribute, res_params[0])

        for const_id in const_parameters.keys():
            res_index = (const_id - 1) * 3 % 4
            res_key = res_params[res_index]['key']
            const_key = const_parameters[const_id]['key']

            # Comparing keys of returned and constant parameters to ensure correct ordering
            self.assertEqual(res_key, const_key,
                             f'Parameter on index {res_index} has key {res_key} instead of {const_key}')

    def test_task_detail(self):
        # No auth, no access (we need to test for RBAC)
        res = self.client.get(
            reverse('tasks-task-detail', kwargs={'slug': constants.task_slug})
        )
        self.assertEqual(res.status_code, 403)
        # Standard auth is good
        res = self.client.get(
            reverse('tasks-task-detail', kwargs={'slug': constants.task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsInstance(data, dict)
        self.assertIn('slug', data)
        self.assertEqual(data['slug'], constants.task_slug)
        self.assertIn('title', data)
        self.assertEqual(data['title'], constants.task_title)
        self.assertIn('type', data)
        self.assertEqual(data['type'], 'Ansible')
        self.assertIn('description', data)
        self.assertEqual(data['description'], constants.task_description)
        self.assertIn('publish_date', data)
        self.assertEqual(data['publish_date'], constants.task_publish_date)
        self.assertNotIn('playbook', data)

        # Nonexistent task should give a 404
        res = self.client.get(
            reverse('tasks-task-detail', kwargs={'slug': constants.bad_task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

    def test_task_no_public_edit(self):
        # Not allowed to edit tasks, even with internal auth data
        # Standard API auth is denied - method not allowed
        res = self.client.post(
            reverse('tasks-task-list'), **self.std_auth
        )
        self.assertEqual(res.status_code, 405, res.content.decode())
        # Internal API auth is denied - Turnpike auth doesn't have the right
        # fields to look like it's authenticated.
        res = self.client.post(
            reverse('tasks-task-list'), **self.int_auth
        )
        self.assertEqual(res.status_code, 403, res.content.decode())

    def test_task_playbook(self):
        # No auth, no access (we need to test for RBAC)
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.task_slug})
        )
        self.assertEqual(res.status_code, 403)
        # Standard auth is good
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        self.assertEqual(res.content, b'---\n- name: ping\n  hosts: localhost\n  tasks:\n    - ping:\n')

        # Standard auth but nonexistent task slug
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.bad_task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404)

        # If an ordinary system requests a playbook that has parameters, but
        # no token is given, no vars get inserted into it:
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.parameters_task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        playbook = yaml.load(res.content, yaml.Loader)[0]

        # If an invalid token is given, but it can't be found for any executed task, it's ignored
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.parameters_task_slug}),
            data={'token': 'cc48dad0-8dd2-4463-a58e-465d90fb4ce2'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        playbook = yaml.load(res.content, yaml.Loader)[0]

        # Even if a token exists, if it's not for this task we get no parameters
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.parameters_task_slug}),
            data={'token': constants.bash_executed_task_token},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        playbook = yaml.load(res.content, yaml.Loader)[0]

        # Only when the token belongs to an execution of this task do we get
        # parameters filled out.
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.parameters_task_slug}),
            data={'token': constants.executed_task_parameters_token},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        # This is the last line in the playbook
        last_line = '- convert2rhel: null\n'
        self.assertTrue(res.content.endswith(bytes(last_line, 'utf-8')))
        playbook = yaml.load(res.content, yaml.Loader)[0]
        # Because this is a test of parameters, all parameters have been given values.
        self.assertIn('content_vars', playbook['vars'])
        self.assertEqual(
            playbook['vars']['content_vars'][constants.param_1_key],
            constants.executed_task_parameter_1_value)
        self.assertEqual(
            playbook['vars']['content_vars'][constants.param_2_key],
            constants.executed_task_parameter_2_value)
        self.assertEqual(
            playbook['vars']['content_vars'][constants.param_3_key],
            constants.executed_task_parameter_3_value)
        self.assertEqual(
            playbook['vars']['content_vars'][constants.param_4_key],
            constants.executed_task_parameter_4_value)
        # The dummy key hasn't been changed or removed
        self.assertEqual(playbook['vars']['key'], 'value')
        # After modification check the last line is still the same, to give hope of successful signature validation
        modified_playbook = '---\n' + yaml.dump([playbook], indent=2, sort_keys=False)
        self.assertTrue(modified_playbook.endswith(last_line))

        # Nonexistent task should get 404 on playbook
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.bad_task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404, res.content.decode())
        # Unpublished task should get the playbook though
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.draft_task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())

    @override_settings(INVENTORY_SERVER_URL=INVENTORY_SERVER_URL)
    @responses.activate
    def test_task_playbook_with_host_fqdn(self):
        responses.get(
            INVENTORY_SERVER_URL + '/hosts/' + constants.host_04_uuid, status=200,
            json={
                "total": 1,
                "count": 1,
                "page": 1,
                "per_page": 50,
                "results": [
                    {
                        "fqdn": "example.system.com",
                        "ansible_host": None
                    }
                ]
            }
        )
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.task_slug}),
            data={'inventory_id': constants.host_04_uuid},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        playbook = yaml.load(res.content, yaml.Loader)[0]
        self.assertEqual(playbook['hosts'], ["example.system.com"])

    @override_settings(INVENTORY_SERVER_URL=INVENTORY_SERVER_URL)
    @responses.activate
    def test_task_playbook_with_host_ansible(self):
        responses.get(
            INVENTORY_SERVER_URL + '/hosts/' + constants.host_04_uuid, status=200,
            json={
                "total": 1,
                "count": 1,
                "page": 1,
                "per_page": 50,
                "results": [
                    {
                        "fqdn": "example.system.com",
                        "ansible_host": "example.ansible.system.com"
                    }
                ]
            }
        )
        res = self.client.get(
            reverse('tasks-task-playbook', kwargs={'slug': constants.task_slug}),
            data={'inventory_id': constants.host_04_uuid},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], constants.yaml_mime)
        #  Ansible host takes precedence over fqdn
        playbook = yaml.load(res.content, yaml.Loader)[0]
        self.assertEqual(playbook['hosts'], ["example.ansible.system.com"])

    def test_task_systems_requirements(self):
        update_stale_dates()

        # Basic request of a task with no filters - no requirements
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': constants.task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        # Structure is paginated
        page = res.json()
        self.assertIn('meta', page)
        self.assertIn('links', page)
        self.assertIn('data', page)
        hosts = page['data']
        for host in hosts:
            self.assertIn('requirements', host)
            self.assertEqual(host['requirements'], [])

        # Basic request of a task with filters but all_systems not set - no systems match
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'convert2rhel_check'}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 0)

        # Basic request of a task with filters and all_systems set - all
        # hosts have requirements lists
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'convert2rhel_check'}),
            data={'all_systems': 'true'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        # sorted by... display name?
        self.assertEqual(hosts[0]['display_name'], constants.host_0b_name)
        self.assertEqual(hosts[0]['requirements'], [OS_V7_REQ])
        self.assertEqual(hosts[0]['connected'], False)  # Without PD available, all disconnected
        self.assertEqual(hosts[1]['display_name'], constants.host_e1_name)
        self.assertEqual(hosts[1]['requirements'], [CENTOS_REQ, OS_V7_REQ])
        self.assertEqual(hosts[2]['display_name'], constants.host_06_name)
        self.assertEqual(hosts[2]['requirements'], [CENTOS_REQ, OS_V7_REQ])
        self.assertEqual(hosts[3]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[3]['requirements'], [CENTOS_REQ])
        self.assertEqual(hosts[3]['connected'], False)  # Without PD available, all disconnected
        self.assertEqual(hosts[4]['display_name'], constants.host_03_name)
        self.assertEqual(hosts[4]['requirements'], [CENTOS_REQ])
        self.assertEqual(hosts[5]['display_name'], constants.host_04_name)
        self.assertEqual(hosts[5]['requirements'], [CENTOS_REQ])

        # RHINENG-14779 - hosts should have the last_check_in field
        for host in hosts:
            self.assertIn('last_check_in', host)

        # Parameter errors should generate a 400
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'convert2rhel_check'}),
            data={'os_version': 'kludge', 'all_systems': 'biscuit'},
            **self.std_auth
        )
        error = res.content.decode()
        self.assertEqual(res.status_code, 400, error)
        self.assertIn(
            "The value is required to be one of the following "
            "values: ", error
        )

        # Nonexistent task should just return a 404
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': constants.bad_task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 404, res.content.decode())

    def test_task_systems_host_group_filtering(self):
        update_stale_dates()

        # Test filtering log4shell systems on matching host group
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'groups': 'group01'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[0]['groups'][0]['name'], 'group01')

        # Test filtering log4shell systems on matching host group & display name
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'groups': 'group01', 'display_name': 'system01'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[0]['groups'][0]['name'], 'group01')

        # Test filtering log4system systems on non-matching host group & display name
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'groups': 'nosystems', 'display_name': 'system01'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 0)

    def test_task_systems_requirements_bootc_image(self):
        update_stale_dates()
        # Note, the bootc image system is in the alternate account
        # No filter applied so expect to see all systems in the alternate account
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            **self.alt_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 3)
        # host_02, 07 and rhelai_host are all matched because there are no requirements on log4shell, yet
        self.assertEqual(hosts[0]['id'], constants.rhelai_host_uuid)
        self.assertEqual(hosts[0]['display_name'], constants.rhelai_host_name)
        self.assertNotEqual(hosts[0]['system_profile'].get('bootc_status', None), None)
        self.assertEqual(hosts[0]['system_profile']['bootc_status']['booted']['image'], constants.rhelai_image)
        self.assertEqual(hosts[1]['id'], constants.host_02_uuid)
        self.assertEqual(hosts[1]['system_profile'].get('bootc_status', None), None)
        self.assertEqual(hosts[1]['display_name'], constants.host_02_name)
        self.assertEqual(hosts[2]['id'], constants.host_07_uuid)
        self.assertEqual(hosts[2]['display_name'], constants.host_07_name)
        self.assertNotEqual(hosts[2]['system_profile'].get('bootc_status', None), None)
        self.assertEqual(hosts[2]['system_profile']['bootc_status']['booted']['image'], constants.bootc_image)

        # Now, make the log4shell task have the same requirements as the bootc_upgrade task,
        # such that eligible systems are bootc image systems but NOT RHEL AI image systems.
        log4shell = Task.objects.get(slug=constants.task_slug)
        log4shell.filter_message = 'Only eligible for bootc image systems'
        log4shell.filters = [
            'bootc_image',
            'not_rhelai_image'
        ]
        log4shell.save()
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            **self.alt_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 1)
        # Only host_07 is matched because its a bootc image system but not a RHEL AI image system
        # rhelai_host is not matched because it is a RHEL AI image system
        self.assertEqual(hosts[0]['id'], constants.host_07_uuid)
        self.assertEqual(hosts[0]['requirements'], [])
        self.assertEqual(hosts[0]['system_profile']['bootc_status']['booted']['image'], constants.bootc_image)

        # Add the all_systems parameter and expect host_02 requirements to say it must be a bootc image
        # and rhelai_host requirements to say it must not be a RHEL AI image
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'all_systems': True}, **self.alt_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 3)
        self.assertEqual(hosts[0]['id'], constants.rhelai_host_uuid)
        self.assertEqual(hosts[0]['requirements'], [NOT_RHELAI_REQ])
        self.assertEqual(hosts[1]['id'], constants.host_02_uuid)
        self.assertEqual(hosts[1]['requirements'], [BOOTC_REQ])
        self.assertEqual(hosts[2]['id'], constants.host_07_uuid)
        self.assertEqual(hosts[2]['requirements'], [])

        # For completeness add the os_v7_v8 filter and expect no hosts to be matched because host_07 is RHEL9
        log4shell.filters.append('os_v7_v8')
        log4shell.save()
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            **self.alt_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 0)

    def test_task_systems_requirements_rhelai_image(self):
        update_stale_dates()

        # Make the log4shell task have the same requirements as the rhel_ai_update task,
        # such that eligible systems are bootc image systems AND RHEL AI image systems
        log4shell = Task.objects.get(slug=constants.task_slug)
        log4shell.filter_message = 'Only eligible for RHEL AI image systems'
        log4shell.filters = [
            'bootc_image',
            'rhelai_image'
        ]
        log4shell.save()

        # Only rhelai_host is matched because its a RHEL AI image system
        # host_02 and 07 are not RHEL AI image systems (even though host_07 is a bootc image system)
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            **self.alt_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['id'], constants.rhelai_host_uuid)
        self.assertEqual(hosts[0]['requirements'], [])
        self.assertEqual(hosts[0]['system_profile']['bootc_status']['booted']['image'], constants.rhelai_image)

        # Use the all_systems parameter and expect host_02 to have the bootc image requirement
        # and host_07 to have RHEL AI image requirement
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'all_systems': True}, **self.alt_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 3)
        self.assertEqual(hosts[0]['id'], constants.rhelai_host_uuid)
        self.assertEqual(hosts[0]['requirements'], [])
        self.assertNotEqual(hosts[0]['system_profile'].get('bootc_status', None), None)
        self.assertEqual(hosts[0]['system_profile']['bootc_status']['booted']['image'], constants.rhelai_image)
        self.assertEqual(hosts[1]['id'], constants.host_02_uuid)
        self.assertEqual(hosts[1]['requirements'], [BOOTC_REQ])
        self.assertEqual(hosts[1]['system_profile'].get('bootc_status', None), None)
        self.assertEqual(hosts[2]['id'], constants.host_07_uuid)
        self.assertEqual(hosts[2]['requirements'], [RHELAI_REQ])
        self.assertNotEqual(hosts[2]['system_profile'].get('bootc_status', None), None)
        self.assertEqual(hosts[2]['system_profile']['bootc_status']['booted']['image'], constants.bootc_image)

        # Try some different RHEL AI image names to confirm they are matched
        rhelai_host = Host.objects.get(id=constants.rhelai_host_uuid)
        other_rhelai_images = [
            'registry.stage.redhat.io/rhelai1/bootc-intel-rhel9:1.4.2-1740747417',
            'registry.redhat.io/rhelai1/granite-7b-starter:1.4-1739210683'
            'registry.access.redhat.com/rhelai2/bootc-amd-rhel10:2.0'
        ]
        for rhelai_image in other_rhelai_images:
            rhelai_host.system_profile['bootc_status']['booted']['image'] = rhelai_image
            rhelai_host.save()
            res = self.client.get(
                reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
                **self.alt_auth
            )
            self.assertEqual(res.status_code, 200, res.content.decode())
            hosts = res.json()['data']
            self.assertEqual(len(hosts), 1)
            self.assertEqual(hosts[0]['id'], constants.rhelai_host_uuid)
            self.assertEqual(hosts[0]['requirements'], [])
            self.assertEqual(hosts[0]['system_profile']['bootc_status']['booted']['image'], rhelai_image)

        # Try some non RHEL AI images to confirm they are not matched
        non_rhelai_images = [
            'registry.redhat.io/rhel9/rhel-bootc:9.4',
            'registry.access.redhat.com/rhel10/rhel-bootc:10.0-1737064208',
        ]
        for non_rhelai_image in non_rhelai_images:
            rhelai_host.system_profile['bootc_status']['booted']['image'] = non_rhelai_image
            rhelai_host.save()
            res = self.client.get(
                reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
                **self.alt_auth
            )
            self.assertEqual(res.status_code, 200, res.content.decode())
            hosts = res.json()['data']
            self.assertEqual(len(hosts), 0)

    def test_task_systems_requirements_rhel_os_versions(self):
        update_stale_dates()

        # Apply RHEL filter to log4shell Task and change system01 to be a RHEL6 system
        log4shell = Task.objects.get(slug=constants.task_slug)
        log4shell.filter_message = 'Only eligible for RHEL systems'
        log4shell.filters = ['rhel']
        log4shell.save()
        system01 = Host.objects.get(id=constants.host_01_uuid)
        system01.system_profile['operating_system'] = {'name': 'RHEL', 'major': 6, 'minor': 5}
        system01.save()

        # All RHEL systems meet the requirements, including RHEL6 (host_01_uuid) and RHEL9 (host_e1_uuid)
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}), **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 5)
        # host_01_uuid and host_e1_uuid meet the requirements
        self.assertTrue([host['id'] for host in hosts
                         if host['id'] in (constants.host_01_uuid, constants.host_e1_uuid)])

        # Apply RHEL & os_v7_v8 filters to log4shell Task and check only RHEL 7 & 8 systems meet the requirements
        log4shell.filters = ['rhel', 'os_v7_v8']
        log4shell.save()
        res = self.client.get(reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}), **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 3)
        # host_01_uuid (RHEL6) and host_e1_uuid (RHEL9) no longer meet the requirements
        self.assertFalse([host['id'] for host in hosts
                          if host['id'] in (constants.host_01_uuid, constants.host_e1_uuid)])

        # Use all_systems parameter to see why hosts system05, system01 and edge01 don't meet the requirements
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'all_systems': True, 'sort': 'os'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 7)
        self.assertEqual(hosts[0]['display_name'], 'centos.example.com')
        self.assertEqual(hosts[0]['requirements'], [RHEL_REQ])
        self.assertEqual(hosts[0]['groups'], [])
        self.assertEqual(hosts[0]['connection_type'], 'direct')
        # system05 isn't RHEL and isn't connected via RHC / Satellite, so it doesn't meet those requirements
        self.assertEqual(hosts[1]['display_name'], constants.host_05_name)
        self.assertEqual(hosts[1]['requirements'], [RHEL_REQ, CONNECTED_REQ])
        self.assertEqual(hosts[1]['groups'], [])
        self.assertEqual(hosts[1]['connection_type'], 'none')
        # system01 is RHEL6 so doesn't meet the requirements of being RHEL7 or 8
        self.assertEqual(hosts[2]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[2]['requirements'], [OS_V7_V8_REQ])
        self.assertEqual(hosts[2]['groups'][0]['name'], 'group01')
        self.assertEqual(hosts[2]['connection_type'], 'direct')
        # edge01 is RHEL9 so doesn't meet the requirements of being RHEL7 or 8
        self.assertEqual(hosts[6]['display_name'], constants.host_e1_name)
        self.assertEqual(hosts[6]['requirements'], [OS_V7_V8_REQ])
        self.assertEqual(hosts[6]['groups'], [])
        self.assertEqual(hosts[6]['connection_type'], 'satellite')

        # set an empty operating_system field for system01's system_profile to get os_version = Unknown OS name
        # system01 should sort last in the list and have requirements that it must have a known OS
        system01.system_profile['operating_system'] = {}
        system01.save()
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'all_systems': True, 'sort': 'os'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 7)
        self.assertEqual(hosts[6]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[6]['os_version'], 'Unknown OS name')
        self.assertEqual(hosts[6]['requirements'], [KNOWN_OS_REQ])

        # delete the operating_system from system01's system_profile to get os_version = Unknown operating system
        # system01 should still have requirements that it must have a known OS
        del system01.system_profile['operating_system']
        system01.save()
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'all_systems': True, 'sort': 'os'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 7)
        self.assertEqual(hosts[6]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[6]['os_version'], 'Unknown operating system')
        self.assertEqual(hosts[6]['requirements'], [KNOWN_OS_REQ])

        # Remove the filter requirements from log4shell and system01 should meet all requirements now
        # because having an unknown OS is ok for running a task without filters
        # system05 still won't meet requirements of eligible systems because it isn't connected via RHC / Satellite
        log4shell.filter_message = None
        log4shell.filters = []
        log4shell.save()
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'all_systems': True, 'sort': 'os'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 7)
        # system05 isn't connected so still isn't an eligible system
        self.assertEqual(hosts[1]['display_name'], constants.host_05_name)
        self.assertEqual(hosts[1]['requirements'], [CONNECTED_REQ])
        # system01 doesn't have an OS but that's no longer a requirement for running the log4shell task
        self.assertEqual(hosts[6]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[6]['os_version'], 'Unknown operating system')
        self.assertEqual(hosts[6]['requirements'], [])

        # Remove all_systems=true and system05 won't appear in the list of eligible systems but system01 will
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'log4shell'}),
            data={'sort': 'os'},
            **self.std_auth)
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 6)
        # system01 is an eligible system without any unmet requirements
        self.assertEqual(hosts[5]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[5]['os_version'], 'Unknown operating system')
        self.assertEqual(hosts[5]['requirements'], [])
        # system05 isn't an eligible system even for tasks with no requirements
        eligible_host_ids = [x['id'] for x in hosts]
        self.assertNotIn(constants.host_05_uuid, eligible_host_ids)

    def test_task_systems_all_systems_new_rhc_connection(self):
        update_stale_dates()

        # system05 appears with all_systems but fails requirements because its not connected via RHC yet
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'convert2rhel_check'}),
            data={'os_version': '7.9', 'all_systems': 'true'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['display_name'], constants.host_05_name)
        self.assertEqual(hosts[0]['requirements'], ['System must be connected via RHC or Satellite'])

        # Add rhc_client_id attribute to system05 system_profile to simulate a new RHC connection
        system05 = Host.objects.get(id=constants.host_05_uuid)
        system05.system_profile['rhc_client_id'] = "00112233-4455-6677-8899-CCCCCCCCCC05"
        system05.save()

        # Test system05 appears with all_systems with no requirements now because it's connected via RHC
        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': 'convert2rhel_check'}),
            data={'os_version': '7.9', 'all_systems': 'true'},
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['display_name'], constants.host_05_name)
        self.assertEqual(hosts[0]['requirements'], [])

    @responses.activate
    @override_settings(PLAYBOOK_DISPATCHER_URL=PD_TEST_URL, PDAPI_PSK=PDAPI_PSK)
    def test_task_system_list_connection_status_pd_available(self):
        responses.add_callback(
            responses.POST, PD_TEST_RECIP_STATUS_URL,
            content_type=constants.json_mime,
            callback=pd_connection_status_response,
        )
        update_stale_dates()

        res = self.client.get(
            reverse('tasks-task-systems', kwargs={'slug': constants.task_slug}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        hosts = res.json()['data']
        # With PD available, our 'connected' hosts show up as connected
        self.assertEqual(hosts[0]['display_name'], constants.host_0b_name)
        self.assertEqual(hosts[0]['connected'], False)
        self.assertEqual(hosts[1]['display_name'], constants.host_e1_name)
        self.assertEqual(hosts[1]['connected'], False)
        self.assertEqual(hosts[2]['display_name'], constants.host_06_name)
        self.assertEqual(hosts[2]['connected'], False)
        self.assertEqual(hosts[3]['display_name'], constants.host_01_name)
        self.assertEqual(hosts[3]['connected'], True)
        self.assertEqual(hosts[4]['display_name'], constants.host_03_name)
        self.assertEqual(hosts[4]['connected'], True)
        self.assertEqual(hosts[5]['display_name'], constants.host_04_name)
        self.assertEqual(hosts[5]['connected'], False)


class TaskInternalViewTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    ext_auth = auth_header_for_testing()
    int_auth = turnpike_auth_header_for_testing()

    def test_task_list(self):
        # No auth is denied
        res = self.client.get(reverse('internal-tasks-task-list'))
        self.assertEqual(res.status_code, 403, res.content.decode())
        # Standard API auth is denied
        res = self.client.get(
            reverse('internal-tasks-task-list'), **self.ext_auth
        )
        self.assertEqual(res.status_code, 403, res.content.decode())
        # Internal API auth is allowed
        res = self.client.get(
            reverse('internal-tasks-task-list'), **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        page = res.json()
        self.assertIsInstance(page, dict)
        self.assertIn('meta', page)
        self.assertIn('links', page)
        self.assertIn('data', page)
        tasklist = page['data']
        # Lists all tasks, even the active=False ones
        self.assertEqual(len(tasklist), 4, tasklist)
        for task in tasklist:
            self.assertIsInstance(task, dict)
            self.assertIn('title', task)
            self.assertIn('type', task)
            self.assertIn('slug', task)
            self.assertIn('playbook', task)
            self.assertIn('filters', task)
        self.assertEqual(tasklist[0]['slug'], constants.task_slug)
        self.assertEqual(tasklist[0]['filters'], [])
        self.assertEqual(tasklist[1]['slug'], constants.draft_task_slug)
        self.assertEqual(tasklist[2]['slug'], constants.bash_task_slug)
        self.assertEqual(tasklist[3]['slug'], constants.parameters_task_slug)

    def test_task_create_update_delete(self):
        # Standard API auth is denied
        res = self.client.post(
            reverse('internal-tasks-task-list'), **self.ext_auth
        )
        self.assertEqual(res.status_code, 403, res.content.decode())
        # Internal API auth is allowed, but no data is invalid
        res = self.client.post(
            reverse('internal-tasks-task-list'), **self.int_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        # Internal API auth is allowed, but bad data is invalid
        res = self.client.post(
            reverse('internal-tasks-task-list'),
            data={'foo': 'bar'},
            **self.int_auth
        )
        self.assertEqual(res.status_code, 400)
        # Create a new task (with parameters):
        res = self.client.post(
            reverse('internal-tasks-task-list'),
            data={
                'slug': 'New_Task',
                'title': 'New Task',
                'description': 'A new task for users to execute',
                'publish_date': '2022-09-02T11:48:50+11:00',
                'playbook': '---\nplaybook text',
                'type': 'A',
                'parameters': [
                    {
                        'key': 'Play_anthem', 'description': 'Should we?',
                        'default': 'false', 'values': ['true', 'false'],
                        'required': True, 'title': 'Play anthem', 'index': 1
                    }, {
                        'key': 'Nationality', 'description': 'Whose?',
                        'default': 'Australian', 'required': False,
                        'values': ['Australian', 'Norwegian', 'French', 'Martian'],
                        'title': 'Nationality', 'index': 2
                    }
                ],
                'filter_message': None,
                'filters': []
            },
            content_type=constants.json_mime,  # have to do this for nested data
            **self.int_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())
        # And the new task can be found in the internal task list:
        res = self.client.get(
            reverse('internal-tasks-task-list'), **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        tasks = res.json()['data']
        self.assertEqual(len(tasks), 5)
        self.assertEqual(tasks[0]['slug'], constants.task_slug)
        self.assertEqual(tasks[1]['slug'], constants.draft_task_slug)
        self.assertEqual(tasks[2]['slug'], constants.bash_task_slug)
        self.assertEqual(tasks[3]['slug'], constants.parameters_task_slug)
        self.assertEqual(len(tasks[3]['parameters']), 4)
        self.assertEqual(tasks[4]['title'], 'New Task')
        self.assertEqual(tasks[4]['type'], 'Ansible')  # Default value
        self.assertFalse(tasks[4]['active'])  # Tasks default to not active
        self.assertEqual(len(tasks[4]['parameters']), 2)
        self.assertEqual(tasks[4]['parameters'][0]['key'], 'Play_anthem')
        self.assertEqual(tasks[4]['parameters'][1]['key'], 'Nationality')
        self.assertIsNone(tasks[4]['filter_message'])
        self.assertEqual(tasks[4]['filters'], [])
        # But because the task is not set active, it is not displayed in the
        # public task list (we only see the standard tasks)
        res = self.client.get(
            reverse('tasks-task-list'), **self.ext_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()['data']
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]['slug'], constants.task_slug)
        self.assertEqual(data[1]['slug'], constants.parameters_task_slug)
        # or by task detail, even if we know the task slug
        res = self.client.get(
            reverse('tasks-task-detail', kwargs={'slug': constants.draft_task_slug}),
            **self.ext_auth
        )
        self.assertEqual(res.status_code, 404)

        # Get the new task by slug:
        res = self.client.get(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'New_Task'}),
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        task = res.json()
        self.assertEqual(task['slug'], 'New_Task')

        # Edit all fields in the new task (even the slug, since it's not a
        # primary key, so changing that doesn't change the references to it):
        res = self.client.put(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'New_Task'}),
            data={
                'slug': 'Updated_Task',
                'title': 'Updated Task',
                'description': 'An updated task for users to execute',
                'publish_date': '2022-09-02T14:37:22+11:00',
                'playbook': '---\nupdated playbook text'
            },
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        task = res.json()
        self.assertEqual(task['slug'], 'Updated_Task')
        self.assertEqual(task['title'], 'Updated Task')
        self.assertEqual(task['description'], 'An updated task for users to execute')
        # The existing parameters should stay the same
        self.assertEqual(len(task['parameters']), 2)

        # Edit only two fields in the new task:
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'Updated_Task'}),
            data={'title': 'More Updated Task', 'active': True, 'type': 'S'},
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        task = res.json()
        self.assertEqual(task['slug'], 'Updated_Task')
        self.assertEqual(task['title'], 'More Updated Task')
        self.assertEqual(task['description'], 'An updated task for users to execute')
        self.assertEqual(task['active'], True)
        self.assertEqual(task['type'], 'Script')
        # The existing parameters should stay the same
        self.assertEqual(len(task['parameters']), 2)
        # And now that it is set active=True, it is visible on the public
        # task list
        res = self.client.get(
            reverse('tasks-task-list'), **self.ext_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()['data']
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]['slug'], constants.task_slug)
        self.assertEqual(data[1]['slug'], 'Updated_Task')  # publish date sort
        self.assertEqual(data[2]['slug'], constants.parameters_task_slug)

        # Edit just the parameters the new task - replaces all of them:
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'Updated_Task'}),
            data={'parameters': [
                {
                    'key': 'Play_anthem', 'description': 'Should we?',
                    'default': 'false', 'required': True, 'values': ['true', 'false']
                }
            ]},
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        task = res.json()
        self.assertEqual(task['slug'], 'Updated_Task')
        self.assertEqual(task['title'], 'More Updated Task')
        self.assertEqual(task['description'], 'An updated task for users to execute')
        self.assertEqual(task['active'], True)
        # The existing parameters should be completely updated
        self.assertEqual(len(task['parameters']), 1)
        self.assertEqual(task['parameters'][0]['key'], 'Play_anthem')

        # Testing with type not present on choices list
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'Updated_Task'}),
            data={'title': 'More Updated Task', 'active': True, 'type': 'K'},
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())

        # Finally, delete it
        res = self.client.delete(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'Updated_Task'}),
            **self.int_auth
        )
        self.assertEqual(res.status_code, 204, res.content.decode())

        # And the new task is not in the internal task list:
        res = self.client.get(
            reverse('internal-tasks-task-list'), **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        tasks = res.json()['data']
        self.assertEqual(len(tasks), 4)
        self.assertEqual(tasks[0]['slug'], constants.task_slug)
        self.assertEqual(tasks[1]['slug'], constants.draft_task_slug)
        self.assertEqual(tasks[2]['slug'], constants.bash_task_slug)
        self.assertEqual(tasks[3]['slug'], constants.parameters_task_slug)

    def test_task_create_update_param_index_uniqueness(self):
        """
        Test that task creation and update is allowed only when parameters have unique indexes.
        """

        # Unique indexes in scope of task a should be allowed
        res = self.client.post(
            reverse('internal-tasks-task-list'),
            data=task_creation_data(2, [1, 2]),
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())

        # Different tasks having the same parameter index should be allowed
        res = self.client.post(
            reverse('internal-tasks-task-list'),
            data=task_creation_data(3, [1, 2]),
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 201, res.content.decode())

        # New task with bad parameter indexes should be rejected
        res = self.client.post(
            reverse('internal-tasks-task-list'),
            data=task_creation_data(4, [1, 1]),
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        self.assertEqual(res.content.decode(),
                         '{"parameters":["Task parameters must have unique indexes for the same task. Index 1 is duplicated."]}')
        # And the new task is not in the internal task list:
        res = self.client.get(
            reverse('internal-tasks-task-list'),
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        tasks = res.json()['data']
        self.assertEqual(len(tasks), 6)
        self.assertEqual(tasks[0]['slug'], constants.task_slug)
        self.assertEqual(tasks[1]['slug'], constants.draft_task_slug)
        self.assertEqual(tasks[2]['slug'], constants.bash_task_slug)
        self.assertEqual(tasks[3]['slug'], constants.parameters_task_slug)
        self.assertEqual(tasks[4]['slug'], "New_Task2")
        self.assertEqual(tasks[5]['slug'], "New_Task3")

        # Updating a task with non-unique indexes should be rejected
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': 'New_Task3'}),
            data=task_creation_data(3, [1, 1]),
            content_type=constants.json_mime,
            **self.int_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        self.assertEqual(res.content.decode(),
                         '{"parameters":["Task parameters must have unique indexes for the same task. Index 1 is duplicated."]}')
        # And the task `New_Task3` should not be updated:
        res = self.client.get(
            reverse('internal-tasks-task-list'),
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())

        self.assertEqual(res.json()['data'][5]['parameters'][0]['index'], 1)
        self.assertEqual(res.json()['data'][5]['parameters'][1]['index'], 2)

    def test_task_edit_filters(self):
        # Nonexistent filters should be warned about
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': constants.task_slug}),
            content_type=constants.json_mime,
            data={
                'filters': ['nonexistent']
            }, **self.int_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        self.assertEqual(res.json(), {'filters': ['"nonexistent" is not a valid choice.']})

        # Blank filter message should be warned about
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': constants.task_slug}),
            content_type=constants.json_mime,
            data={
                'filter_message': '',
                'filters': ['centos']
            }, **self.int_auth
        )
        self.assertEqual(res.status_code, 400, res.content.decode())
        self.assertEqual(res.json(), {'filter_message': ['This field may not be blank.']})

        # Check that the existing task has no filters
        res = self.client.get(
            reverse('internal-tasks-task-detail', kwargs={'slug': constants.task_slug}),
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        task = res.json()
        self.assertEqual(task['filters'], [])
        # Valid filters should be saved
        self.assertIn('centos', requirements)
        self.assertIn('os_v7', requirements)
        res = self.client.patch(
            reverse('internal-tasks-task-detail', kwargs={'slug': constants.task_slug}),
            content_type=constants.json_mime,
            data={
                'filters': ['centos', 'os_v7']
            }, **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        # Now it should have those filters
        res = self.client.get(
            reverse('internal-tasks-task-detail', kwargs={'slug': constants.task_slug}),
            **self.int_auth
        )
        self.assertEqual(res.status_code, 200, res.content.decode())
        task = res.json()
        self.assertEqual(sorted(task['filters']), ['centos', 'os_v7'])
