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

from kessel.inventory.v1beta2 import check_request_pb2

from api import kessel
from api.tests import constants as api_constants


class constants(object):
    standard_org = api_constants.standard_org
    standard_acct = api_constants.standard_acct
    alternate_org = api_constants.alternate_org
    alternate_acct = api_constants.alternate_acct

    # Task constants
    task_id = 1
    task_slug = 'log4shell'
    task_title = 'Log4Shell vulnerability detection'
    task_description = "Detection of log4j usage on a server and whether it may be vulnerable to the 'log4shell' vulnerability"
    task_publish_date = "2022-04-11T03:59:54Z"
    task_severity = 4
    task_severity_name = 'Critical'

    draft_task_id = 2
    draft_task_slug = 'draft'
    draft_task_title = 'Unpublished draft task'
    draft_task_description = 'This is a test task to see if filtering on active status works'

    bash_task_id = 3
    bash_task_slug = 'bash-script'

    parameters_task_id = 4
    parameters_task_slug = 'convert2rhel_check'
    parameters_task_title = 'Use Convert2RHEL to check a system for conversion'
    parameters_task_filter_message = 'Only eligible CentOS 7 systems are shown'
    parameters_task_publish_date = "2023-05-29T23:47:21Z"

    param_1_key = 'extra_repositories'
    param_1_title = 'Enable Extra Repositories'
    param_1_default = 'false'
    param_1_required = False
    param_1_index = 1
    param_2_key = 'repository_names'
    param_2_title = 'Extra Repository Names'
    param_2_default = None
    param_2_required = False
    param_2_index = 4
    param_3_key = 'has_internet_access'
    param_3_title = 'Check for Updates Online'
    param_3_default = 'true'
    param_3_required = True
    param_3_index = 3
    param_4_key = 'organisation_id'
    param_4_title = 'Organisation ID'
    param_4_default = None
    param_4_required = True
    param_4_index = 2

    # Test parameters are indexed in the following order:
    # param_min, param_max, param_max-1, param_max-2, ..., param_min+1
    parameters = {
            1: {
                'key': param_1_key,
                'title': param_1_title,
                'default': param_1_default,
                'required': param_1_required,
                'index': param_1_index
            },
            4: {
                'key': param_4_key,
                'title': param_4_title,
                'default': param_4_default,
                'required': param_4_required,
                'index': param_4_index
            },
            3: {
                'key': param_3_key,
                'title': param_3_title,
                'default': param_3_default,
                'required': param_3_required,
                'index': param_3_index
            },
            2: {
                'key': param_2_key,
                'title': param_2_title,
                'default': param_2_default,
                'required': param_2_required,
                'index': param_2_index
            }
    }

    bad_task_slug = 'lgo4shell'

    # Status constants
    status_running = 'Running'
    status_completed = 'Completed'
    status_completed_with_errors = 'Completed With Errors'
    status_success = 'Success'
    status_failure = 'Failure'
    status_timeout = 'Timeout'
    status_cancelled = 'Cancelled'

    # Executed task constants
    executed_task_id = 1
    executed_task_name = "My Named Task for Log4Shell vulnerability detection"
    executed_task_start_time = '2022-04-11T04:01:26Z'
    executed_task_token = '00112233-4455-6677-8899-aabbccddee01'

    executed_task_id_org_2 = 2

    completed_task_id = 3
    bash_executed_task_id = 4
    bash_executed_task_token = '00112233-4455-6677-8899-aabbccddee04'

    executed_task_parameters_id = 5
    executed_task_parameters_start_time = '2023-05-30T00:25:09Z'
    executed_task_parameters_token = '00112233-4455-6677-8899-aabbccddee05'

    executed_task_parameter_1_value = 'true'
    executed_task_parameter_2_value = 'els,epel'
    executed_task_parameter_3_value = 'true'
    executed_task_parameter_4_value = '1248'

    # Host constants - copied from API tests
    host_01_uuid = api_constants.host_01_uuid
    host_01_name = api_constants.host_01_name
    host_01_clid = '00112233-4455-6677-8899-cccccccccc01'
    host_02_name = api_constants.host_02_name
    host_02_uuid = api_constants.host_02_uuid
    host_03_uuid = api_constants.host_03_uuid
    host_03_name = api_constants.host_03_name
    host_03_clid = '00112233-4455-6677-8899-cccccccccc03'
    host_04_uuid = api_constants.host_04_uuid
    host_04_name = api_constants.host_04_name
    host_04_recip = 'b698ded4-9798-48d9-b1c0-6f30e8fdd815'
    host_04_satid = '82148fc8-afba-44ba-8d48-1d497f4b3b11'
    host_05_uuid = api_constants.host_05_uuid
    host_05_name = api_constants.host_05_name
    host_06_uuid = api_constants.host_06_uuid
    host_06_name = api_constants.host_06_name
    host_06_clid = '00112233-4455-6677-8899-cccccccccc06'
    host_07_name = api_constants.host_07_name
    host_07_uuid = api_constants.host_07_uuid
    host_08_uuid = api_constants.host_08_uuid
    host_08_name = api_constants.host_08_name
    host_08_clid = '00112233-4455-6677-8899-cccccccccc08'
    host_09_uuid = api_constants.host_09_uuid
    host_0a_uuid = api_constants.host_0a_uuid
    host_0b_uuid = '00112233-4455-6677-8899-01234567890b'
    host_0b_name = 'centos.example.com'
    host_e1_uuid = api_constants.host_e1_uuid
    host_e1_name = api_constants.host_e1_name
    host_e1_inid = api_constants.host_e1_inid
    host_e1_said = api_constants.host_e1_said
    rhelai_host_uuid = '02468135-7902-4681-3579-024681357914'
    rhelai_host_name = 'rhelai.example.org'

    rhelai_image = 'registry.redhat.io/rhelai1/bootc-aws-nvidia-rhel9:1.4'  # RHEL AI image name used in fixture
    bootc_image = '192.168.124.1:5000/bootc-insights:latest'  # bootc image name used in fixture

    job_1_id = 1
    job_1_run_id = '00112233-4455-6677-8899-52554e494401'  # RUNID\x01
    job_1_rhc_client_id = '00112233-4455-6677-8899-52554e494401'  # test RHC Client ID
    job_2_id = 2
    job_2_run_id = '00112233-4455-6677-8899-52554e494403'  # RUNID\x03 for sys 3
    job_3_id = 3
    job_3_run_id = '00112233-4455-6677-8899-52554e494431'  # executed task 3, sys 1
    job_4_id = 4
    job_4_run_id = '00112233-4455-6677-8899-52554e494433'  # executed task 3, sys 3
    job_5_id = 5
    job_5_run_id = '00112233-4455-6677-8899-52554e494434'  # executed task 3, sys 4
    job_6_id = 6
    job_6_run_id = '00112233-4455-6677-8899-52554e494422'  # executed task 2, sys 2 - 2nd acct
    job_7_id = 7
    job_7_run_id = '00112233-4455-6677-8899-52554e494444'  # executed task 4, sys 4
    job_8_id = 8
    job_8_run_id = '00112233-4455-6677-8899-52554e494454'  # executed task 5, sys 4
    job_9_id = 9
    job_9_run_id = '00000000-0000-0000-0000-000000000000'  # executed task 1, sys 4 - Failed job

    # Miscellaneous constants
    json_mime = 'application/json'
    yaml_mime = 'application/yaml'
    csv_mime = 'text/csv'
    text_mime = 'text/plain'
    missing_branch = api_constants.missing_branch

    test_user = 'testing'

    # Kessel permissions
    kessel_std_workspace_id = api_constants.kessel_std_workspace_id
    kessel_std_org_obj = api_constants.kessel_std_org_obj
    kessel_std_user_obj = api_constants.kessel_std_user_obj
    # Kessel request check values
    kessel_tasks_read = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="tasks_task_view",
        subject=kessel_std_user_obj,
    )
    kessel_tasks_write = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="tasks_task_edit",
        subject=kessel_std_user_obj,
    )
    # Kessel permission checks
    kessel_tasks_rw = [(
        kessel_tasks_write, kessel.ALLOWED
    ), (
        kessel_tasks_read, kessel.ALLOWED
    )]
    kessel_tasks_ro = [(
        kessel_tasks_write, kessel.DENIED
    ), (
        kessel_tasks_read, kessel.ALLOWED
    )]


def task_creation_data(task_number: int, indexes: list):
    """
    Return a dict that can be used to create a new task with parameters.
    """
    data = {
        'slug': f'New_Task{task_number}',
        'title': f'New Task {task_number}',
        'description': f'Task {task_number} for testing',
        'publish_date': '2022-09-02T11:48:50+11:00',
        'playbook': '---\nplaybook text',
        'type': 'A',
        'parameters': [],
        'filter_message': None,
        'filters': []
    }

    for i in range(0, len(indexes)):
        data['parameters'].append({
            'key': f'Param_{i + 1}',
            'description': f'Description for Param_{i + 1}',
            'default': 'Value 1',
            'required': True,
            'values': ['Value 1', 'Value 2', 'Value 3'],
            'title': f'Parameter {i + 1}',
            'index': indexes[i]
        })

    return data
