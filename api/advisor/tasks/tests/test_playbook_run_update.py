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
from project_settings import kafka_settings as kafka_settings
from django.test import TestCase, override_settings
from django.urls import reverse

from api.permissions import auth_header_for_testing
from tasks.management.commands.tasks_service import (
    handle_ansible_job_updates, get_stdout_url
)
from tasks.models import Job
from tasks.tests import constants


PLAYBOOK_DISPATCHER_URL = 'http://localhost'
PDAPI_PSK = 'test'


def run_update_message():
    return {
        "event_type": "create",
        "payload": {
            "id": constants.job_1_run_id,
            "account": "901578",
            "recipient": "dd018b96-da04-4651-84d1-187fa5c23f6c",
            "correlation_id": "fbf49ad9-ea79-41fb-9f6c-cb13307e993d",
            "service": "tasks",
            "url": "http://example.com",
            "labels": {
                "remediation_id": "1234",
            },
            "name": "Apply fix",
            "web_console_url": "http://example.com/remediations/1234",
            "recipient_config": {
                "sat_id": "16372e6f-1c18-4cdb-b780-50ab4b88e74b",
                "sat_org_id": "6826"
            },
            "status": "success",
            "timeout": 3600,
            "created_at": "2022-04-22T11:15:45.429294Z",
            "updated_at": "2022-04-22T11:15:45.429294Z"
        }
    }


STDOUT = r"""
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [task for leapp pre-upgrade assessment] ***********************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Install Leapp from RHEL 7 Extras] ****************************************
skipping: [localhost]

TASK [Install Leapp on RHEL 8 or later] ****************************************
ok: [localhost]

TASK [Remove previous json report] *********************************************
changed: [localhost]

TASK [Remove previous text report] *********************************************
changed: [localhost]

TASK [leapp data-17 files] *****************************************************
ok: [localhost]

TASK [Copy leapp-data17.tar.gz to disk] ****************************************
changed: [localhost]

TASK [Extract leapp-data17.tar.gz to /etc/leapp/files] *************************
changed: [localhost]

TASK [Execute leapp pre-upgrade] ***********************************************
fatal: [localhost]: FAILED! => {"changed": true, "cmd": "/usr/bin/leapp preupgrade --report-schema=1.1.0", "delta": "0:00:39.393624", "end": "2022-10-06 13:57:16.299819", "msg": "non-zero return code", "rc": 1, "start": "2022-10-06 13:56:36.906195", "stderr": "", "stderr_lines": [], "stdout": "==> Processing phase `configuration_phase`\n====> * ipu_workflow_config\n        IPU workflow config actor\n==> Processing phase `FactsCollection`\n====> * scan_pkg_manager\n        Provides data about package manager (yum/dnf)\n====> * get_enabled_modules\n        Provides data about which module streams are enabled on the source system.\n====> * firewalld_collect_global_config\n        This actor reads firewalld's configuration and produces Model\n====> * scandasd\n        In case of s390x architecture, check whether DASD is used.\n====> * network_deprecations\n        Ensures that network configuration doesn't rely on unsupported settings\n====> * scan_kernel_cmdline\n        No documentation has been provided for the scan_kernel_cmdline actor.\n====> * firewalld_collect_used_object_names\n        This actor reads firewalld's configuration and produces Model\n====> * check_custom_network_scripts\n        Check the existence of custom network-scripts and warn user about possible\n====> * repository_mapping\n        Produces message containing repository mapping based on provided file.\n====> * rpm_scanner\n        Provides data about installed RPM Packages.\n====> * sssd_facts_8to9\n        Check SSSD configuration for changes in RHEL9 and report them in model.\n====> * scanmemory\n        Scan Memory of the machine.\n====> * storage_scanner\n        Provides data about storage settings.\n====> * get_installed_desktops\n        Actor checks if kde or gnome desktop environments\n====> * scan_files_for_target_userspace\n        Scan the source system and identify files that will be copied into the target userspace when it is created.\n====> * common_leapp_dracut_modules\n        Influences the generation of the initram disk\n====> * scan_custom_repofile\n        Scan the custom /etc/leapp/files/leapp_upgrade_repositories.repo repo file.\n====> * root_scanner\n        Scan the system root directory and produce a message containing\n====> * persistentnetnames\n        Get network interface information for physical ethernet interfaces of the original system.\n====> * scan_sap_hana\n        Gathers information related to SAP HANA instances on the system.\n====> * load_device_driver_deprecation_data\n        Loads deprecation data for drivers and devices (PCI & CPU)\n====> * transaction_workarounds\n        Provides additional RPM transaction tasks based on bundled RPM packages.\n====> * scancryptopolicies\n        Scan information about system wide set crypto policies\n====> * system_facts\n        Provides data about many facts from system.\n====> * scan_subscription_manager_info\n        Scans the current system for subscription manager information\n====> * udevadm_info\n        Produces data exported by the \"udevadm info\" command.\n====> * biosdevname\n        Enable biosdevname on the target RHEL system if all interfaces on the source RHEL\n====> * scanclienablerepo\n        Produce CustomTargetRepository based on the LEAPP_ENABLE_REPOS in config.\n====> * persistentnetnamesdisable\n        Disable systemd-udevd persistent network naming on machine with single eth0 NIC\n====> * checkrhui\n        Check if system is using RHUI infrastructure (on public cloud) and send messages to\n====> * red_hat_signed_rpm_scanner\n        Provide data about installed RPM Packages signed by Red Hat.\n====> * pci_devices_scanner\n        Provides data about existing PCI Devices.\n====> * selinuxcontentscanner\n        Scan the system for any SELinux customizations\n====> * xfs_info_scanner\n        This actor scans all mounted mountpoints for XFS information\n====> * check_ifcfg\n        Ensures that ifcfg files are compatible with NetworkManager\n====> * rpm_transaction_config_tasks_collector\n        Provides additional RPM transaction tasks from /etc/leapp/transaction.\n====> * ipa_scanner\n        Scan system for ipa-client and ipa-server status\n====> * detect_kernel_drivers\n        Matches all currently loaded kernel drivers against known deprecated and removed drivers.\n====> * scancpu\n        Scan CPUs of the machine.\n====> * multipath_conf_read\n        Read multipath configuration files and extract the necessary informaton\n====> * vdo_conversion_scanner\n        Provides conversion info about VDO devices.\n====> * used_repository_scanner\n        Scan used enabled repositories\n====> * pes_events_scanner\n        Provides data about package events from Package Evolution Service.\n====> * setuptargetrepos\n        Produces list of repositories that should be available to be used by Upgrade process.\n\n============================================================\n                           ERRORS                           \n============================================================\n\n2022-10-06 13:57:06.093131 [ERROR] Actor: scan_subscription_manager_info\nMessage: A subscription-manager command failed to execute\nSummary:\n    Details: Command ['subscription-manager', 'status'] failed with exit code 1.\n    Stderr: \n    Hint: Please ensure you have a valid RHEL subscription and your network is up. If you are using proxy for Red Hat subscription-manager, please make sure it is specified inside the /etc/rhsm/rhsm.conf file. Or use the --no-rhsm option when running leapp, if you do not want to use subscription-manager for the in-place upgrade and you want to deliver all target repositories by yourself or using RHUI on public cloud.\n\n============================================================\n                       END OF ERRORS                        \n============================================================\n\n\nDebug output written to /var/log/leapp/leapp-preupgrade.log\n\n============================================================\n                           REPORT                           \n============================================================\n\nA report has been generated at /var/log/leapp/leapp-report.json\nA report has been generated at /var/log/leapp/leapp-report.txt\n\n============================================================\n                       END OF REPORT                        \n============================================================\n\nAnswerfile has been generated at /var/log/leapp/answerfile", "stdout_lines": ["==> Processing phase `configuration_phase`", "====> * ipu_workflow_config", "        IPU workflow config actor", "==> Processing phase `FactsCollection`", "====> * scan_pkg_manager", "        Provides data about package manager (yum/dnf)", "====> * get_enabled_modules", "        Provides data about which module streams are enabled on the source system.", "====> * firewalld_collect_global_config", "        This actor reads firewalld's configuration and produces Model", "====> * scandasd", "        In case of s390x architecture, check whether DASD is used.", "====> * network_deprecations", "        Ensures that network configuration doesn't rely on unsupported settings", "====> * scan_kernel_cmdline", "        No documentation has been provided for the scan_kernel_cmdline actor.", "====> * firewalld_collect_used_object_names", "        This actor reads firewalld's configuration and produces Model", "====> * check_custom_network_scripts", "        Check the existence of custom network-scripts and warn user about possible", "====> * repository_mapping", "        Produces message containing repository mapping based on provided file.", "====> * rpm_scanner", "        Provides data about installed RPM Packages.", "====> * sssd_facts_8to9", "        Check SSSD configuration for changes in RHEL9 and report them in model.", "====> * scanmemory", "        Scan Memory of the machine.", "====> * storage_scanner", "        Provides data about storage settings.", "====> * get_installed_desktops", "        Actor checks if kde or gnome desktop environments", "====> * scan_files_for_target_userspace", "        Scan the source system and identify files that will be copied into the target userspace when it is created.", "====> * common_leapp_dracut_modules", "        Influences the generation of the initram disk", "====> * scan_custom_repofile", "        Scan the custom /etc/leapp/files/leapp_upgrade_repositories.repo repo file.", "====> * root_scanner", "        Scan the system root directory and produce a message containing", "====> * persistentnetnames", "        Get network interface information for physical ethernet interfaces of the original system.", "====> * scan_sap_hana", "        Gathers information related to SAP HANA instances on the system.", "====> * load_device_driver_deprecation_data", "        Loads deprecation data for drivers and devices (PCI & CPU)", "====> * transaction_workarounds", "        Provides additional RPM transaction tasks based on bundled RPM packages.", "====> * scancryptopolicies", "        Scan information about system wide set crypto policies", "====> * system_facts", "        Provides data about many facts from system.", "====> * scan_subscription_manager_info", "        Scans the current system for subscription manager information", "====> * udevadm_info", "        Produces data exported by the \"udevadm info\" command.", "====> * biosdevname", "        Enable biosdevname on the target RHEL system if all interfaces on the source RHEL", "====> * scanclienablerepo", "        Produce CustomTargetRepository based on the LEAPP_ENABLE_REPOS in config.", "====> * persistentnetnamesdisable", "        Disable systemd-udevd persistent network naming on machine with single eth0 NIC", "====> * checkrhui", "        Check if system is using RHUI infrastructure (on public cloud) and send messages to", "====> * red_hat_signed_rpm_scanner", "        Provide data about installed RPM Packages signed by Red Hat.", "====> * pci_devices_scanner", "        Provides data about existing PCI Devices.", "====> * selinuxcontentscanner", "        Scan the system for any SELinux customizations", "====> * xfs_info_scanner", "        This actor scans all mounted mountpoints for XFS information", "====> * check_ifcfg", "        Ensures that ifcfg files are compatible with NetworkManager", "====> * rpm_transaction_config_tasks_collector", "        Provides additional RPM transaction tasks from /etc/leapp/transaction.", "====> * ipa_scanner", "        Scan system for ipa-client and ipa-server status", "====> * detect_kernel_drivers", "        Matches all currently loaded kernel drivers against known deprecated and removed drivers.", "====> * scancpu", "        Scan CPUs of the machine.", "====> * multipath_conf_read", "        Read multipath configuration files and extract the necessary informaton", "====> * vdo_conversion_scanner", "        Provides conversion info about VDO devices.", "====> * used_repository_scanner", "        Scan used enabled repositories", "====> * pes_events_scanner", "        Provides data about package events from Package Evolution Service.", "====> * setuptargetrepos", "        Produces list of repositories that should be available to be used by Upgrade process.", "", "============================================================", "                           ERRORS                           ", "============================================================", "", "2022-10-06 13:57:06.093131 [ERROR] Actor: scan_subscription_manager_info", "Message: A subscription-manager command failed to execute", "Summary:", "    Details: Command ['subscription-manager', 'status'] failed with exit code 1.", "    Stderr: ", "    Hint: Please ensure you have a valid RHEL subscription and your network is up. If you are using proxy for Red Hat subscription-manager, please make sure it is specified inside the /etc/rhsm/rhsm.conf file. Or use the --no-rhsm option when running leapp, if you do not want to use subscription-manager for the in-place upgrade and you want to deliver all target repositories by yourself or using RHUI on public cloud.", "", "============================================================", "                       END OF ERRORS                        ", "============================================================", "", "", "Debug output written to /var/log/leapp/leapp-preupgrade.log", "", "============================================================", "                           REPORT                           ", "============================================================", "", "A report has been generated at /var/log/leapp/leapp-report.json", "A report has been generated at /var/log/leapp/leapp-report.txt", "", "============================================================", "                       END OF REPORT                        ", "============================================================", "", "Answerfile has been generated at /var/log/leapp/answerfile"]}
...ignoring

TASK [Read report] *************************************************************
ok: [localhost]

TASK [Set inhibitor count] *****************************************************
ok: [localhost]

TASK [Set result] **************************************************************
ok: [localhost]

TASK [Print Task Result] *******************************************************
ok: [localhost] => {
    "task_results": {
        "alert": false,
        "message": "Your system has 0 inhibitors out of 1 potential problems.",
        "report": "Risk Factor: high\nTitle:",
        "report_json": {
            "entries": [
                {
                    "actor": "scan_subscription_manager_info",
                    "audience": "sysadmin",
                    "hostname": "dan-laptop",
                    "id": "f6f6367748a02d4274fb40d3961aa45471c2d2e2ebcea773652d7ec71a784988",
                    "key": "7ec8269784db1bba2ac54ae438689ef397e16833",
                    "severity": "high",
                    "summary": "{\"details\": \"Command ['subscription-manager', 'status'] failed with exit code 1.\"",
                    "timeStamp": "2022-10-06T17:57:06.093327Z",
                    "title": "A subscription-manager command failed to execute"
                }
            ],
            "leapp_run_id": "da27e2cf-0015-4e2e-9d2d-3014fbe5b06d"
        },
        "return_code": "1"
    }
}

PLAY RECAP *********************************************************************
localhost                  : ok=12   changed=5    unreachable=0    failed=0    skipped=1    rescued=0    ignored=1

"""


def json_playbook_dispatcher_reply():
    return {
        "data": [
            {
                "stdout": STDOUT
            }
        ],
        "links": {
            "first": "/api/playbook-dispatcher/v1/run_hosts?fields%5Bdata%5D=stdout&filter%5Brun%5D%5Bid%5D=00112233-4455-6677-8899-012345670001&limit=50&offset=0",
            "last": "/api/playbook-dispatcher/v1/run_hosts?fields%5Bdata%5D=stdout&filter%5Brun%5D%5Bid%5D=00112233-4455-6677-8899-012345670001&limit=50&offset=0"
        },
        "meta": {
            "count": 1,
            "total": 1
        }
    }


# Probably need a better way to encode a lot of carriage return line feed stuff here.
STDOUT_EOLN = "[WARNING]: provided hosts list is empty, only localhost is available. Note thatthe implicit localhost does not match 'all'\r\nPLAY [run insights] ************************************************************\r\nTASK [run insights] ************************************************************ok: [localhost]\r\nTASK [Set result] **************************************************************ok: [localhost]\r\nTASK [Print Task Result] *******************************************************ok: [localhost] =\u003e {\r\n    \"task_results\": {\r\n        \"alert\": \"false\",\r\n        \"message\": \"WARN: BASIC authentication method is being deprecated. Please consider using CERT authentication method.\\nStarting to collect Insights data for rhel8-vm\\nWriting RHSM facts to /etc/rhsm/facts/insights-client.facts ...\\nUploading Insights data.\\nSuccessfully uploaded report from rhel8-vm to account 6089719.\\nView details about this system on console.redhat.com:\\nhttps://console.redhat.com/insights/inventory/67ec0940-444c-49ea-b091-cb1f8cd00d31\",\r\n        \"report\": {\r\n            \"changed\": false,\r\n            \"cmd\": [\r\n                \"insights-client\"\r\n            ],\r\n            \"delta\": \"0:00:40.879763\",\r\n            \"end\": \"2024-04-17 13:38:15.726133\",\r\n            \"failed\": false,\r\n            \"msg\": \"\",\r\n            \"rc\": 0,\r\n            \"start\": \"2024-04-17 13:37:34.846370\",\r\n            \"stderr\": \"\",\r\n            \"stderr_lines\": [],\r\n            \"stdout\": \"WARN: BASIC authentication method is being deprecated. Please consider using CERT authentication method.\\nStarting to collect Insights data for rhel8-vm\\nWriting RHSM facts to /etc/rhsm/facts/insights-client.facts ...\\nUploading Insights data.\\nSuccessfully uploaded report from rhel8-vm to account 6089719.\\nView details about this system on console.redhat.com:\\nhttps://console.redhat.com/insights/inventory/67ec0940-444c-49ea-b091-cb1f8cd00d31\",\r\n            \"stdout_lines\": [\r\n                \"WARN: BASIC authentication method is being deprecated. Please consider using CERT authentication method.\",\r\n                \"Starting to collect Insights data for rhel8-vm\",\r\n                \"Writing RHSM facts to /etc/rhsm/facts/insights-client.facts ...\",\r\n                \"Uploading Insights data.\",\r\n                \"Successfully uploaded report from rhel8-vm to account 6089719.\",\r\n                \"View details about this system on console.redhat.com:\",\r\n                \"https://console.redhat.com/insights/inventory/67ec0940-444c-49ea-b091-cb1f8cd00d31\"\r\n            ]\r\n        }\r\n    }\r\n}\r\nPLAY RECAP *********************************************************************\r\nlocalhost                  : ok=3    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   \r\n"


def json_playbook_dispatcher_reply_eoln():
    return {"data": [{"stdout": STDOUT_EOLN}], "error": ""}


@override_settings(PLAYBOOK_DISPATCHER_URL=PLAYBOOK_DISPATCHER_URL, PDAPI_PSK=PDAPI_PSK)
class TaskJobUpdateTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    std_auth = auth_header_for_testing()

    @responses.activate
    def test_job_update_complete_json_response(self):
        responses.get(
            get_stdout_url(constants.job_1_run_id),
            status=200,
            body=STDOUT
        )
        handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, run_update_message())

        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsNotNone(data['end_time'])
        self.assertEqual(data['status'], constants.status_completed_with_errors)
        job = next(job for job in data['jobs'] if job['system_id'] == constants.host_01_uuid)
        self.assertEqual(job['system_id'], constants.host_01_uuid)
        self.assertEqual(job['status'], constants.status_success, job['results'])
        self.assertEqual(job['results'], {
            "alert": False,
            "message": "Your system has 0 inhibitors out of 1 potential problems.",
            "report": "Risk Factor: high\nTitle:",
            "report_json": {
                "entries": [
                    {
                        "actor": "scan_subscription_manager_info",
                        "audience": "sysadmin",
                        "hostname": "dan-laptop",
                        "id": "f6f6367748a02d4274fb40d3961aa45471c2d2e2ebcea773652d7ec71a784988",
                        "key": "7ec8269784db1bba2ac54ae438689ef397e16833",
                        "severity": "high",
                        "summary": "{\"details\": \"Command ['subscription-manager', 'status'] failed with exit code 1.\"",
                        "timeStamp": "2022-10-06T17:57:06.093327Z",
                        "title": "A subscription-manager command failed to execute"
                    }
                ],
                "leapp_run_id": "da27e2cf-0015-4e2e-9d2d-3014fbe5b06d"
            },
            "return_code": "1"
        })
        # This update will have also set the job's stdout, so...
        self.assertTrue(job['has_stdout'])
        # And we should be able to see the stdout if we request it nicely
        res = self.client.get(
            reverse('tasks-job-stdout', kwargs={'id': constants.job_1_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.text_mime)
        self.assertEqual(
            res.content.decode(),
            STDOUT
        )

    @responses.activate
    def test_job_update_complete_json_response_eoln(self):
        responses.get(
            get_stdout_url(constants.job_1_run_id),
            status=200,
            body=STDOUT_EOLN
        )
        handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, run_update_message())
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        data = res.json()
        self.assertIsNotNone(data['end_time'])
        job = next(job for job in data['jobs'] if job['system_id'] == constants.host_01_uuid)
        self.assertEqual(job['system_id'], constants.host_01_uuid)
        self.assertEqual(job['status'], constants.status_success)
        self.assertEqual(job['results'], {
            "alert": "false",
            "message": "WARN: BASIC authentication method is being deprecated. Please consider using CERT authentication method.\nStarting to collect Insights data for rhel8-vm\nWriting RHSM facts to /etc/rhsm/facts/insights-client.facts ...\nUploading Insights data.\nSuccessfully uploaded report from rhel8-vm to account 6089719.\nView details about this system on console.redhat.com:\nhttps://console.redhat.com/insights/inventory/67ec0940-444c-49ea-b091-cb1f8cd00d31",
            "report": {
                "changed": False,
                "cmd": [
                    "insights-client"
                ],
                "delta": "0:00:40.879763",
                "end": "2024-04-17 13:38:15.726133",
                "failed": False,
                "msg": "",
                "rc": 0,
                "start": "2024-04-17 13:37:34.846370",
                "stderr": "",
                "stderr_lines": [],
                "stdout": "WARN: BASIC authentication method is being deprecated. Please consider using CERT authentication method.\nStarting to collect Insights data for rhel8-vm\nWriting RHSM facts to /etc/rhsm/facts/insights-client.facts ...\nUploading Insights data.\nSuccessfully uploaded report from rhel8-vm to account 6089719.\nView details about this system on console.redhat.com:\nhttps://console.redhat.com/insights/inventory/67ec0940-444c-49ea-b091-cb1f8cd00d31",
                "stdout_lines": [
                    "WARN: BASIC authentication method is being deprecated. Please consider using CERT authentication method.",
                    "Starting to collect Insights data for rhel8-vm",
                    "Writing RHSM facts to /etc/rhsm/facts/insights-client.facts ...",
                    "Uploading Insights data.",
                    "Successfully uploaded report from rhel8-vm to account 6089719.",
                    "View details about this system on console.redhat.com:",
                    "https://console.redhat.com/insights/inventory/67ec0940-444c-49ea-b091-cb1f8cd00d31"
                ]
            }
        })
        # This update will have also set the job's stdout, so...
        self.assertTrue(job['has_stdout'])
        # And we should be able to see the stdout if we request it nicely
        res = self.client.get(
            reverse('tasks-job-stdout', kwargs={'id': constants.job_1_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.text_mime)
        self.assertEqual(
            res.content.decode(),
            json_playbook_dispatcher_reply_eoln()['data'][0]['stdout']
        )

    @responses.activate
    def test_job_update_deleted_system(self):
        responses.get(
            get_stdout_url(constants.job_1_run_id),
            status=200,
            body=STDOUT
        )
        job = Job.objects.filter(run_id=constants.job_1_run_id)[0]
        job.system_id = '00000000-0000-0000-0000-000000000000'  # non existent system.
        job.save()

        handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, run_update_message())

        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )

        data = res.json()
        self.assertIsNotNone(data['end_time'])
        self.assertEqual(data['status'], constants.status_completed_with_errors)  # status is still updated even with deleted system
        job = next(job for job in data['jobs'] if job['system_id'] == '00000000-0000-0000-0000-000000000000')
        self.assertEqual(job['status'], constants.status_success)  # status is still updated even with deleted system

    @responses.activate
    def test_job_update_non_org_admin(self):
        responses.get(
            get_stdout_url(constants.job_3_run_id),
            status=200,
            body=STDOUT
        )
        update_message = run_update_message()
        update_message['payload']['id'] = constants.job_3_run_id
        handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, update_message)

    def test_job_update_bad_status(self):
        update_message = run_update_message()
        update_message['payload']['status'] = "bad status"
        job_count = Job.objects.count()
        with self.assertRaises(KeyError):
            handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, update_message)
        # Should be no extra jobs
        self.assertEqual(Job.objects.count(), job_count)

    @responses.activate
    def test_job_update_mangled_json_response(self):
        this_stdout = STDOUT.replace('"message"', "bad keyword")
        responses.get(
            get_stdout_url(constants.job_1_run_id),
            status=200,
            body=this_stdout
        )
        handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, run_update_message())

        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsNotNone(data['end_time'])
        self.assertEqual(data['status'], constants.status_completed_with_errors)
        job = next(job for job in data['jobs'] if job['system_id'] == constants.host_01_uuid)
        self.assertEqual(job['system_id'], constants.host_01_uuid)
        self.assertEqual(job['status'], constants.status_failure)  # because JSON parsing failed
        self.assertEqual(job['results'], {
            "alert": True, "error": True,
            "message": "Error in parsing JSON between delimiters (Expecting "
            "property name enclosed in double quotes: line 3 column 9 (char 34)",
        })

    @responses.activate
    def test_job_update_failure(self):
        # Playbook dispatcher here returns a 403...
        responses.get(
            get_stdout_url(constants.job_1_run_id),
            status=403,
        )
        # So the handle_ansible_job_updates function should call fetch_playbook_dispatcher_stdout because
        # the status is 'success'.  That then tries to fetch the stdout from
        # the playbook dispatcher, which gets a non-200 and fails.
        handle_ansible_job_updates(kafka_settings.WEBHOOKS_TOPIC, run_update_message())

        # In that case we can still request the detail for the executed task...
        res = self.client.get(
            reverse('tasks-executedtask-detail', kwargs={'id': constants.executed_task_id}),
            **self.std_auth
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.accepted_media_type, constants.json_mime)
        data = res.json()
        self.assertIsNotNone(data['end_time'])
        self.assertEqual(data['status'], constants.status_completed_with_errors)
        job = next(job for job in data['jobs'] if job['system_id'] == constants.host_01_uuid)
        self.assertEqual(job['system_id'], constants.host_01_uuid)
        self.assertEqual(job['status'], constants.status_success)
        # But the message is still an empty dict.
        self.assertEqual(job['results'], {})
