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

from copy import copy
from datetime import datetime
import json
from mock.mock import patch
from os import environ
import pytz

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from api.scripts import import_content
from api.models import Ack, Rule, ResolutionRisk, Pathway
from api.tests import constants

# Some node_id values can be '', so the ABORT_COMMAND_ISSUED rule has its
# node_id removed to test this.
CONTENT_JSON = r"""[
{
  "status": "active",
  "impact": "Storage Performance Loss",
  "python_module": "telemetry.rules.plugins.storage.abort_command_issued",
  "description": "Performance degradation of I/O when commands timeout due to faulty storage hardware",
  "tags": [
    "sbr_kernel",
    "kernel",
    "storage"
  ],
  "component": "kernel",
  "reboot_required": false,
  "reason": "This host has encountered **{{=pydata.total_aborts}}** occurrences of *Abort command issued* in /var/log/messages, including {{?pydata.abort_groups > 1}}multiple occurrences{{??}}1 occurrence{{?}} of 10 or more abort commands occurring within a period of an hour.  \n\n*Abort command issued* messages indicate an error condition being returned from the SAN.\n\nAn example abort command that is displayed in /var/log/messages: \n\n**{{=pydata.example_abort}}**",
  "node_id": "",
  "path": "/opt/app-root/src/insights-content/content/storage/abort_command_issued/ABORT_COMMAND_ISSUED",
  "summary": "Occurrences of the message \"Abort Command Issued\" indicate an error condition being returned from the storage area network (SAN).",
  "likelihood": 2,
  "condition": "Storage faulty occurred",
  "category": "Stability",
  "product_code": "rhel",
  "name": "Performance degradation of I/O when commands timeout due to faulty storage hardware",
  "plugin": "abort_command_issued",
  "generic": "\"Abort Command Issued\" messages are being detected, which are indicative of a storage area network (SAN) or hardware error.\n\nVerify if there are any issues present from the FC switch, FC cabling, zoning, or storage array. Red Hat recommends that you contact the storage vendor to review the issue encountered.",
  "resolution_risk": "Hardware Vendor Analysis",
  "playbooks": [],
  "error_key": "ABORT_COMMAND_ISSUED",
  "role": "host",
  "publish_date": "2016-10-31 04:08:30",
  "resolution": "Red Hat recommends that you verify if there are any issues present from the FC switch, FC cabling, zoning, or storage array and contact the storage vendor to review the switch logs to verify if there are any error counters, CRC errors in FC switch logs to solve this issue.\n",
  "rule_id": "abort_command_issued|ABORT_COMMAND_ISSUED",
  "more_info": null
}, {
  "status": "active",
  "impact": "Kernel Panic",
  "python_module": "telemetry.rules.plugins.kernel.ilo",
  "description": "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version",
  "tags": [
    "hp",
    "hp_ilo"
  ],
  "component": "ilo",
  "reboot_required": false,
  "reason": "This **{{=pydata.product_name}}** system is using iLO 3 with the firmware version of **{{=pydata.firmware_ver}}**. Memory corruption and subsequent kernel panics will occur when HP System Health Application and Command Line Utilities for Linux (hp-health) are running.\n\nThis behaviour is caused by the old firmware version of iLO3.\n",
  "node_id": "744973",
  "path": "/opt/app-root/src/insights-content/content/kernel/ilo/HP_ILO_ISSUE",
  "likelihood": 2,
  "condition": "HP ProLiant G7 systems with specific iLO 3 firmware version",
  "category": "Stability",
  "product_code": "rhel",
  "name": "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version",
  "plugin": "ilo",
  "generic": "Memory corruption and subsequent kernel panics happens when hp-health service running on HP ProLiant G7 systems with iLO 3 firmware versions 1.80 and earlier.\n",
  "resolution_risk": "Hardware Vendor Firmware Update",
  "playbooks": [],
  "error_key": "HP_ILO_ISSUE",
  "role": "host",
  "publish_date": "2016-10-31 04:08:34",
  "resolution": "Red Hat recommends that you upgrade HP iLO 3 firmware version to **1.82** or later to fix this issue. Regarding the update method for iLO 3 firmware, please consult your hardware vendor. \n",
  "rule_id": "ilo|HP_ILO_ISSUE",
  "more_info": null
}, {
  "status": "active",
  "category": "Stability",
  "python_module": "telemetry.rules.plugins.kernel.ilo",
  "description": "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version",
  "tags": [
    "hp",
    "hp_ilo"
  ],
  "component": "ilo",
  "reboot_required": false,
  "reason": "This **{{=pydata.product_name}}** system is using iLO 3 with the firmware version of **{{=pydata.firmware_ver}}**. Memory corruption and subsequent kernel panics will occur when HP System Health Application and Command Line Utilities for Linux (hp-health) are running.\n\nThis behaviour is caused by the old firmware version of iLO3.\n",
  "node_id": "744973",
  "path": "/opt/app-root/src/insights-content/content/kernel/ilo/HP_ILO_ISSUE/rhev_hypervisor",
  "product_code": "rhev",
  "likelihood": 2,
  "condition": "HP ProLiant G7 systems with specific iLO 3 firmware version",
  "name": "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version",
  "impact": "Kernel Panic",
  "plugin": "ilo",
  "generic": "Memory corruption and subsequent kernel panics happens when hp-health service running on HP ProLiant G7 systems with iLO 3 firmware versions 1.80 and earlier.\n",
  "resolution_risk": "Hardware Vendor Firmware Update",
  "playbooks": [],
  "role": "hypervisor",
  "publish_date": "2016-10-31 04:08:34",
  "error_key": "HP_ILO_ISSUE",
  "resolution": "To fix this issue, Red Hat recommends that you upgrade HP iLO 3 firmware version to **1.82** or later. Regarding the update method for iLO 3 firmware, please consult your hardware vendor.\n",
  "rule_id": "ilo|HP_ILO_ISSUE",
  "more_info": null
}, {
  "more_info": null,
  "reason": "The available disk space of **Satellite {{=pydata.sat_ver}}** is low because `smart_proxy_dynflow_core` log cannot be rotated.\n\nThe output of `lsof` command:\n  ~~~\n  {{=pydata.lsof[0]}} {{=pydata.lsof[1]}} \n  ~~~\n\n{{for (var i in pydata.usage) { }}\nThe following partition is at or near its capacity:\n<pre>\n<table border=\"1\" align=\"left\">\n  <tr>\n    <th style=\"text-align:center;\">Partition</th>\n    <th style=\"text-align:right;\">Disk Use%</th>\n  </tr>\n<tr>\n    <td style=\"background-color:#FAFAFA;text-align:left;font-weight:normal;\">{{=i}}</td>\n    <td style=\"background-color:#FAFAFA;text-align:left;font-weight:normal;word-wrap:break-word;width:50%;\">{{=pydata.usage[i]}}</td>\n</tr>\n{{ } }}\n</table>\n</pre>\n",
  "resolution": "Red Hat recommends that you upgrade this **Satellite {{=pydata.sat_ver}}** to **Satellite 6.4** or later version, using [Red Hat Satellite Upgrade Helper](https://access.redhat.com/labs/satelliteupgradehelper/).\n",
  "category": "Availability",
  "component": "satellite6",
  "name": "Disk will be exhausted because dynflow_core logs cannot be rotated normally in Satellite 6",
  "node_id": "3433771",
  "product_code": "rhel",
  "python_module": "telemetry.rules.plugins.satellite.sat6_dynflow_core_log",
  "reboot_required": false,
  "role": "host",
  "plugin": "sat6_dynflow_core_log",
  "rule_id": "sat6_dynflow_core_log|DYNFLOW_CORE_LOG_ISSUE",
  "path": "/opt/app-root/src/insights-content/content/satellite/sat6_dynflow_core_log/DYNFLOW_CORE_LOG_ISSUE",
  "error_key": "DYNFLOW_CORE_LOG_ISSUE",
  "generic": "Disk will be exhausted because dynflow_core logs cannot be rotated normally in Satellite 6. This is indicated by `smart_proxy_dynflow_core` redirecting logs to deleted files **/var/log/foreman-proxy/smart_proxy_dynflow_core.log-yyyymmdd (deleted)** in `lsof` command output.\n",
  "condition": "Dynflow_core logs cannot be rotated normally",
  "description": "Disk will be exhausted because dynflow_core logs cannot be rotated normally in Satellite 6",
  "impact": "Management Availability",
  "likelihood": 3,
  "publish_date": "null",
  "resolution_risk": "Update Package",
  "status": "inactive",
  "tags": [
    "sbr_sysmgmt",
    "satellite6"
  ],
  "playbooks": []
}
]"""

CONTENT_JSON_UPDATE = r"""[{
  "status": "inactive",
  "impact": "Storage Performance Loss",
  "python_module": "telemetry.rules.plugins.storage.abort_command_issued",
  "description": "Performance degradation of I/O when commands timeout due to faulty storage hardware",
  "tags": [
    "kernel",
    "storage",
    "performance"
  ],
  "component": "kernel",
  "reboot_required": false,
  "reason": "This host has encountered **{{=pydata.total_aborts}}** occurrences of *Abort command issued* in /var/log/messages, including {{?pydata.abort_groups > 1}}multiple occurrences{{??}}1 occurrence{{?}} of 10 or more abort commands occurring within a period of an hour.  \n\n*Abort command issued* messages indicate an error condition being returned from the SAN.\n\nAn example abort command that is displayed in /var/log/messages: \n\n**{{=pydata.example_abort}}**",
  "node_id": "",
  "path": "/opt/app-root/src/insights-content/content/storage/abort_command_issued/ABORT_COMMAND_ISSUED",
  "likelihood": 2,
  "condition": "Storage faulty occurred",
  "category": "Stability",
  "product_code": "rhel",
  "name": "Performance degradation of I/O when commands timeout due to faulty storage hardware",
  "plugin": "abort_command_issued",
  "generic": "Updated rule generic information",
  "summary": "Updated rule summary information",
  "resolution_risk": "Hardware Vendor Analysis",
  "playbooks": [{
    "resolution_risk": 1,
    "resolution_type": "fixer",
    "play": "- name: Winston Wolfe",
    "description": "Solves problems",
    "path": "just/do/what/i/say",
    "version": "c8682a66d9d5857974f585d35b34dab82f949d37"
   }],
  "error_key": "ABORT_COMMAND_ISSUED",
  "role": "host",
  "publish_date": "null",
  "resolution": "Updated resolution",
  "rule_id": "abort_command_issued|ABORT_COMMAND_ISSUED",
  "more_info": null
}]"""

CVE_CONTENT_JSON = r"""
[{
    "category": "Security",
    "python_module": "prodsec.rules.heartbleed",
    "node_id": "781793",
    "product_code": "rhel",
    "reboot_required": false,
    "role": "host",
    "name": "CVE-2014-0160: \"Heartbleed\" OpenSSL information disclosure",
    "plugin": "heartbleed",
    "rule_id": "heartbleed|HAS_HEARTBLEED",
    "path": "/opt/app-root/src/insights-content/content/security/heartbleed/HAS_HEARTBLEED",
    "error_key": "HAS_HEARTBLEED",
    "more_info": "* You should use either the latest or the specific rpm version listed in [CVE-2014-0160](https://access.redhat.com/security/cve/CVE-2014-0160).\n* To learn how to upgrade packages, see \"[What is yum and how do I use it?](https://access.redhat.com/solutions/9934)\"\n* The Customer Portal page for the [Red Hat Security Team](https://access.redhat.com/security/) contains more information about policies, procedures, and alerts for Red Hat Products.\n* The Security Team also maintains a frequently updated blog at [securityblog.redhat.com](https://securityblog.redhat.com).",
    "resolution": "Red Hat recommends you upgrade OpenSSL immediately:\n\n~~~\n# yum update 'openssl*'\n~~~\n\nYou **must** restart any SSL-enabled services for this to take effect.",
    "reason": "[CVE-2014-0160](https://access.redhat.com/security/cve/CVE-2014-0160), known as Heartbleed, can allow remote attackers read access to privileged parts of system memory.   \nThis host is running  **{{=pydata.package}}** and is vulnerable.",
    "generic": "[CVE-2014-0160](https://access.redhat.com/security/cve/CVE-2014-0160), known as Heartbleed, can allow remote attackers read access to privileged parts of system memory.  \n\nRed Hat recommends you upgrade OpenSSL immediately and restart any SSL-enabled services.",
    "status": "active",
    "description": "CVE-2014-0160: \"Heartbleed\" OpenSSL information disclosure",
    "impact": "Information Disclosure",
    "likelihood": 2,
    "publish_date": "2016-10-31 04:08:34",
    "resolution_risk": "Update Commonly Used Library",
    "tags": [
      "security",
      "cve"
    ],
    "playbooks": []
}]"""

DATE_FORMAT_CONTENT_JSON = r"""
[{
    "generic": "A vulnerability was found in PolicyKit (polkit) UID handling which allows user or group with ID above INT32_MAX to elevate their privileges on the system leading to authentication bypass.\n\nRed Hat recommends that you update polkit package.\t\n",
    "more_info": "* For more information about the flaw, see [CVE page](https://access.redhat.com/security/cve/cve-2018-19788).\n* To learn how to upgrade packages, see [What is yum and how do I use it?](https://access.redhat.com/solutions/9934).\n* The Customer Portal page for the [Red Hat Security Team](https://access.redhat.com/security/) contains more information about policies, procedures, and alerts for Red Hat products.\n* The Security Team also maintains a frequently updated blog at [securityblog.redhat.com](https://securityblog.redhat.com).\n",
    "reason": "This system is vulnerable because:\n* It has the following, vulnerable `polkit` package installed: **{{=pydata.PACKAGES[0]}}**\n{{? pydata.error_key == \"CVE_2018_19788_POLKIT_UID_BAD\" }}* The highest UID on the system is **{{=pydata.value}}** which is above INT32_MAX{{?}}\n",
    "resolution": "{{? pydata.fixable == true}} \n<!-- It is not fixable on RHEL 6, so only steps for RHEL 7+ are needed -->\nRed Hat recommends that you update the `{{=pydata.PACKAGE_NAMES[0]}}` package and restart polkit service:\n~~~\n# yum update {{=pydata.PACKAGE_NAMES[0]}}\n# systemctl restart polkit\n~~~\n{{?}}\n{{? pydata.value > 2147483647 }}\n{{? pydata.fixable == true }}Alternatively, you can{{??}}Red Hat recommends that you{{?}} change the user or group ID so it is no longer above INT32_MAX (2147483647).{{?}}\n",
    "category": "Security",
    "name": "CVE-2018-19788: PolicyKit authentication bypass",
    "node_id": 3734021,
    "product_code": "rhel",
    "python_module": "prodsec.rules.CVE_2018_19788_polkit",
    "reboot_required": false,
    "role": "host",
    "plugin": "CVE_2018_19788_polkit",
    "rule_id": "CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD",
    "path": "/opt/app-root/src/insights-content/content/security/CVE_2018_19788_polkit/CVE_2018_19788_POLKIT_UID_BAD",
    "error_key": "CVE_2018_19788_POLKIT_UID_BAD",
    "status": "active",
    "description": "CVE-2018-19788: PolicyKit authentication bypass with affected UID",
    "impact": "Local Privilege Escalation",
    "likelihood": 4,
    "publish_date": "2018-12-03 12:00",
    "resolution_risk": "Update Package",
    "tags": [
      "security",
      "cve"
    ],
    "playbooks": []
}]"""

RESOLUTION_NODEID_CONTENT_JSON = r"""
[{
  "status": "active",
  "category": "Stability",
  "python_module": "telemetry.rules.plugins.kernel.ilo",
  "description": "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version",
  "tags": [
    "hp",
    "hp_ilo"
  ],
  "component": "ilo",
  "reboot_required": false,
  "reason": "This **{{=pydata.product_name}}** system is using iLO 3 with the firmware version of **{{=pydata.firmware_ver}}**. Memory corruption and subsequent kernel panics will occur when HP System Health Application and Command Line Utilities for Linux (hp-health) are running.\n\nThis behaviour is caused by the old firmware version of iLO3.\n",
  "node_id": 744973,
  "path": "/opt/app-root/src/insights-content/content/kernel/ilo/HP_ILO_ISSUE/rhev_hypervisor",
  "product_code": "rhev",
  "likelihood": 2,
  "condition": "HP ProLiant G7 systems with specific iLO 3 firmware version",
  "name": "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version",
  "impact": "Kernel Panic",
  "plugin": "ilo",
  "generic": "Memory corruption and subsequent kernel panics happens when hp-health service running on HP ProLiant G7 systems with iLO 3 firmware versions 1.80 and earlier.\n",
  "resolution_risk": "Hardware Vendor Firmware Update",
  "playbooks": [],
  "role": "hypervisor",
  "publish_date": "2016-10-31 04:08:34",
  "error_key": "HP_ILO_ISSUE",
  "resolution": "Contact your hardware vendor",
  "rule_id": "ilo|HP_ILO_ISSUE",
  "more_info": null
}]"""

PLAYBOOK_CONTENT_JSON = r"""
[{
    "reason": "Nasty alien mofos",
    "resolution": "Nuke em from orbit",
    "more_info": null,
    "category": "Stability",
    "component": "corosync",
    "name": "Cluster nodes are frequently fenced as realtime is not enabled in corosync",
    "node_id": "1602623",
    "product_code": "rhel",
    "python_module": "telemetry.rules.plugins.osp.corosync_enable_rt_schedule",
    "reboot_required": false,
    "role": "host",
    "plugin": "corosync_enable_rt_schedule",
    "rule_id": "corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT",
    "path": "/opt/app-root/src/insights-content/content/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT",
    "error_key": "COROSYNC_NOT_ENABLE_RT",
    "generic": "Cluster nodes are frequently fenced because the realtime scheduling priority is not enabled. This increases the possibility of corosync token losses.\n",
    "condition": "realtime is not enabled in corosync",
    "description": "Cluster nodes are frequently fenced as realtime is not enabled in corosync",
    "impact": "Cluster Availability",
    "likelihood": 2,
    "publish_date": "2016-10-31 04:08:34",
    "resolution_risk": "Update Package",
    "status": "active",
    "tags": [
      "openstack",
      "sbr_stack",
      "corosync"
    ],
    "playbooks": [
      {
        "resolution_risk": 1,
        "resolution_type": "update_latest",
        "play": "- name: Update corosync to the latest version and restart cluster\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Update corosync to latest version\n      yum:\n        name: corosync\n        state: latest\n\n    - name: Stop pcs cluster\n      shell: pcs cluster stop\n\n    - name: Start pcs cluster\n      shell: pcs cluster start\n",
        "description": "Update corosync to the latest version and restart cluster",
        "path": "playbooks/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT/rhel_host/update_latest_fixit.yml",
        "version": "1111111111111111111111111111111111111111"
      },
      {
        "resolution_risk": 1,
        "resolution_type": "update_specific",
        "play": "- name: Update corosync to 2.3.4-4.el7_1.3 version and restart cluster\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Update corosync to 2.3.4-4.el7_1.3 version\n      yum:\n        name: corosync-2.3.4-4.el7_1.3\n        state: present\n\n    - name: Stop pcs cluster\n      shell: pcs cluster stop\n\n    - name: Start pcs cluster\n      shell: pcs cluster start\n",
        "description": "Update corosync to 2.3.4-4.el7_1.3 version and restart cluster",
        "path": "playbooks/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT/rhel_host/update_specific_fixit.yml",
        "version": "1111111111111111111111111111111111111111"
      },
      {
        "resolution_risk": 1,
        "resolution_type": "workaround",
        "play": "- name: Add \"-r\" into COROSYNC_OPTIONS option to mitigate and restart cluster\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Add \"-r\" into COROSYNC_OPTIONS\n      lineinfile:\n        path: /etc/sysconfig/corosync\n        regexp: '^(COROSYNC_OPTIONS=\")(.*)(\")'\n        line: '\\1\\2 -r\\3'\n        backrefs: yes\n        backup: yes\n\n    - name: Stop pcs cluster\n      shell: pcs cluster stop\n\n    - name: Start pcs cluster\n      shell: pcs cluster start\n",
        "description": "Add \"-r\" into COROSYNC_OPTIONS option to mitigate and restart cluster",
        "path": "playbooks/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT/rhel_host/workaround_fixit.yml",
        "version": "1111111111111111111111111111111111111111"
      }
    ]
  },
  {
    "reason": "Scary dead peeps",
    "resolution": "Dead peeps need love too",
    "more_info": null,
    "category": "Stability",
    "component": "ansible",
    "name": "New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled",
    "node_id": "",
    "product_code": "rhel",
    "python_module": "telemetry.rules.plugins.non_kernel.ansible_deprecated_repo",
    "reboot_required": false,
    "role": "host",
    "plugin": "ansible_deprecated_repo",
    "rule_id": "ansible_deprecated_repo|ANSIBLE_DEPRECATED_REPO",
    "path": "/opt/app-root/src/insights-content/content/non_kernel/ansible_deprecated_repo/ANSIBLE_DEPRECATED_REPO",
    "error_key": "ANSIBLE_DEPRECATED_REPO",
    "generic": "Since the release of Ansible Engine 2.4, Red Hat will no longer provide future errata from the Extras repo but from a dedicated Ansible repo instead. New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled.\n",
    "condition": "Ansible package is installed and dedicated Ansible repo is not enabled",
    "description": "New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled",
    "impact": "Compatibility Error",
    "likelihood": 2,
    "publish_date": "2018-04-16 10:03:16",
    "resolution_risk": "Update Package",
    "status": "active",
    "tags": [
      "sbr_services",
      "ansible"
    ],
    "playbooks": [
      {
        "resolution_risk": 1,
        "resolution_type": "fix",
        "play": "- name: Enable ansible repo and update ansible package\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Enable ansible repo\n      command: subscription-manager repos --enable=rhel-7-server-ansible-2-rpms\n\n    - name: Update ansible package\n      yum:\n        name: ansible\n        state: latest\n",
        "description": "Enable ansible repo and update ansible package",
        "path": "playbooks/non_kernel/ansible_deprecated_repo/ANSIBLE_DEPRECATED_REPO/rhel_host/fix_fixit.yml",
        "version": "1111111111111111111111111111111111111111"
      }
    ]
  }
]
"""

PLAYBOOK_CONTENT_JSON_UPDATE = r"""
[{
    "reason": "Nasty alien mofos",
    "resolution": "Nuke em from orbit",
    "more_info": null,
    "category": "Stability",
    "component": "corosync",
    "name": "Cluster nodes are frequently fenced as realtime is not enabled in corosync",
    "node_id": "1602623",
    "product_code": "rhel",
    "python_module": "telemetry.rules.plugins.osp.corosync_enable_rt_schedule",
    "reboot_required": false,
    "role": "host",
    "plugin": "corosync_enable_rt_schedule",
    "rule_id": "corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT",
    "path": "/opt/app-root/src/insights-content/content/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT",
    "error_key": "COROSYNC_NOT_ENABLE_RT",
    "generic": "Cluster nodes are frequently fenced because the realtime scheduling priority is not enabled. This increases the possibility of corosync token losses.\n",
    "condition": "realtime is not enabled in corosync",
    "description": "Cluster nodes are frequently fenced as realtime is not enabled in corosync",
    "impact": "Cluster Availability",
    "likelihood": 2,
    "publish_date": "2016-10-31 04:08:34",
    "resolution_risk": "Update Package",
    "status": "active",
    "tags": [
      "openstack",
      "sbr_stack",
      "corosync"
    ],
    "playbooks": [
      {
        "resolution_risk": 1,
        "resolution_type": "fix",
        "play": "- name: Enable ansible repo and update ansible package\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Enable ansible repo\n      command: subscription-manager repos --enable=rhel-7-server-ansible-2-rpms\n\n    - name: Update ansible package\n      yum:\n        name: ansible\n        state: latest\n",
        "description": "Enable ansible repo and update ansible package",
        "path": "playbooks/non_kernel/ansible_deprecated_repo/ANSIBLE_DEPRECATED_REPO/rhel_host/fix_fixit.yml",
        "version": "1111111111111111111111111111111111111112"
      },
      {
        "resolution_risk": 1,
        "resolution_type": "workaround",
        "play": "- name: Add \"-r\" into COROSYNC_OPTIONS option to mitigate and restart cluster\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Add \"-r\" into COROSYNC_OPTIONS\n      lineinfile:\n        path: /etc/sysconfig/corosync\n        regexp: '^(COROSYNC_OPTIONS=\")(.*)(\")'\n        line: '\\1\\2 -r\\3'\n        backrefs: yes\n        backup: yes\n\n    - name: Stop pcs cluster\n      shell: pcs cluster stop\n\n    - name: Start pcs cluster\n      shell: pcs cluster start\n",
        "description": "Add \"-r\" into COROSYNC_OPTIONS option to mitigate and restart cluster",
        "path": "playbooks/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT/rhel_host/workaround_fixit.yml",
        "version": "1111111111111111111111111111111111111111"
      }
    ]
  },
  {
    "reason": "Scary dead peeps",
    "resolution": "Dead peeps need love too",
    "more_info": null,
    "category": "Stability",
    "component": "ansible",
    "name": "New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled",
    "node_id": "",
    "product_code": "rhel",
    "python_module": "telemetry.rules.plugins.non_kernel.ansible_deprecated_repo",
    "reboot_required": false,
    "role": "host",
    "plugin": "ansible_deprecated_repo",
    "rule_id": "ansible_deprecated_repo|ANSIBLE_DEPRECATED_REPO",
    "path": "/opt/app-root/src/insights-content/content/non_kernel/ansible_deprecated_repo/ANSIBLE_DEPRECATED_REPO",
    "error_key": "ANSIBLE_DEPRECATED_REPO",
    "generic": "Since the release of Ansible Engine 2.4, Red Hat will no longer provide future errata from the Extras repo but from a dedicated Ansible repo instead. New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled.\n",
    "condition": "Ansible package is installed and dedicated Ansible repo is not enabled",
    "description": "New Ansible Engine packages are inaccessible when dedicated Ansible repo is not enabled",
    "impact": "Compatibility Error",
    "likelihood": 2,
    "publish_date": "2018-04-16 10:03:16",
    "resolution_risk": "Update Package",
    "status": "active",
    "tags": [
      "sbr_services",
      "ansible"
    ],
    "playbooks": []
  }
]
"""

PLAYBOOK_CONTENT_JSON_UPDATE_2 = r"""
[{
    "reason": "Nasty alien mofos",
    "resolution": "Nuke em from orbit",
    "more_info": null,
    "category": "Stability",
    "component": "corosync",
    "name": "Cluster nodes are frequently fenced as realtime is not enabled in corosync",
    "node_id": "1602623",
    "product_code": "rhel",
    "python_module": "telemetry.rules.plugins.osp.corosync_enable_rt_schedule",
    "reboot_required": false,
    "role": "host",
    "plugin": "corosync_enable_rt_schedule",
    "rule_id": "corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT",
    "path": "/opt/app-root/src/insights-content/content/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT",
    "error_key": "COROSYNC_NOT_ENABLE_RT",
    "generic": "Cluster nodes are frequently fenced because the realtime scheduling priority is not enabled. This increases the possibility of corosync token losses.\n",
    "condition": "realtime is not enabled in corosync",
    "description": "Cluster nodes are frequently fenced as realtime is not enabled in corosync",
    "impact": "Cluster Availability",
    "likelihood": 2,
    "publish_date": "2016-10-31 04:08:34",
    "resolution_risk": "Update Package",
    "status": "active",
    "tags": [
      "openstack",
      "sbr_stack",
      "corosync"
    ],
    "playbooks": [
      {
        "resolution_risk": 1,
        "resolution_type": "fix",
        "play": "- name: Enable ansible repo and update ansible package\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Enable ansible repo\n      command: subscription-manager repos --enable=rhel-7-server-ansible-3-rpms\n\n    - name: Update ansible package\n      yum:\n        name: ansible\n        state: latest\n",
        "description": "Enable ansible repo and update ansible package",
        "path": "playbooks/non_kernel/ansible_deprecated_repo/ANSIBLE_DEPRECATED_REPO/rhel_host/fix_fixit.yml",
        "version": "1111111111111111111111111111111111111113"
      },
      {
        "resolution_risk": 1,
        "resolution_type": "mitigate",
        "play": "- name: Add \"-r\" into COROSYNC_OPTIONS option to mitigate and restart cluster\n  hosts: \"{{HOSTS}}\"\n  become: true\n\n  tasks:\n    - name: Add \"-r\" into COROSYNC_OPTIONS\n      lineinfile:\n        path: /etc/sysconfig/corosync\n        regexp: '^(COROSYNC_OPTIONS=\")(.*)(\")'\n        line: '\\1\\2 -r\\3'\n        backrefs: yes\n        backup: yes\n\n    - name: Stop pcs cluster\n      shell: pcs cluster stop\n\n    - name: Start pcs cluster\n      shell: pcs cluster start\n",
        "description": "Add \"-r\" into COROSYNC_OPTIONS option to mitigate and restart cluster",
        "path": "playbooks/osp/corosync_enable_rt_schedule/COROSYNC_NOT_ENABLE_RT/rhel_host/mitigate_fixit.yml",
        "version": "1111111111111111111111111111111111111113"
      }
    ]
  }
]
"""


# A cut-down version of the config.
CONFIG_JSON = r'''
{
  "impact": {
    "VM Clone Failure": 2, "Database Inconsistency": 4,
    "Malware Detected": 3, "Local Vulnerability": 2,
    "Container Creation Failure": 2, "Man In The Middle": 4,
    "Decreased Security": 2, "Network Performance Loss": 2,
    "Boot Failure": 3, "Container Inoperation": 3, "VM Start Failure": 3,
    "Kdump Fail": 1, "Invalid Configuration": 1, "System Stability Loss": 3,
    "Best Practice": 1, "Local Privilege Escalation": 2, "Hung Task": 2,
    "System Performance Loss": 2, "Storage Excessive Consumption": 2,
    "Database Availability": 2, "Diagnostics Failure": 1, "Packet Loss": 2,
    "Service Inoperation": 2, "Storage Performance Loss": 2,
    "VM Performance Loss": 2, "Management Availability": 2,
    "Cluster Availability": 2, "Inaccessible Storage": 3,
    "Database Performance Loss": 2, "Network Connectivity Loss": 3,
    "Service Crash": 2, "Support Unavailable": 1, "Compatibility Error": 2,
    "Insecure Encryption": 2, "Application Not Connectable": 2,
    "Unsupported Functionality": 3, "Information Disclosure": 3,
    "Service Inoperative": 2, "Denial Of Service": 3, "Hardening": 1,
    "Application Hang": 2, "Filesystem Corruption": 2, "Kernel Panic": 3,
    "Offline Storage": 2, "VM Migration Failure": 3,
    "Remote Vulnerability": 4, "Unsupported Packet": 1, "Data Loss": 4,
    "Suspicious Activity": 2, "Docker Metadata Inconsistency": 2,
    "Session Decryption Vulnerability": 3, "VM Crash": 2, "null": 1
  },
  "resolution_risk": {
    "Upgrade Openshift": 2, "Activate SELinux": 4, "Restart Container": 2,
    "Update Openshift Configuration": 2, "OpenStack Parameter Tuning": 2,
    "Hardware Vendor Firmware Update": 3, "Update Service Configuration": 3,
    "Reinstall Kernel": 2, "Remount Filesystem": 4, "Configure fstab": 3,
    "Docker Parameter Tuning": 2, "Use Unprivileged User": 4,
    "Upgrade RHV Hypervisor": 2, "Network Parameter Tuning": 2,
    "Clean Database": 4, "Update Module Parameter": 2, "Limits Tuning": 2,
    "Update Storage Configuration": 3, "Update JBoss Configuration": 2,
    "Eliminate Orphaned Semaphores": 2, "Sysctl Parameter Tuning": 2,
    "Install Package": 1, "Upgrade RHV Manager": 3, "Configure SELinux": 2,
    "Update Commonly Used Library": 4, "Update Ceph Deployment": 4,
    "Update Third-party Software": 2, "Hardware Vendor Analysis": 1,
    "Ceph Parameter Tuning": 2, "Clean Disk Space": 3, "Update Firewall": 3,
    "BIOS Parameter Adjustment": 2, "Update Grub Configuration": 4,
    "Pacemaker Parameter Tuning": 2, "Update Database Configuration": 2,
    "Update RHV Configuration": 2, "Configure Users or Groups": 3,
    "Openshift Parameter Tuning": 2, "Update Network Configuration": 3,
    "Inspect Hardware": 1, "Restart libvirtd": 3, "Upgrade Satellite": 3,
    "Update OpenStack Configuration": 2, "Storage Parameter Tuning": 2,
    "Update LVM Configuration": 4, "Contact Red Hat Support": 1,
    "Upgrade Kernel": 3, "Update Package": 1, "Rebuild RPM Database": 3,
    "Update Certificate": 1, "Apply kpatch for Kernel": 1, "null": 1,
    "Update File Permission": 4, "Adjust Service Status": 1,
    "Update Ceph Configuration": 2, "Remove Package": 3, "Adjust Time": 3,
    "RHV Storage Tuning": 3, "Update Registration Info": 1
  },
  "tags": {
    "kernel": ["sbr_kernel", "kernel"],
    "sysmgmt": ["sbr_sysmgmt", "satellite6"],
    "openstack": ["openstack", "sbr_stack", "hp", "hp_ilo", "corosync"],
    "storage": ["storage"],
    "services": ["sbr_services"],
    "security": ["security", "cve"],
    "other": ["ansible"]
  }
}
'''
# NB: tags are definitely cut down, if the tag lookup fails then check here.
content = json.loads(CONTENT_JSON)
updated_content = json.loads(CONTENT_JSON_UPDATE)
playbook_content = json.loads(PLAYBOOK_CONTENT_JSON)
updated_playbook_content = json.loads(PLAYBOOK_CONTENT_JSON_UPDATE)
config = json.loads(CONFIG_JSON)


class ImportContentTestCase(TestCase):
    fixtures = ['rulesets', 'system_types', 'rule_categories']

    def test_import_config_blank(self):
        """
        If there's no 'resolution risk' config, nothing happens and no stats
        are returned.
        """
        stats = import_content.update_resolution_risks_with_content({})
        self.assertIsNone(stats)

    def test_import_config_with_data(self):
        # Nothing up our sleeves:
        self.assertFalse(ResolutionRisk.objects.all().exists())
        # Now import the config
        import_content.update_resolution_risks_with_content(config)
        # And now we should have something there
        self.assertEqual(ResolutionRisk.objects.count(), 59)
        rule_model = ResolutionRisk.objects.get(name='Update File Permission')
        self.assertEqual(rule_model.name, 'Update File Permission')
        self.assertEqual(rule_model.risk, 4)

    def test_import_config_from_string_updates(self):
        # Nothing up our sleeves:
        self.assertFalse(ResolutionRisk.objects.all().exists())
        # Now import the config
        import_content.update_resolution_risks_with_content(config)
        # And now we should have something there
        self.assertEqual(ResolutionRisk.objects.count(), 59)
        self.assertEqual(ResolutionRisk.objects.get(name='Clean Database').risk, 4)
        self.assertEqual(ResolutionRisk.objects.get(name='Upgrade Kernel').risk, 3)
        self.assertEqual(ResolutionRisk.objects.get(name='Adjust Time').risk, 3)

        # Now do one update, one addition and one deletion.
        # Use initial data, otherwise everything that's missing is deleted.
        new_risks = dict(config['resolution_risk'])
        new_risks['Upgrade Kernel'] = 2  # updated
        new_risks['Berate Vendor'] = 3  # added
        del new_risks['Adjust Time']  # deleted
        # Update the content data
        stats = import_content.update_resolution_risks_with_content(
            {'resolution_risk': new_risks}
        )
        # Now, do we have updated content?
        self.assertEqual(ResolutionRisk.objects.count(), 59)
        self.assertEqual(ResolutionRisk.objects.get(name='Clean Database').risk, 4)
        self.assertEqual(ResolutionRisk.objects.get(name='Upgrade Kernel').risk, 2)
        self.assertEqual(ResolutionRisk.objects.get(name='Berate Vendor').risk, 3)
        self.assertEqual(ResolutionRisk.objects.filter(name='Adjust Time').count(), 0)
        # And do we get the right stats?
        self.assertEqual(stats['added'], 1)
        self.assertEqual(stats['updated'], 1)
        self.assertEqual(stats['same'], 57)
        self.assertEqual(stats['deleted'], 1)
        # We handled 60 objects in total, because the deleted and added
        # operations count in the stats but cancel themselves out in the total
        # objects remaining.

        # Test the update=True mode
        newer_risks = {
            'Clean Database': 4,  # same
            'Upgrade Kernel': 1,  # updated
            'Vacuum Filesystem': 2  # added
        }  # can't delete in update=True mode
        # Update the content data
        stats = import_content.update_resolution_risks_with_content(
            {'resolution_risk': newer_risks}, update=True
        )
        # Now, do we have updated content?
        self.assertEqual(ResolutionRisk.objects.count(), 60)
        self.assertEqual(ResolutionRisk.objects.get(name='Clean Database').risk, 4)
        self.assertEqual(ResolutionRisk.objects.get(name='Upgrade Kernel').risk, 1)
        self.assertEqual(ResolutionRisk.objects.get(name='Berate Vendor').risk, 3)
        self.assertEqual(ResolutionRisk.objects.get(name='Vacuum Filesystem').risk, 2)
        self.assertEqual(ResolutionRisk.objects.filter(name='Adjust Time').count(), 0)
        # And do we get the right stats?
        self.assertEqual(stats['added'], 1)
        self.assertEqual(stats['updated'], 1)
        self.assertEqual(stats['same'], 58)  # including all risks not mentioned
        self.assertEqual(stats['deleted'], 0)

    def test_import_new_content_bad_entries(self):
        # Import the config, since we need resolution risks
        import_content.update_resolution_risks_with_content(config)
        # Exercise a few code paths
        stats = import_content.update_ruleset_with_content([
            {
                'no_python_module': True
            }, {
                'python_module': 'ignored',
                'no_rule_id': True,
            }, {
                'python_module': 'ignored because no matching ruleset',
                'rule_id': 'ignored',
            }
        ])
        # No errors, just nothing happened.
        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 0)
        self.assertEqual(stats['same'], 0)
        self.assertEqual(stats['deleted'], 0)

    def test_import_new_content_from_string(self):
        # Nothing up our sleeves:
        self.assertFalse(Rule.objects.filter(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        ).exists())
        # Now import the content
        stats = import_content.import_all(config, content)

        # And we should have something there:
        self.assertTrue(Rule.objects.filter(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        ).exists())
        # So test the rule properties we expect to be filled from the data
        rule_model = Rule.objects.get(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        )
        self.assertTrue(rule_model.active)
        self.assertEqual(rule_model.description, "Performance degradation of I/O when commands timeout due to faulty storage hardware")
        self.assertEqual(rule_model.reboot_required, False)
        # Note conversion into UTC
        self.assertEqual(rule_model.publish_date, datetime(
            2016, 10, 31, 4, 8, 30, tzinfo=pytz.UTC
        ))
        self.assertEqual(rule_model.node_id, '')
        self.assertEqual(rule_model.generic, "\"Abort Command Issued\" messages are being detected, which are indicative of a storage area network (SAN) or hardware error.\n\nVerify if there are any issues present from the FC switch, FC cabling, zoning, or storage array. Red Hat recommends that you contact the storage vendor to review the issue encountered.")
        self.assertEqual(rule_model.summary, "Occurrences of the message \"Abort Command Issued\" indicate an error condition being returned from the storage area network (SAN).")
        self.assertEqual(rule_model.reason, "This host has encountered **{{=pydata.total_aborts}}** occurrences of *Abort command issued* in /var/log/messages, including {{?pydata.abort_groups > 1}}multiple occurrences{{??}}1 occurrence{{?}} of 10 or more abort commands occurring within a period of an hour.  \n\n*Abort command issued* messages indicate an error condition being returned from the SAN.\n\nAn example abort command that is displayed in /var/log/messages: \n\n**{{=pydata.example_abort}}**")
        self.assertEqual(rule_model.more_info, '')
        # Calculated fields:
        self.assertEqual(rule_model.total_risk, 2)

        # Tags have been set correctly
        self.assertEqual(
            list(rule_model.tags.order_by('name').values_list('name', flat=True)),
            ["kernel", "sbr_kernel", "storage"]
        )

        # And the resolution we expect to have been explicitly created.
        # For ABORT_COMMAND_ISSUED, we have one resolution:
        self.assertEqual(rule_model.resolution_set.count(), 1)
        resolution = rule_model.resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Red Hat recommends that you verify if there are any issues present from the FC switch, FC cabling, zoning, or storage array and contact the storage vendor to review the switch logs to verify if there are any error counters, CRC errors in FC switch logs to solve this issue.\n")
        self.assertEqual(resolution.resolution_risk.name, "Hardware Vendor Analysis")
        self.assertEqual(resolution.resolution_risk.risk, 1)
        self.assertFalse(resolution.has_playbook)

        # Test that a rule with multiple resolutions is added once, but its
        # resolutions are separate:
        self.assertTrue(Rule.objects.filter(rule_id="ilo|HP_ILO_ISSUE").exists())
        self.assertEqual(Rule.objects.filter(rule_id="ilo|HP_ILO_ISSUE").count(), 1)
        # So test the rule properties we expect to be filled from the data
        ilo_model = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE")
        self.assertTrue(ilo_model.active)
        self.assertEqual(ilo_model.description, "Memory corruption and subsequent kernel panics when hp-health service running on HP ProLiant G7 systems with specific iLO 3 firmware version")
        self.assertEqual(ilo_model.reboot_required, False)
        self.assertEqual(ilo_model.node_id, '744973')
        # Check that it has two resolutions, and they differ by system type
        self.assertEqual(ilo_model.resolution_set.count(), 2)
        self.assertEqual(ilo_model.resolution_set.filter(system_type__role='host').count(), 1)
        self.assertEqual(ilo_model.resolution_set.filter(system_type__role='hypervisor').count(), 1)
        # Calculated fields:
        self.assertEqual(rule_model.total_risk, 2)

        # A rule with an invalid publish date should not have one.
        dfcli_query = Rule.objects.filter(rule_id="sat6_dynflow_core_log|DYNFLOW_CORE_LOG_ISSUE")
        self.assertTrue(dfcli_query.exists())
        dfcli_model = dfcli_query[0]
        self.assertFalse(dfcli_model.active)
        self.assertIsNone(dfcli_model.publish_date)

        # The stats should reflect that we had two new rules and one same
        # i.e. same content, different resolution
        self.assertEqual(stats['content']['added'], 3)
        self.assertEqual(stats['content']['updated'], 0)
        self.assertEqual(stats['content']['same'], 1)
        self.assertEqual(stats['content']['deleted'], 0)

        # Now that we've got some content there, test that we can update a
        # rule and update the resolution of an existing rule.
        # Note, rule 'ilo|HP_ILO_ISSUE' is active in the DB but missing from the content so it is deleted
        stats = import_content.update_ruleset_with_content(updated_content)
        rule_model = Rule.objects.get(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        )
        self.assertFalse(rule_model.active)
        self.assertIsNone(rule_model.publish_date)
        # check the rule's summary field is NOT a copy of the generic field
        self.assertEqual(rule_model.generic, "Updated rule generic information")
        self.assertEqual(rule_model.summary, "Updated rule summary information")
        self.assertEqual(rule_model.resolution_set.count(), 1)
        self.assertEqual(rule_model.resolution_set.all()[0].resolution, "Updated resolution")
        self.assertTrue(rule_model.resolution_set.first().has_playbook)
        self.assertEqual(rule_model.resolution_set.first().playbook_set.first().type, "fixer")
        self.assertEqual(
            list(rule_model.tags.order_by('name').values_list('name', flat=True)),
            ["kernel", "performance", "storage"]
        )

        # The stats should reflect that updated one rule, resolution stats
        # are not tracked.
        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 1)
        self.assertEqual(stats['same'], 0)
        self.assertEqual(stats['deleted'], 2)

        # Do another update but setting the generic field to null for ABORT_COMMAND_ISSUED
        # This is to further confirm that generic and summary fields have the same value, even when null
        import_content.update_ruleset_with_content(
            json.loads(CONTENT_JSON_UPDATE.replace('"Updated rule generic information"', "null"))
        )
        rule_model = Rule.objects.get(rule_id="abort_command_issued|ABORT_COMMAND_ISSUED")
        self.assertEqual(rule_model.generic, "")
        self.assertEqual(rule_model.summary, "Updated rule summary information")

    def test_import_playbook_missing_keys(self):
        # Simulate a problem we saw with content missing
        import_content.import_all(config, content)
        missing_key_content = copy(updated_content)
        missing_key_content[0]['playbooks'][0].pop('version')
        stats = import_content.update_ruleset_with_content(missing_key_content)
        # The rule might have been updated...
        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 1)
        self.assertEqual(stats['same'], 0)
        self.assertEqual(stats['deleted'], 2)
        # but the rule won't have new playbooks
        rule_model = Rule.objects.get(rule_id="abort_command_issued|ABORT_COMMAND_ISSUED")
        self.assertEqual(rule_model.playbooks().count(), 0)

    def test_import_new_playbook_content(self):
        # Load and test some resolutions with playbooks
        import_content.import_all(config, playbook_content)
        self.assertTrue(Rule.objects.filter(rule_id="corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT").exists())
        self.assertTrue(Rule.objects.filter(rule_id="ansible_deprecated_repo|ANSIBLE_DEPRECATED_REPO").exists())

        corosync = Rule.objects.get(rule_id="corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT").resolution_set.first()
        ansible = Rule.objects.get(rule_id="ansible_deprecated_repo|ANSIBLE_DEPRECATED_REPO").resolution_set.first()
        self.assertTrue(corosync.has_playbook)
        self.assertEqual(corosync.playbook_set.count(), 3)
        self.assertEqual(set([p.type for p in corosync.playbook_set.all()]),
                         {'workaround', 'update_specific', 'update_latest'})
        self.assertTrue(ansible.has_playbook)
        self.assertEqual(ansible.playbook_set.count(), 1)

        # Update the resolutions with playbooks
        # - tests removing playbook files and adding a new one
        import_content.update_ruleset_with_content(updated_playbook_content)
        corosync = Rule.objects.get(rule_id="corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT").resolution_set.first()
        ansible = Rule.objects.get(rule_id="ansible_deprecated_repo|ANSIBLE_DEPRECATED_REPO").resolution_set.first()
        self.assertTrue(corosync.has_playbook)
        self.assertEqual(corosync.playbook_set.count(), 2)
        self.assertEqual(set([(p.type, p.version) for p in corosync.playbook_set.all()]),
                         {('workaround', '1111111111111111111111111111111111111111'),
                          ('fix', '1111111111111111111111111111111111111112')})
        self.assertIn('rhel-7-server-ansible-2-rpms', corosync.playbook_set.get(type='fix').play)
        self.assertFalse(ansible.has_playbook)

        # Update the playbooks again
        # - tests changing one of the plays slightly and renaming one of the playbook files/type
        import_content.update_ruleset_with_content(json.loads(PLAYBOOK_CONTENT_JSON_UPDATE_2))
        corosync = Rule.objects.get(rule_id="corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT").resolution_set.first()
        self.assertEqual(corosync.playbook_set.count(), 2)
        self.assertEqual(set([(p.type, p.version) for p in corosync.playbook_set.all()]),
                         {('mitigate', '1111111111111111111111111111111111111113'),
                          ('fix', '1111111111111111111111111111111111111113')})
        self.assertEqual(list(corosync.playbook_set.filter(type='workaround')), [])
        self.assertNotIn('rhel-7-server-ansible-2-rpms', corosync.playbook_set.get(type='fix').play)
        self.assertIn('rhel-7-server-ansible-3-rpms', corosync.playbook_set.get(type='fix').play)

        # Update the playbooks yet again, but don't update the version
        # This shouldn't happen (the version should always be updated) but is here for completeness
        # - tests changing one of the plays slightly but not updating the version - no changes should be made
        import_content.update_ruleset_with_content(json.loads(PLAYBOOK_CONTENT_JSON_UPDATE_2.replace(
            'rhel-7-server-ansible-3-rpms', 'rhel-7-server-ansible-4-rpms')))
        corosync = Rule.objects.get(rule_id="corosync_enable_rt_schedule|COROSYNC_NOT_ENABLE_RT").resolution_set.first()
        # Because the version wasn't updated, no changes should've been made
        self.assertIn('rhel-7-server-ansible-3-rpms', corosync.playbook_set.get(type='fix').play)
        self.assertNotIn('rhel-7-server-ansible-4-rpms', corosync.playbook_set.get(type='fix').play)

    def test_import_publish_date_issues(self):
        # Load and test content with different date formats
        # Missing seconds, should still be able convert this to a datetime
        import_content.import_all(config, json.loads(DATE_FORMAT_CONTENT_JSON))  # 2018-12-03 12:00
        rule_model = Rule.objects.get(rule_id="CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD")
        self.assertEqual(rule_model.publish_date, datetime(2018, 12, 3, 12, 0, tzinfo=pytz.UTC))

        # Missing minutes and seconds, bit weird so don't convert it and set the date to None
        import_content.update_ruleset_with_content(
            json.loads(DATE_FORMAT_CONTENT_JSON.replace("2018-12-03 12:00", "2018-12-03 12")))
        rule_model = Rule.objects.get(rule_id="CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD")
        self.assertIsNone(rule_model.publish_date)

        # Missing the time completely, still ok and should become midnight
        import_content.update_ruleset_with_content(
            json.loads(DATE_FORMAT_CONTENT_JSON.replace("2018-12-03 12:00", "2018-12-03")))
        rule_model = Rule.objects.get(rule_id="CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD")
        self.assertEqual(rule_model.publish_date, datetime(2018, 12, 3, 0, 0, tzinfo=pytz.UTC))

        # Ok this can't be converted to a date, make it None
        import_content.update_ruleset_with_content(
            json.loads(DATE_FORMAT_CONTENT_JSON.replace("2018-12-03 12:00", "OUTATIME")))
        rule_model = Rule.objects.get(rule_id="CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD")
        self.assertIsNone(rule_model.publish_date)

        # Null publish_date should become None
        import_content.update_ruleset_with_content(
            json.loads(DATE_FORMAT_CONTENT_JSON.replace("2018-12-03 12:00", "null")))
        rule_model = Rule.objects.get(rule_id="CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD")
        self.assertIsNone(rule_model.publish_date)

    def test_nodeid_issues(self):
        # Load and test a rule for which we will change node_id values
        # node_id is an integer in the content, but a string in the model
        stats = import_content.import_all(config, json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        rule_model = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE")
        self.assertEqual(rule_model.node_id, "744973")
        self.assertIsInstance(rule_model.node_id, str)

        self.assertEqual(stats['content']['added'], 1)
        self.assertEqual(stats['content']['updated'], 0)
        self.assertEqual(stats['content']['same'], 0)

        # Try using a string node_id but with the same value ... shouldn't be any changes
        stats = import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON.replace("744973", '"744973"')))
        rule_model = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE")
        self.assertEqual(rule_model.node_id, "744973")

        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 0)
        self.assertEqual(stats['same'], 1)

        # Change the node_id to a different value but use a string ... should change
        stats = import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON.replace("744973", '"1234567"')))
        rule_model = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE")
        self.assertEqual(rule_model.node_id, "1234567")
        self.assertIsInstance(rule_model.node_id, str)

        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 1)
        self.assertEqual(stats['same'], 0)

        # Now use the same node_id value as above, but this time an integer ... shouldn't be any changes
        stats = import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON.replace("744973", "1234567")))
        rule_model = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE")
        self.assertEqual(rule_model.node_id, "1234567")
        self.assertIsInstance(rule_model.node_id, str)

        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 0)
        self.assertEqual(stats['same'], 1)

    def test_resolution_issues(self):
        # Load and test a rule for which we will change resolution values
        stats = import_content.import_all(config, json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor")

        self.assertEqual(stats['content']['added'], 1)
        self.assertEqual(stats['content']['updated'], 0)
        self.assertEqual(stats['content']['same'], 0)

        # No change in resolution ... so nothing changes in the model
        stats = import_content.update_ruleset_with_content(json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor")

        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 0)
        self.assertEqual(stats['same'], 1)

        # Add a small change to the resolution string ... should change in the model, but not the stats
        stats = import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON.replace("vendor", "vendor.")))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor.")

        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 0)
        self.assertEqual(stats['same'], 1)

        # Another small change to the resolution string ... again, should change in the model, but not the stats
        stats = import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON.replace("vendor", "vendor!")))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor!")
        self.assertEqual(resolution.resolution_risk.name, "Hardware Vendor Firmware Update")

        self.assertEqual(stats['added'], 0)
        self.assertEqual(stats['updated'], 0)
        self.assertEqual(stats['same'], 1)

    def test_resolution_risk_issues(self):
        # Load and test a rule for which we will change resolution values
        import_content.import_all(config, json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor")
        self.assertEqual(resolution.resolution_risk.name, "Hardware Vendor Firmware Update")
        self.assertEqual(resolution.resolution_risk.risk, 3)

        # No change in resolution or resolution risk in the content ... so nothing changes in the model
        import_content.update_ruleset_with_content(json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor")
        self.assertEqual(resolution.resolution_risk.name, "Hardware Vendor Firmware Update")

        # Just change the resolution risk in the content ... it should change in the model too
        import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON
                       .replace("Hardware Vendor Firmware Update", "Hardware Vendor Analysis")))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor")
        self.assertEqual(resolution.resolution_risk.name, "Hardware Vendor Analysis")
        self.assertEqual(resolution.resolution_risk.risk, 1)

        # Change both the resolution and resolution risk in the content ... should change in the model too
        import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON
                       .replace("vendor", "vendor!")
                       .replace("Hardware Vendor Firmware Update", "Update Storage Configuration")))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor!")
        self.assertEqual(resolution.resolution_risk.name, "Update Storage Configuration")
        self.assertEqual(resolution.resolution_risk.risk, 3)

        # Use the same resolution value in the content (will match what's in the DB so no change there)
        # But change the resolution risk value again in the content ... should change in the model too
        import_content.update_ruleset_with_content(
            json.loads(RESOLUTION_NODEID_CONTENT_JSON
                       .replace("vendor", "vendor!")
                       .replace("Hardware Vendor Firmware Update", "Activate SELinux")))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor!")
        self.assertEqual(resolution.resolution_risk.name, "Activate SELinux")
        self.assertEqual(resolution.resolution_risk.risk, 4)

        # Restore the original content, which is different to what's in the DB
        # So this will restore the resolution and resolution risk models too
        import_content.update_ruleset_with_content(json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        resolution = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE").resolution_set.all()[0]
        self.assertEqual(resolution.resolution, "Contact your hardware vendor")
        self.assertEqual(resolution.resolution_risk.name, "Hardware Vendor Firmware Update")
        self.assertEqual(resolution.resolution_risk.risk, 3)

    def test_null_impact_issues(self):
        # Load and test a rule which has None for impact (to similate the problem we had)
        # The content should import so that the rule imact is the 'null' impact
        import_content.import_all(config, json.loads(CONTENT_JSON_UPDATE.replace('"Storage Performance Loss"', "null")))
        rule_impact = Rule.objects.get(rule_id='abort_command_issued|ABORT_COMMAND_ISSUED').impact
        self.assertEqual(rule_impact.name, "null")

        # Re-import the content and change it back to "Storage Performance Loss"
        import_content.update_ruleset_with_content(json.loads(CONTENT_JSON_UPDATE))
        rule_impact = Rule.objects.get(rule_id='abort_command_issued|ABORT_COMMAND_ISSUED').impact
        self.assertEqual(rule_impact.name, "Storage Performance Loss")

        # Re-import the content and change it back to None.  Impact should be the 'null' impact again
        # This tests a different code path than the first test above
        import_content.update_ruleset_with_content(json.loads(CONTENT_JSON_UPDATE.replace('"Storage Performance Loss"', "null")))
        rule_impact = Rule.objects.get(rule_id='abort_command_issued|ABORT_COMMAND_ISSUED').impact
        self.assertEqual(rule_impact.name, "null")

    def test_cve_rule_import(self):
        # CVE rules are disabled by default if the environment variable DISABLE_CVE_RULES is missing (or True)

        # Test adding new CVE rule with CVE rules disabled by default - expect CVE rule to be inactive
        import_content.import_all(config, json.loads(CVE_CONTENT_JSON))
        cve_rule = Rule.objects.get(rule_id="heartbleed|HAS_HEARTBLEED")
        self.assertEqual(cve_rule.active, False)

        # Test updating existing CVE rule with CVE rules disabled by default - expect CVE rule to still be inactive
        import_content.update_ruleset_with_content(json.loads(CVE_CONTENT_JSON))
        cve_rule = Rule.objects.get(rule_id="heartbleed|HAS_HEARTBLEED")
        self.assertEqual(cve_rule.active, False)

        # Test adding new non-CVE rules with CVE rules disabled - expect non-CVE rule to be active
        import_content.update_ruleset_with_content(json.loads(RESOLUTION_NODEID_CONTENT_JSON))
        non_cve_rule = Rule.objects.get(rule_id="ilo|HP_ILO_ISSUE")
        self.assertEqual(non_cve_rule.active, True)

        # Tests of CVE rule identification
        # CVE rules are identified as having the 'cve' tag.  Prodsec said that's how CVE rules
        # will be named going forward, so this identification method should be ok.

        # Test removing the 'cve' tag - not a CVE rule anymore so it will be active
        # Even though the name and description have CVE-xxxx in it, its not a CVE without the cve tag
        import_content.update_ruleset_with_content(json.loads(CVE_CONTENT_JSON.replace('cve', 'kernel')))
        cve_rule = Rule.objects.get(rule_id="heartbleed|HAS_HEARTBLEED")
        self.assertEqual(cve_rule.active, True)

        # Test changing the name/description - doesn't matter - its still a CVE rule because of the cve tag match
        import_content.update_ruleset_with_content(json.loads(CVE_CONTENT_JSON.replace('CVE-2014-0160: ', '')))
        cve_rule = Rule.objects.get(rule_id="heartbleed|HAS_HEARTBLEED")
        self.assertEqual(cve_rule.active, False)

        # Test removing the 'cve' tag and changing the name/description - not identified as a CVE rule now
        import_content.update_ruleset_with_content(json.loads(CVE_CONTENT_JSON.replace('cve', 'kernel')
                                                              .replace('CVE-2014-0160: ', '')))
        cve_rule = Rule.objects.get(rule_id="heartbleed|HAS_HEARTBLEED")
        self.assertEqual(cve_rule.active, True)

        # Tests with cve rules enabled.  This is very unlikely, but done for completeness anyway
        environ['DISABLE_CVE_RULES'] = 'false'

        # Test adding new CVE rule with CVE rules enabled - expect CVE rule to be active
        import_content.update_ruleset_with_content(json.loads(DATE_FORMAT_CONTENT_JSON))
        cve_rule = Rule.objects.get(rule_id="CVE_2018_19788_polkit|CVE_2018_19788_POLKIT_UID_BAD")
        self.assertEqual(cve_rule.active, True)

        # Test updating existing CVE rule with CVE rules enabled - expect CVE rule to be active now
        import_content.update_ruleset_with_content(json.loads(CVE_CONTENT_JSON))
        cve_rule = Rule.objects.get(rule_id="heartbleed|HAS_HEARTBLEED")
        self.assertEqual(cve_rule.active, True)


class ImportContentViewTestCase(TestCase):
    fixtures = ['rulesets', 'system_types', 'rule_categories']

    def _check_import_results(self, response):
        self.assertEqual(response.status_code, 200, response.content)
        # Test that content type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        # Decode as JSON or fail!
        stats_data = response.json()
        # What we get should be statistics data
        for stat in ('resolution_risks', 'impacts', 'content'):
            self.assertIn(stat, stats_data['stats'])
            self.assertIn('added', stats_data['stats'][stat])
            self.assertIn('updated', stats_data['stats'][stat])
            self.assertIn('same', stats_data['stats'][stat])
            self.assertIn('deleted', stats_data['stats'][stat])

        # And there should be data in the database.
        self.assertTrue(Rule.objects.filter(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        ).exists())

    def _check_import_stats(self, response, type=None):
        stats = response.json()['stats']
        if type == 'new':
            self.assertEqual(stats['content']['added'], 3)
            self.assertEqual(stats['content']['updated'], 0)
            self.assertEqual(stats['content']['same'], 1)
            self.assertEqual(stats['content']['deleted'], 0)
        elif type == 'same':
            self.assertEqual(stats['content']['added'], 0)
            self.assertEqual(stats['content']['updated'], 0)
            self.assertEqual(stats['content']['same'], 4)
            self.assertEqual(stats['content']['deleted'], 0)
        elif type == 'update':
            self.assertEqual(stats['content']['added'], 0)
            self.assertEqual(stats['content']['updated'], 1)
            self.assertEqual(stats['content']['same'], 0)
            self.assertEqual(stats['content']['deleted'], 2)
        else:
            assert False

    def test_import_content_get(self):
        # 'GET' method not allowed.
        response = self.client.get(reverse('import_content-list'))
        self.assertEqual(response.status_code, 405)

    def test_import_content_push_application_json(self):
        # Push the data as application/json (recommended content-type)
        # Nothing up our sleeves:
        self.assertFalse(Rule.objects.filter(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        ).exists())

        # Import the data for the first time
        json_data = {'config': json.loads(CONFIG_JSON), 'content': json.loads(CONTENT_JSON)}
        response = self.client.post(reverse('import_content-list'), data=json_data,
                                    content_type='application/json')
        self.assertIn("application/json", response.request['CONTENT_TYPE'])
        self._check_import_results(response)
        self._check_import_stats(response, type='new')

        # Re-import the same data, no changes
        json_data = {'config': json.loads(CONFIG_JSON), 'content': json.loads(CONTENT_JSON)}
        response = self.client.post(reverse('import_content-list'), data=json_data,
                                    content_type='application/json')
        self._check_import_results(response)
        self._check_import_stats(response, type='same')

        # Update the data, should be changes
        json_data = {'config': json.loads(CONFIG_JSON), 'content': json.loads(CONTENT_JSON_UPDATE)}
        response = self.client.post(reverse('import_content-list'), data=json_data,
                                    content_type='application/json')
        self._check_import_results(response)
        self._check_import_stats(response, type='update')

    def test_import_content_push_non_json(self):
        # Push the data as multipart/urlencoded form data (not recommended content-type but accepted)
        # Its the default content-type if not explicitly set

        # Nothing up our sleeves:
        self.assertFalse(Rule.objects.filter(
            rule_id="abort_command_issued|ABORT_COMMAND_ISSUED"
        ).exists())

        # Import the data for the first time
        response = self.client.post(reverse('import_content-list'), data={
            'config': CONFIG_JSON, 'content': CONTENT_JSON
        })
        self.assertIn("multipart/form-data", response.request['CONTENT_TYPE'])
        self._check_import_results(response)
        self._check_import_stats(response, type='new')

        # Re-import the same data, no changes
        response = self.client.post(reverse('import_content-list'), data={
            'config': CONFIG_JSON, 'content': CONTENT_JSON
        })
        self._check_import_results(response)
        self._check_import_stats(response, type='same')

        # Update the data, should be changes
        response = self.client.post(reverse('import_content-list'), data={
            'config': CONFIG_JSON, 'content': CONTENT_JSON_UPDATE
        })
        self._check_import_results(response)
        self._check_import_stats(response, type='update')

    def test_import_content_push_failures(self):
        # Missing fields
        response = self.client.post(reverse('import_content-list'), data={
            'config': ''
        }, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Config or content fields were not present")

        # Fields that don't decode as JSON for non application/json ...
        response = self.client.post(reverse('import_content-list'), data={
            'config': '{aardvark', 'content': '}wysiwig?,]{]'
        })
        self.assertIn("multipart/form-data", response.request['CONTENT_TYPE'])
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Expecting property name enclosed in double quotes", response.content)

        # ... but do parse as JSON when using application/json
        # Note that because we're using the Client's data parameter, these
        # get converted from Python objects - in this case strings - into JSON,
        # so there's no 'failure to convert the JSON' in this case.
        response = self.client.post(reverse('import_content-list'), data={
            'config': '{aardvark', 'content': '}wysiwig?,]{]'
        }, content_type='application/json')
        self.assertIn("application/json", response.request['CONTENT_TYPE'])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Config parses as JSON but isn't a dictionary")

        # No resolution_risk in config data, but is a dict
        response = self.client.post(reverse('import_content-list'), data={
            'config': {}, 'content': []
        }, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Config parses as JSON but doesn't have resolution_risk data")

        # No rule ID in content data
        response = self.client.post(reverse('import_content-list'), data={
            'config': {'resolution_risk': {}}, 'content': [{'foo': 'bar'}]
        }, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Content parses as JSON but doesn't look like a list of rules")

        # Valid config/content data but invalid content-type
        json_data = {'config': json.loads(CONFIG_JSON), 'content': json.loads(CONTENT_JSON)}
        response = self.client.post(reverse('import_content-list'), data=json_data, content_type='application/jason')
        self.assertEqual(response.status_code, 415)


# Create config and content that matches the data from the basic_test_data fixture
# This is to simulate renaming rule_ids for existing rules and as well as changing their impacts
BASIC_TEST_DATA_CONFIG = r"""
{
  "impact": {
    "Best Practice": 1,
    "Database Inconsistency": 4,
    "Invalid Configuration": 1,
    "null": 1
  },
  "resolution_risk": {
    "Adjust Service Status": 1,
    "BIOS Parameter Adjustment": 2,
    "Hardware Vendor Firmware Update": 3,
    "Activate SELinux": 4
  },
  "tags": {
    "container": ["docker"],
    "idm": ["idm"],
    "kernel": ["kernel"],
    "sysmgmt": ["satellite"],
    "storage": ["xfs"],
    "security": ["security"],
    "other" : ["active", "acked", "testing", "deleted", "inactive", "not-yet-active",
              "second", "anonymous", "highest", "incident",
              "replaceme1", "replaceme2", "autoack"]
  }
}"""

BASIC_TEST_DATA_CONTENT = r"""[
{
  "status": "active",
  "impact": "Invalid Configuration",
  "python_module": "telemetry.rules.plugins.kernel.active_rule",
  "description": "Active rule",
  "tags": [
    "active",
    "testing",
    "kernel",
    "replaceme1"
  ],
  "reboot_required": false,
  "reason": "This rule has\n DoT syntax object {{=pydata.active}} still *embedded* in HTML",
  "node_id": "1048576",
  "likelihood": 1,
  "notif_action": null,
  "product_code": "rhel",
  "category": "Availability",
  "generic": "markdown can include:\n\n* bullet lists\n* block quotations:\n\n    Shall I compare thee to a summer's day?\n\n* *italic* and **bold** markup.\n\n~~~\n10 PRINT 'FENCED CODE'\n20 GOTO 10\n~~~\n",
  "resolution_risk": "Adjust Service Status",
  "playbooks": [{
        "resolution_risk": 1,
        "resolution_type": "fixit",
        "play": "- name: Active rule playbook",
        "description": "Fix for test|Active_rule on rhel/host",
        "path": "/tmp/playbooks/test|Active_rule/fixit.yaml",
        "version": "e64829e009379e7f80e967eecf7a56c91a250afb"
  }],
  "role": "host",
  "publish_date": "2018-05-23 15:38:55",
  "resolution": "In order to fix this problem, {{=pydata.active}} must equal **bar**",
  "rule_id": "test|Active_rule",
  "more_info": "DoT {{=pydata.active}} active and **mark-up**\n\n* list 1\n  ~~~\n  Code block inside indent\n  ~~~\n* list 2\n",
  "component": "Active rule component"
},
{
  "status": "inactive",
  "impact": "Best Practice",
  "python_module": "telemetry.rules.plugins.kernel.inactive_rule",
  "description": "Inactive rule",
  "tags": [
    "inactive",
    "satellite",
    "testing"
  ],
  "reboot_required": false,
  "reason": "Inactive rule should have {{=pydata.inactive}} inactive content",
  "node_id": "1048577",
  "likelihood": 1,
  "notif_action": null,
  "product_code": "rhel",
  "category": "Security",
  "generic": "Inactive rule",
  "resolution_risk": "Adjust Service Status",
  "playbooks": [],
  "role": "host",
  "publish_date": "2018-05-23 15:38:55",
  "resolution": "This rule is inactive and can no longer be resolved by {{=pydata.inactive}}",
  "rule_id": "test|Inactive_rule",
  "more_info": null,
  "component": "Inactive rule component"
},
{
  "status": "active",
  "impact": "Best Practice",
  "python_module": "telemetry.rules.plugins.kernel.acked_rule",
  "description": "Acked rule",
  "tags": [
    "active",
    "acked",
    "idm",
    "testing"
  ],
  "reboot_required": false,
  "reason": "Acked rule content with {{=pydata.acked}} DoT information",
  "node_id": "1048578",
  "likelihood": 1,
  "notif_action": null,
  "product_code": "rhel",
  "category": "Stability",
  "generic": "Acked rule",
  "resolution_risk": "Adjust Service Status",
  "playbooks": [],
  "role": "host",
  "publish_date": "2018-05-23 15:38:55",
  "resolution": "In order to fix this problem, {{=pydata.acked}} must equal **baz**",
  "rule_id": "test|Acked_rule",
  "more_info": null,
  "component": "Acked rule component"
},
{
  "status": "active",
  "impact": "Best Practice",
  "python_module": "telemetry.rules.plugins.kernel.second_rule",
  "description": "Second rule, which has no node_id",
  "tags": [
    "active",
    "second",
    "kernel",
    "testing",
    "replaceme2"
  ],
  "reboot_required": false,
  "reason": "Rule data {{=pydata.second}} with ūñïċøđê",
  "node_id": "",
  "likelihood": 1,
  "notif_action": null,
  "product_code": "rhev",
  "category": "Performance",
  "generic": "This rule should apply to one system but not another",
  "resolution_risk": "Adjust Service Status",
  "playbooks": [],
  "role": "manager",
  "publish_date": "2018-09-23 15:38:55",
  "resolution": "Secondary rule resolution content with {{=pydata.second}} engaged",
  "rule_id": "test|Second_rule",
  "more_info": "DoT {{=pydata.second}} second and **mark-up**",
  "component": "Second rule component"
},
{
  "status": "inactive",
  "impact": "Best Practice",
  "python_module": "telemetry.rules.plugins.kernel.rule_not_yet_active",
  "description": "Rule that hasn't yet been activated",
  "tags": [
    "not-yet-active",
    "xfs",
    "testing"
  ],
  "reboot_required": false,
  "reason": "Not yet activated rule with {{=pydata.notactivated}} content",
  "node_id": "",
  "likelihood": 1,
  "notif_action": null,
  "product_code": "rhel",
  "category": "Performance",
  "generic": "A rule that hasn't yet been activated, and with no node ID",
  "resolution_risk": "Adjust Service Status",
  "role": "host",
  "playbooks": [],
  "publish_date": null,
  "resolution": "This rule has {{=pydata.notactivated}} yet",
  "rule_id": "test|Rule_not_yet_activated",
  "more_info": null
}]"""


class ImportContentRuleRenamingTestCase(TestCase):
    # Setup the test database with the basic_test_data fixture
    fixtures = ['rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data']

    def test_fixture_matches_test_data(self):
        # Test that the data we've got in BASIC_TEST_DATA_CONTENT matches our
        # fixture data.  If not, then we need to change the content here,
        # because other tests here assume that they match exactly.
        this_content = json.loads(BASIC_TEST_DATA_CONTENT)
        fixt_rules = {
            rule.rule_id: rule
            for rule in Rule.objects.all()
        }
        for this_rule in this_content:
            self.assertIn('rule_id', this_rule)
            self.assertIn(this_rule['rule_id'], fixt_rules)
            fixt_rule = fixt_rules[this_rule['rule_id']]
            for field in (
                'description', 'reason', 'generic', 'more_info',
            ):
                self.assertIn(field, this_rule)
                if this_rule['more_info'] is None and fixt_rule.more_info == '':
                    continue
                self.assertEqual(
                    this_rule[field], getattr(fixt_rule, field),
                    f"Field {field} in rule {this_rule['rule_id']} mismatch"
                )
            fixt_res = fixt_rule.resolution_set.get(
                system_type__product_code=this_rule['product_code'],
                system_type__role=this_rule['role'],
            )
            self.assertEqual(fixt_res.resolution, this_rule['resolution'])

    def test_rule_renaming(self):
        # Import the config and content that matches the basic_test_data fixture
        # This simulates importing the same content with nothing changed
        stats = import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG),
                                          json.loads(BASIC_TEST_DATA_CONTENT))
        self.assertEqual(stats['content']['added'], 0)
        self.assertEqual(stats['content']['updated'], 1)
        self.assertEqual(stats['content']['same'], 4)
        self.assertEqual(stats['content']['deleted'], 1)

        # The rule should exist in the DB and should be active
        self.assertTrue(Rule.objects.filter(rule_id="test|Active_rule").exists())
        rule = Rule.objects.get(rule_id="test|Active_rule")
        self.assertTrue(rule.active)
        self.assertEqual(rule.impact.name, "Invalid Configuration")
        self.assertEqual(rule.resolution_set.first().resolution_risk.name, "Adjust Service Status")

        # Reimport content with rule "test|Active_rule" renamed to "test|Active_rule_2"
        stats = import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG),
                                          json.loads(BASIC_TEST_DATA_CONTENT.replace('"test|Active_rule"', '"test|Active_rule_2"')))
        self.assertEqual(stats['content']['added'], 1)  # Added test|Active_rule_2
        self.assertEqual(stats['content']['updated'], 0)  # Nothing was updated
        self.assertEqual(stats['content']['same'], 4)  # The 4 other entries in the content haven't changed
        self.assertEqual(stats['content']['deleted'], 1)  # One rule was deleted

        # Only one rule should exist in the DB
        # The original rule was deleted
        self.assertFalse(Rule.objects.filter(rule_id="test|Active_rule").exists())
        self.assertTrue(Rule.objects.filter(rule_id="test|Active_rule_2").exists())

        # The new rule should be active
        rule_2 = Rule.objects.get(rule_id="test|Active_rule_2")
        self.assertTrue(rule_2.active)
        self.assertEqual(rule_2.impact.name, "Invalid Configuration")
        self.assertEqual(rule_2.resolution_set.first().resolution_risk.name, "Adjust Service Status")

        # Reimport content with new rule "test|Active_rule_3" and with new impact name "Incorrect Configuration"
        # that replaces "Invalid Configuration"
        stats = import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG.
                                                     replace("Invalid Configuration", "Incorrect Configuration")),
                                          json.loads(BASIC_TEST_DATA_CONTENT.
                                                     replace('"test|Active_rule"', '"test|Active_rule_3"').
                                                     replace("Invalid Configuration", "Incorrect Configuration")))
        self.assertEqual(stats['content']['added'], 1)  # Added test|Active_rule_3
        self.assertEqual(stats['content']['updated'], 0)  # Nothing was updated
        self.assertEqual(stats['content']['same'], 4)  # The 4 other entries in the content haven't changed
        self.assertEqual(stats['content']['deleted'], 1)  # Active_rule_2 was deleted

        # Only one rule should exist in the Database
        # The first two rules were deleted
        # Only the third should exist
        self.assertFalse(Rule.objects.filter(rule_id="test|Active_rule").exists())
        self.assertFalse(Rule.objects.filter(rule_id="test|Active_rule_2").exists())
        self.assertTrue(Rule.objects.filter(rule_id="test|Active_rule_3").exists())

        # The _3 rule should be active now and have the new impact "Incorrect Configuration"
        rule_3 = Rule.objects.get(rule_id="test|Active_rule_3")
        self.assertTrue(rule_3.active)
        self.assertEqual(rule_3.impact.name, "Incorrect Configuration")
        self.assertEqual(rule_3.resolution_set.first().resolution_risk.name, "Adjust Service Status")

        # Final test of changing the impact from "Incorrect Configuration" to "Bad Configuration"
        stats = import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG.
                                                     replace("Invalid Configuration", "Bad Configuration")),
                                          json.loads(BASIC_TEST_DATA_CONTENT.
                                                     replace('"test|Active_rule"', '"test|Active_rule_3"').
                                                     replace("Invalid Configuration", "Bad Configuration")))
        self.assertEqual(stats['content']['added'], 0)
        self.assertEqual(stats['content']['updated'], 1)  # Changed test|Active_rule_3's impact
        self.assertEqual(stats['content']['same'], 4)  # The 4 other entries in the content haven't changed
        self.assertEqual(stats['content']['deleted'], 0)

        # The _3 rule should still be active and have the new impact "Bad Configuration"
        rule_3 = Rule.objects.get(rule_id="test|Active_rule_3")
        self.assertTrue(rule_3.active)
        self.assertEqual(rule_3.impact.name, "Bad Configuration")
        self.assertEqual(rule_3.resolution_set.first().resolution_risk.name, "Adjust Service Status")


class ImportContentAutoAckTestCase(TestCase):
    # Setup the test database with the basic_test_data fixture
    fixtures = ['rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data']

    def test_autoack_import(self):
        # Get model instances for Active and Second rules
        active_rule = Rule.objects.get(rule_id="test|Active_rule")
        second_rule = Rule.objects.get(rule_id="test|Second_rule")

        # Clear all existing acks
        Ack.objects.all().delete()

        # Import the content and check there is nothing up our sleeves (ie no acks)
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))
        self.assertFalse(Ack.objects.filter(rule=active_rule).exists())
        self.assertFalse(Ack.objects.filter(rule=second_rule).exists())

        # Add autoack tag to Active_rule and re-import content
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                              .replace("replaceme1", settings.AUTOACK['TAG'])))
        self.assertTrue(Ack.objects.filter(rule=active_rule).exists())
        self.assertEqual(Ack.objects.get(rule=active_rule, org_id='9876543').created_by, settings.AUTOACK['CREATED_BY'])
        self.assertEqual(Ack.objects.get(rule=active_rule, org_id='9988776').created_by, settings.AUTOACK['CREATED_BY'])
        self.assertFalse(Ack.objects.filter(rule=second_rule).exists())

        # Remove autoack tag from Active_rule and add an autoack to Second_rule
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                              .replace("replaceme2", settings.AUTOACK['TAG'])))
        self.assertFalse(Ack.objects.filter(rule=active_rule).exists())
        self.assertTrue(Ack.objects.filter(rule=second_rule).exists())
        self.assertEqual(Ack.objects.get(rule=second_rule, org_id='9876543').created_by, settings.AUTOACK['CREATED_BY'])
        self.assertEqual(Ack.objects.get(rule=second_rule, org_id='9988776').created_by, settings.AUTOACK['CREATED_BY'])

        # Re-import the content without any autoack tags to make sure the autoacks have been removed
        # It is very unlikely this will occur in practice, but is covered for completeness
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT))
        self.assertFalse(Ack.objects.filter(rule=active_rule).exists())
        self.assertFalse(Ack.objects.filter(rule=second_rule).exists())

        # Manually create an ack for Active rule for org_id 9876543 (account 1234567)
        new_ack = Ack(rule=active_rule, org_id='9876543')
        new_ack.justification = "Generated by user"
        new_ack.created_by = "User"
        new_ack.save()

        # Add autoack tag to Active_rule and re-import content, but it won't overwrite the user's ack
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                              .replace("replaceme1", settings.AUTOACK['TAG'])))
        self.assertTrue(Ack.objects.filter(rule=active_rule).exists())
        self.assertEqual(Ack.objects.get(rule=active_rule, org_id='9876543').created_by, "User")
        self.assertEqual(Ack.objects.get(rule=active_rule, org_id='9988776').created_by, settings.AUTOACK['CREATED_BY'])
        self.assertFalse(Ack.objects.filter(rule=second_rule).exists())

        # Remove the autoack tag from Active rule, but it won't remove the user's ack
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT))
        self.assertTrue(Ack.objects.filter(rule=active_rule).exists())
        self.assertTrue(Ack.objects.filter(rule=active_rule, org_id='9876543').exists())
        self.assertEqual(Ack.objects.get(rule=active_rule, org_id='9876543').created_by, "User")
        self.assertFalse(Ack.objects.filter(rule=active_rule, org_id='9988776').exists())


class ImportContentPathways(TestCase):
    # Setup the test database with the basic_test_data fixture
    fixtures = ['rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data']

    def get_rule_pathways(self):
        # Returns a list of a rules that are part of any pathway
        return sorted(list(Rule.objects.filter(pathway__isnull=False).values_list('rule_id', flat=True)))

    def get_rule_pathway(self, rule_id):
        # Returns the pathway for a particular rule_id or None if it isn't part of a pathway
        pathway = list(Rule.objects.filter(rule_id=rule_id).values_list('pathway__name', flat=True))
        return pathway[0] if pathway else None

    def test_default_pathways(self):
        # Check the default pathways that are included with the fixture data
        # to make sure they match the data we use in this test
        pathways = Pathway.objects.all().order_by('name')
        self.assertEqual(len(pathways), 2)
        self.assertEqual(pathways[0].slug, 'test-component-1')
        self.assertEqual(pathways[0].component, 'test1')
        self.assertEqual(pathways[0].resolution_risk_name, 'Adjust Service Status')
        self.assertEqual(pathways[1].slug, 'test-component-2')
        self.assertEqual(pathways[1].component, 'test2')
        self.assertEqual(pathways[1].resolution_risk_name, 'Adjust Service Status')

        # Expect these rules to have pathways from the fixture data
        rule_pathways = self.get_rule_pathways()
        self.assertEqual(len(rule_pathways), 3)
        self.assertEqual(rule_pathways, ['test|Acked_rule', 'test|Active_rule', 'test|Inactive_rule'])

    def test_importing_pathways(self):
        # Import BASIC_TEST_DATA content, which will remove the existing pathways from the basic_test_data fixture rules
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))
        self.assertEqual(self.get_rule_pathways(), [])
        self.assertIsNone(self.get_rule_pathway('test|Active_rule'))

        # Add component test1 to active_rule (again) and re-import content
        # Expect active rule to be part of 'test component 1' pathway
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('Active rule component', 'test1')))
        rule_pathways = self.get_rule_pathways()
        self.assertEqual(rule_pathways, ['test|Active_rule'])
        self.assertEqual(self.get_rule_pathway('test|Active_rule'), 'test component 1')
        self.assertIsNone(self.get_rule_pathway('test|Second_rule'))

        # Add test1 component to inactive and second rules as well and re-import content
        # Expect active, inactive and second rules to be part of 'test component 1' pathway
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('Active rule component', 'test1')
                                                   .replace('Inactive rule component', 'test1')
                                                   .replace('Second rule component', 'test1')))
        rule_pathways = self.get_rule_pathways()
        self.assertEqual(rule_pathways, ['test|Active_rule', 'test|Inactive_rule', 'test|Second_rule'])
        self.assertEqual(self.get_rule_pathway('test|Inactive_rule'), 'test component 1')
        self.assertEqual(self.get_rule_pathway('test|Second_rule'), 'test component 1')

        # Change active and second rule components to test2 and re-import content
        # Expect active and second rules to now be part of 'test component 2' pathway
        # Expect inactive rule to still be part of 'test component 1' pathway
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('Active rule component', 'test2')
                                                   .replace('Inactive rule component', 'test1')
                                                   .replace('Second rule component', 'test2')))
        rule_pathways = self.get_rule_pathways()
        self.assertEqual(rule_pathways, ['test|Active_rule', 'test|Inactive_rule', 'test|Second_rule'])
        self.assertEqual(self.get_rule_pathway('test|Active_rule'), 'test component 2')
        self.assertEqual(self.get_rule_pathway('test|Inactive_rule'), 'test component 1')
        self.assertEqual(self.get_rule_pathway('test|Second_rule'), 'test component 2')

        # Change all the rules to have a different resolution risk, but keep the same components
        # Expect active, inactive and second rules to now not be part of any pathways
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('Active rule component', 'test2')
                                                   .replace('Inactive rule component', 'test1')
                                                   .replace('Second rule component', 'test2')
                                                   .replace('Adjust Service Status', 'BIOS Parameter Adjustment')))
        self.assertEqual(self.get_rule_pathways(), [])
        self.assertIsNone(self.get_rule_pathway('test|Active_rule'))
        self.assertIsNone(self.get_rule_pathway('test|Inactive_rule'))
        self.assertIsNone(self.get_rule_pathway('test|Second_rule'))

    def test_importing_modified_pathway(self):
        # A contrived example because its not expected that pathways will change their component or resolution risk
        # Again, import BASIC_TEST_DATA content, which removes the pathways from the fixture rules
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))

        # Update the resolution risk for pathway 'test component 1' to 'BIOS Parameter Adjustment'
        # (Unlikely, but not impossible, to happen in practice)
        test1_pathway = Pathway.objects.get(component='test1')
        test1_pathway.resolution_risk_name = 'BIOS Parameter Adjustment'
        test1_pathway.save()

        # test1 now has resolution_risk BIOS Parameter Adjustment and test2 has Adjust Service Status
        # Import the rules but change all rules content to have resolution_risk BIOS Parameter Adjustment
        # Expect inactive rule to match test1 pathway, but active and second rules won't match test2 pathway
        #   because its resolution risk is set to Adjust Service Status
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('Active rule component', 'test2')
                                                   .replace('Inactive rule component', 'test1')
                                                   .replace('Second rule component', 'test2')
                                                   .replace('Adjust Service Status', 'BIOS Parameter Adjustment')))
        rule_pathways = self.get_rule_pathways()
        self.assertEqual(rule_pathways, ['test|Inactive_rule'])
        self.assertIsNone(self.get_rule_pathway('test|Active_rule'))
        self.assertEqual(self.get_rule_pathway('test|Inactive_rule'), 'test component 1')
        self.assertIsNone(self.get_rule_pathway('test|Second_rule'))

        # Change active and second rules components to test2 and don't modify inactive rule's content
        # Expect active and second rules to be in 'test component 1' pathway, and inactive rule to have a pathway
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('Active rule component', 'test1')
                                                   .replace('Second rule component', 'test1')
                                                   .replace('Adjust Service Status', 'BIOS Parameter Adjustment')))
        rule_pathways = self.get_rule_pathways()
        self.assertEqual(rule_pathways, ['test|Active_rule', 'test|Second_rule'])
        self.assertEqual(self.get_rule_pathway('test|Active_rule'), 'test component 1')
        self.assertIsNone(self.get_rule_pathway('test|Inactive_rule'))
        self.assertEqual(self.get_rule_pathway('test|Second_rule'), 'test component 1')


class ImportContentNotifAction(TestCase):
    # Setup the test database with the basic_test_data fixture
    fixtures = ['rulesets', 'system_types', 'rule_categories', 'upload_sources', 'basic_test_data']

    # Patch various methods, esp for testing sending notifications
    LOGGER_TARGET = "api.scripts.import_content.logger"
    SEND_WEBHOOK_TARGET = "api.scripts.import_content.send_webhook_event"

    def test_publish_date_no_change(self):
        # Import the rules and do a check of the state of the inactive rules
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertFalse(inactive_rule.active)
        self.assertEqual(inactive_rule.publish_date, datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.UTC))
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertFalse(not_yet_activated_rule.active)
        self.assertIsNone(not_yet_activated_rule.publish_date)

        # Now try activating the inactive rules - the publish_date should still be the same as in the content
        # This is because the notif_action is not set to enhance for previously the inactive rules,
        # thus the publish_date doesn't change
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertEqual(inactive_rule.publish_date, datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.UTC))
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        self.assertIsNone(not_yet_activated_rule.publish_date)

        # Now try setting notif_action to enhance, but again there will be no change to publish_date
        # because the previously inactive rules were already active
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')
                                                   .replace('"notif_action": null', '"notif_action": "enhance"')))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertEqual(inactive_rule.publish_date, datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.UTC))
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        self.assertIsNone(not_yet_activated_rule.publish_date)

    def test_publish_date_change(self):
        from time import sleep
        # Import the rules then re-import them, activating the inactive rules and setting notif_action to enhance
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')
                                                   .replace('"notif_action": null', '"notif_action": "enhance"')))
        nowish = datetime.strftime(datetime.utcnow(), '%Y-%m-%d %H:%M')
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertNotEqual(inactive_rule.publish_date, datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.UTC))
        self.assertEqual(inactive_rule.publish_date.strftime("%Y-%m-%d %H:%M"), nowish)
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        self.assertIsNotNone(not_yet_activated_rule.publish_date)
        self.assertEqual(not_yet_activated_rule.publish_date.strftime("%Y-%m-%d %H:%M"), nowish)

        # Re-import the default rule content and confirm the publish_date doesn't change,
        # but the rules will be inactive again
        current_inactive_rule_publish_date = inactive_rule.publish_date
        current_not_yet_activated_rule_publish_date = not_yet_activated_rule.publish_date

        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertFalse(inactive_rule.active)
        self.assertEqual(inactive_rule.publish_date, current_inactive_rule_publish_date)
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertFalse(not_yet_activated_rule.active)
        # Note, the publish_date for not_yet_activated_rule is set back to None because it is null in the content
        # In reality though is very unlikely a rule's publish_date will be set back to null in the content
        self.assertIsNone(not_yet_activated_rule.publish_date)

        # Re-activate the rules again, but don't do notif_action enhance and again, the publish_date doesn't change
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertEqual(inactive_rule.publish_date, current_inactive_rule_publish_date)
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        # The publish_date for not_yet_activated_rule is still set to None because its null in the content
        self.assertIsNone(not_yet_activated_rule.publish_date)

        # Reimport the rules again, enhancing and activating them again and confirm their publish_dates are not the
        # same as before.  Sleep for a second just to add a slight delay from the previous imports
        sleep(1)
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT))
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')
                                                   .replace('"notif_action": null', '"notif_action": "enhance"')))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertNotEqual(inactive_rule.publish_date, current_inactive_rule_publish_date)
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        # Now the publish_date for not_yet_activated_rule is set to the current time because the rule
        # was enhanced and activated, even though in the content it is still null
        # This is a bit of a contrived example because it is very unlikely the publish_date will be null in the content
        self.assertIsNotNone(not_yet_activated_rule.publish_date)
        self.assertNotEqual(not_yet_activated_rule.publish_date, current_not_yet_activated_rule_publish_date)

    def test_notif_action_speling(self):
        # What happens if enhance is not exactly spelled 'enhance'?
        # If its spelled incorrectly or something different, then it has no effect - in this case 'notenhance'
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')
                                                   .replace('"notif_action": null', '"notif_action": "notenhance"')))
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertEqual(inactive_rule.publish_date, datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.UTC))
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        self.assertIsNone(not_yet_activated_rule.publish_date)

        # However, if the capitalization is different, or it starts with 'enhance' it works as if it were 'enhance'
        # Here we set notif_action: Enhancement, which is fine
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT))
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "inactive"', '"status": "active"')
                                                   .replace('"notif_action": null', '"notif_action": "Enhancement"')))
        nowish = datetime.strftime(datetime.utcnow(), '%Y-%m-%d %H:%M')
        inactive_rule = Rule.objects.get(rule_id="test|Inactive_rule")
        self.assertTrue(inactive_rule.active)
        self.assertNotEqual(inactive_rule.publish_date, datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.UTC))
        self.assertEqual(inactive_rule.publish_date.strftime("%Y-%m-%d %H:%M"), nowish)
        not_yet_activated_rule = Rule.objects.get(rule_id="test|Rule_not_yet_activated")
        self.assertTrue(not_yet_activated_rule.active)
        self.assertIsNotNone(not_yet_activated_rule.publish_date)
        self.assertEqual(not_yet_activated_rule.publish_date.strftime("%Y-%m-%d %H:%M"), nowish)

    @patch(LOGGER_TARGET)
    @patch(SEND_WEBHOOK_TARGET)
    def test_disabled_rule_notifications(self, webhook_mock, log_mock):
        # For active rules, set their status to inactive
        # Firstly import the rules, then re-import them deactivating the active rules and setting notif_action to retire
        import_content.import_all(json.loads(BASIC_TEST_DATA_CONFIG), json.loads(BASIC_TEST_DATA_CONTENT))
        import_content.update_ruleset_with_content(json.loads(BASIC_TEST_DATA_CONTENT
                                                   .replace('"status": "active"', '"status": "inactive"')
                                                   .replace('"notif_action": null', '"notif_action": "retire"')))
        log_mock.info.assert_any_call("Rule '%s' is being deactivated with notif_action '%s'", 'test|Active_rule', 'retire')
        log_mock.info.assert_any_call("Account %s org_id %s is affected by deactivated rule '%s'", '1122334', '9988776', 'test|Active_rule')
        log_mock.info.assert_any_call("Account %s org_id %s is affected by deactivated rule '%s'", '1234567', '9876543', 'test|Active_rule')
        log_mock.info.assert_any_call("Rule '%s' is being deactivated with notif_action '%s'", 'test|Second_rule', 'retire')
        log_mock.info.assert_any_call("Account %s org_id %s is affected by deactivated rule '%s'", '1234567', '9876543', 'test|Second_rule')

        # 2 webhook notifications will be 'sent' for the 2 accounts affected by deactivating these rules
        assert webhook_mock.call_count == 2

        # Check the structure of the first notification sent (to subscribed users in account 1122334)
        notif1 = webhook_mock.call_args_list[0].args[0]  # notification for account 1122334
        assert notif1['account_id'] == '1122334'
        assert notif1['org_id'] == '9988776'
        assert notif1['event_type'] == 'deactivated-recommendation'
        # 1 payload for notif1 because only 1 of the disabled rules affected its systems
        notif1_payloads = [event['payload'] for event in notif1['events']]
        notif1_rules = [rule['rule_id'] for rule in notif1_payloads]
        # Assert account 1122334 was only affected by deactivated rule Active_rule
        assert len(notif1_rules) == 1
        assert 'test|Active_rule' in notif1_rules
        assert all([rule not in notif1_rules for rule in ['test|Acked_rule', 'test|Second_rule']])
        # Assert the rules were deactivated because they were being retired
        assert all(['Retirement' in event for event in [rule['deactivation_reason'] for rule in notif1_payloads]])
        # Assert 2 systems were affected by Active_rule for account 1122334
        active_rule = [rule for rule in notif1_payloads if rule['rule_id'] == 'test|Active_rule'][0]
        assert active_rule['affected_systems'] == 2

        # Check the structure of the second notification sent (to subscribed users in account 1234567)
        notif2 = webhook_mock.call_args_list[1].args[0]  # notification for account 1234567
        assert notif2['account_id'] == '1234567'
        assert notif2['org_id'] == '9876543'
        assert notif2['event_type'] == 'deactivated-recommendation'
        # 2 payloads for notif2 because 2 disabled rules affected its systems
        notif2_payloads = [event['payload'] for event in notif2['events']]
        notif2_rules = [rule['rule_id'] for rule in notif2_payloads]
        # Assert account 1234567 was affected by deactivated rules Active_rule and Second_rule
        assert len(notif2_rules) == 2
        assert all([rule in notif2_rules for rule in ['test|Active_rule', 'test|Second_rule']])
        assert 'test|Acked_rule' not in notif2_rules
        # Assert all the rules were deactivated because they were being retired
        assert all(['Retirement' in event for event in [rule['deactivation_reason'] for rule in notif2_payloads]])
        # Assert 6 systems were affected by Active_rule for account 1234567
        active_rule = [rule for rule in notif2_payloads if rule['rule_id'] == 'test|Active_rule'][0]
        assert active_rule['affected_systems'] == 6
