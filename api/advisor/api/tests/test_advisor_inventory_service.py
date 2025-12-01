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

# import responses
from copy import deepcopy
from datetime import datetime, timedelta

from django.test import TestCase  # , override_settings
from django.utils import timezone

from kafka_utils import JsonValue
# from project_settings import kafka_settings
from api.management.commands.advisor_inventory_service import (
    handle_inventory_event, handle_created_event, handle_deleted_event
)
from api.models import CurrentReport, Host, HostAck, InventoryHost, Upload
from api.tests import constants

#############################################################################
# Message structures
#############################################################################
new_host_id: str = "00112233-4455-6677-8899-012345678920"
new_host_name: str = "new_host_20.example.org"
new_host_satid: str = "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE20"
# Note that we want to make sure that we use current timestamps so this
# data appears in current InventoryHost searches.
now: datetime = timezone.now()
plus7days: timedelta = timedelta(days=7)
stale_time: str = (now + plus7days * 1).isoformat()
stale_warn_time: str = (now + plus7days * 2).isoformat()
cull_time: str = (now + plus7days * 3).isoformat()
create_new_host_msg: JsonValue = {
    # A minimal structure for a new host event.  We don't really need to test
    # that fields we want to ignore are in fact ignored...
    'type': 'created',
    "timestamp": "<timestamp>",
    "metadata": {
        "request_id": "<request_id>",
    },
    "host": {
        "id": new_host_id,
        "account": constants.standard_acct,
        "org_id": constants.standard_org,
        "display_name": new_host_name,
        "insights_id": "FFEEDDCC-BBAA-9988-7766-554433221120",
        "satellite_id": new_host_satid,
        "created": "2025-11-28T03:53:20Z",
        "updated": "2025-11-28T03:53:20Z",
        "tags": [],
        "stale_timestamp": stale_time,
        "stale_warning_timestamp": stale_warn_time,
        "culled_timestamp": cull_time,
        "system_profile": {
            "ansible": "", "bootc_status": "", "host_type": "", "mssql": "",
            "operating_system": "", "owner_id": "", "rhc_client_id": "",
            "sap": "", "sap_system": "", "sap_sids": "",
            "system_update_method": ""
        },
        "per_reporter_staleness": {"puptoo": {
            "stale_timestamp": stale_time,
            "stale_warning_timestamp": stale_warn_time,
            "culled_timestamp": cull_time
        }},
        "groups": [],
    }
}
update_host_msg: JsonValue = {
    # A minimal structure for a new host event.  We don't really need to test
    # that fields we want to ignore are in fact ignored...
    'type': 'updated',
    "timestamp": "<timestamp>",
    "metadata": {
        "request_id": "<request_id>",
    },
    "host": {
        "id": constants.host_01_uuid,
        "account": constants.standard_acct,
        "org_id": constants.standard_org,
        "display_name": constants.host_01_name,
        "insights_id": constants.host_01_inid,
        "satellite_id": '',
        "created": "2025-12-01T03:09:27Z",
        "updated": "2025-12-01T03:09:27Z",
        "tags": [],
        "stale_timestamp": stale_time,
        "stale_warning_timestamp": stale_warn_time,
        "culled_timestamp": cull_time,
        "system_profile": {  # taken from the fixture, only certain values copied
            "arch": "x86_64", "bios_vendor": "Dell Inc.", "bios_version": "2.8.0",
            "bios_release_date": "13/06/2017", "cores_per_socket": 8,
            "number_of_sockets": 2, "infrastructure_type": "physical",
            "system_memory_bytes": 134927265792, "satellite_managed": True,
            "insights_egg_version": "3.0.182-1", "sap_system": True,
            "insights_client_version": "3.0.14", "sap_sids": ["E01", "E02"],
            "os_release": "Red Hat Enterprise Linux Server",
            "owner_id": "55df28a7-d7ef-48c5-bc57-8967025399b1",
            "operating_system": {"name": "RHEL", "major": 7, "minor": 5},
            "system_update_method": "dnf",
            "workloads": {
                "sap": {
                    "sap_system": True, "version": "2.00.122.04.1478575636",
                    "sids": ["E01", "E02"], "instance_number": "00"
                }
            }
        },
        "per_reporter_staleness": {"puptoo": {
            "stale_timestamp": stale_time,
            "stale_warning_timestamp": stale_warn_time,
            "culled_timestamp": cull_time
        }},
        "groups": [],
    }
}
delete_host_msg: dict[str, str] = {  # Pick a host with acks, hostacks, etc.
    "type": "delete",
    "id": constants.host_01_uuid,
    "timestamp": "<delete timestamp>",
    # Test handling of no account number
    "org_id": constants.standard_org,
    "insights_id": constants.host_01_inid,
    "request_id": "<request id>",
}


#############################################################################
# Test class
#############################################################################


class TestAdvisorInventoryServer(TestCase):
    """
    Test the Advisor Inventory Server functionality.

    Because the command runs as a long-running service, we need to test its
    parts by directly calling the functions that handle inventory events.
    Until we find a way to simulate a Kafka queue that actually sends
    messages to the consumer invoked in KafkaDispatcher, this will have to do.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def test_message_dispatch(self):
        """
        Test that the handle_inventory_event function dispatches messages
        correctly.
        """
        # No 'type' field in message
        with self.assertLogs(logger='advisor-log') as logs:
            handle_inventory_event('topic', {'key': 'value'})
            self.assertEqual(len(logs.output), 1)
            self.assertEqual(
                "ERROR:advisor-log:Message received on topic topic with no 'type' field",
                logs.output[0]
            )
        # Unknown message type
        with self.assertLogs(logger='advisor-log') as logs:
            handle_inventory_event('topic', {'type': 'foo'})
            self.assertEqual(len(logs.output), 1)
            self.assertEqual(
                "ERROR:advisor-log:Inventory event: Unknown message type: foo",
                logs.output[0]
            )
        # Test the actual calls to create and delete in their own test methods.

    def test_created_message_success(self):
        """
        Test successful creation and updating of hosts.
        """
        # Start by processing the create message using handle_inventory_event
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            handle_inventory_event('topic', create_new_host_msg)
            # We aim to remove this debug log soon but in the meantime
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Handling 'created' event",
                log_lines[0]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Created Inventory host %s account %s org_id %s" % (
                    new_host_id, constants.standard_acct, constants.standard_org
                ),
                log_lines[1]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Created Host %s account %s org_id %s" % (
                    new_host_id, constants.standard_acct, constants.standard_org
                ),
                log_lines[2]
            )
            self.assertEqual(len(log_lines), 3)
            # Check existence of InventoryHost record
            self.assertEqual(
                InventoryHost.objects.filter(id=new_host_id).count(),
                1
            )
            new_ihost = InventoryHost.objects.get(id=new_host_id)
            # Probably don't need to check the entire data set.
            self.assertEqual(str(new_ihost.id), new_host_id)
            self.assertEqual(new_ihost.account, constants.standard_acct)
            self.assertEqual(new_ihost.org_id, constants.standard_org)
            # Check existence of Host record
            self.assertEqual(
                Host.objects.filter(inventory_id=new_host_id).count(),
                1
            )
            new_host = Host.objects.get(inventory_id=new_host_id)
            self.assertEqual(str(new_host.satellite_id).upper(), new_host_satid)

    def test_created_message_fail_missing_key(self):
        """
        Test all the missing keys being detected in the create message
        """
        for missing_field in (
            'metadata', 'request_id', 'host', 'id', 'display_name', 'org_id',
            'tags', 'groups', 'created', 'updated', 'insights_id',
        ):
            with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
                modified_msg: JsonValue = deepcopy(create_new_host_msg)
                # Have to delete bits of the structure - not linear
                match missing_field:
                    case 'request_id':
                        del modified_msg['metadata']['request_id']
                    case 'host' | 'metadata':
                        del modified_msg[missing_field]
                    case host_field:  # everything else inside host
                        del modified_msg['host'][host_field]
                handle_created_event(modified_msg)
                # We aim to remove this debug log soon but in the meantime
                log_lines: list[str] = list(filter(
                    lambda line: 'Using Cyndi replication view' not in line, logs.output
                ))
                self.assertEqual(
                    "INFO:advisor-log:Handling 'created' event",
                    log_lines[0]
                )
                if missing_field == 'metadata':
                    this_req_id = 'metadata'
                elif missing_field == 'request_id':
                    this_req_id = 'unknown request_id'
                else:
                    this_req_id = modified_msg['metadata']['request_id']
                self.assertEqual(
                    "ERROR:advisor-log:Request %s: Inventory event did not contain required key '%s'" % (
                        this_req_id, missing_field
                    ),
                    log_lines[1],
                    f"Field {missing_field} is required"
                )
                self.assertEqual(len(log_lines), 2)
        # The optional fields should allow a success though.
        # This also tests that receiving a 'create' event on a host that
        # already exists is treated as an update.
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            modified_msg: JsonValue = deepcopy(create_new_host_msg)
            del modified_msg['host']['account']
            handle_created_event(modified_msg)
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Handling 'created' event",
                log_lines[0]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Created Inventory host %s account %s org_id %s" % (
                    new_host_id, None, constants.standard_org
                ),
                log_lines[1]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Created Host %s account %s org_id %s" % (
                    new_host_id, None, constants.standard_org
                ),
                log_lines[2]
            )
            self.assertEqual(len(log_lines), 3)
            # Check existence of InventoryHost record
            self.assertEqual(
                InventoryHost.objects.filter(id=new_host_id).count(),
                1
            )
            self.assertEqual(
                Host.objects.filter(inventory_id=new_host_id).count(),
                1
            )
            host = Host.objects.get(inventory_id=new_host_id)
            self.assertEqual(str(host.satellite_id), new_host_satid.lower())
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            modified_msg: JsonValue = deepcopy(create_new_host_msg)
            del modified_msg['host']['satellite_id']
            handle_created_event(modified_msg)
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Handling 'created' event",
                log_lines[0]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Updated Inventory host %s account %s org_id %s" % (
                    new_host_id, constants.standard_acct, constants.standard_org
                ),
                log_lines[1]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Updated Host %s account %s org_id %s" % (
                    new_host_id, constants.standard_acct, constants.standard_org
                ),
                log_lines[2]
            )
            self.assertEqual(len(log_lines), 3)
            # Check existence of InventoryHost record
            self.assertEqual(
                InventoryHost.objects.filter(id=new_host_id).count(),
                1
            )
            self.assertEqual(
                Host.objects.filter(inventory_id=new_host_id).count(),
                1
            )
            host = Host.objects.get(inventory_id=new_host_id)
            # Because the host is being updated, the Satellite ID has carried
            # over from the previous update.
            self.assertEqual(str(host.satellite_id), new_host_satid.lower())

    def test_updated_message_success(self):
        """
        Test successful updating of existing host.
        """
        # Call handle_created_event directly
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            handle_created_event(update_host_msg)
            # Now check the logs
            # We aim to remove this debug log soon but in the meantime
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Handling 'updated' event",
                log_lines[0]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Updated Inventory host %s account %s org_id %s" % (
                    constants.host_01_uuid, constants.standard_acct, constants.standard_org
                ),
                log_lines[1]
            )
            self.assertEqual(
                "DEBUG:advisor-log:Updated Host %s account %s org_id %s" % (
                    constants.host_01_uuid, constants.standard_acct, constants.standard_org
                ),
                log_lines[2]
            )
            self.assertEqual(len(log_lines), 3)

    def test_deleted_message_success(self):
        """
        Test successful deletion of existing host.
        """
        # Call handle_created_event directly
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            handle_inventory_event('topic', delete_host_msg)
            # Now check the logs
            # We aim to remove this debug log soon but in the meantime
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Handling 'deleted' event",
                log_lines[0]
            )
            self.assertEqual(
                "INFO:advisor-log:Received DELETE event from Inventory for host %s." % (
                    constants.host_01_uuid
                ),
                log_lines[1]
            )
            self.assertEqual(
                "INFO:advisor-log:Deleted %d records based on Host: %s." % (
                    9, "{'api.CurrentReport': 4, 'api.HostAck': 1, 'api.Upload': 3, 'api.Host': 1}"
                ),
                log_lines[2]
            )
            self.assertEqual(
                "INFO:advisor-log:Deleted %d records based on InventoryHost: %s." % (
                    1, "{'api.InventoryHost': 1}"
                ),
                log_lines[3]
            )
            self.assertEqual(len(log_lines), 4)
        # Now test that we actually deleted all those things:
        self.assertEqual(
            InventoryHost.objects.filter(id=constants.host_01_uuid).count(),
            0
        )
        self.assertEqual(
            Host.objects.filter(inventory_id=constants.host_01_uuid).count(),
            0
        )
        self.assertEqual(
            Upload.objects.filter(host_id=constants.host_01_uuid).count(),
            0
        )
        self.assertEqual(
            CurrentReport.objects.filter(host_id=constants.host_01_uuid).count(),
            0
        )
        self.assertEqual(
            HostAck.objects.filter(host_id=constants.host_01_uuid).count(),
            0
        )

    def test_deleted_message_fail_missing_key(self):
        """
        Test all the missing keys being detected in the delete message
        """
        # account is optional and missing account is tested above.
        for missing_field in ('id', 'org_id', 'request_id'):
            with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
                modified_msg: dict[str, str] = deepcopy(delete_host_msg)
                del modified_msg[missing_field]
                handle_deleted_event(modified_msg)
                # We aim to remove this debug log soon but in the meantime
                log_lines: list[str] = list(filter(
                    lambda line: 'Using Cyndi replication view' not in line, logs.output
                ))
                self.assertEqual(
                    "INFO:advisor-log:Handling 'deleted' event",
                    log_lines[0]
                )
                if missing_field == 'request_id':
                    this_req_id = 'unknown request_id'
                else:
                    this_req_id = modified_msg['request_id']
                self.assertEqual(
                    "ERROR:advisor-log:Request %s: Inventory event did not contain required key %s" % (
                        this_req_id, missing_field
                    ),
                    log_lines[1],
                    f"Field {missing_field} is required"
                )
                self.assertEqual(len(log_lines), 2)
