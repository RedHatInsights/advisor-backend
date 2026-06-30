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
from unittest.mock import patch
from django.test import TestCase  # , override_settings
from django.utils import timezone

import prometheus
from feature_flags import set_unleash_flag, FLAG_INVENTORY_EVENT_REPLICATION
from django.core.signals import request_started, request_finished
from kafka_utils import DummyConsumer, JsonValue, KafkaDispatcher
# from project_settings import kafka_settings
from api.management.commands.advisor_inventory_service import (
    handle_inventory_event, parse_created_event, parse_deleted_event,
)
from api.models import AdvisorInventoryHost, CurrentReport, Host, HostAck, InventoryHost, Upload
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
create_new_host_msg: dict[str, JsonValue] = {
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
        "last_check_in": "2025-11-28T03:53:20Z",
        "tags": [],
        "stale_timestamp": stale_time,
        "system_profile": {
            "host_type": "edge",
            "operating_system": {"name": "RHEL", "major": 9, "minor": 4},
            "bootc_status": {
                "booted": {
                    "image": "quay.io/example/rhel:9.4",
                    "image_digest": "sha256:abc123"
                }
            },
            "owner_id": "55df28a7-d7ef-48c5-bc57-8967025399b1",
            "rhc_client_id": "66ef39b8-e8f0-59d6-ca68-cee5983500c2",
            "system_update_method": "dnf",
            "workloads": {
                "sap": {
                    "sap_system": True,
                    "sids": ["E01", "E02"],
                    "instance_number": "00",
                    "version": "2.00.122"
                },
                "ansible": {
                    "controller_version": "4.6.0",
                    "hub_version": "4.9.0"
                },
                "mssql": {
                    "version": "16.0.1000"
                }
            }
        },
        "reporter": "puptoo",
        "per_reporter_staleness": {"puptoo": {
            "stale_timestamp": stale_time,
            "stale_warning_timestamp": stale_warn_time,
            "culled_timestamp": cull_time
        }},
        "groups": [{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "test-workspace"}],
    }
}
update_host_msg: dict[str, JsonValue] = {
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
        "last_check_in": "2025-12-01T03:09:27Z",
        "tags": [],
        "stale_timestamp": stale_time,
        "system_profile": {
            "operating_system": {"name": "RHEL", "major": 7, "minor": 5},
            "owner_id": "55df28a7-d7ef-48c5-bc57-8967025399b1",
            "system_update_method": "dnf",
            "workloads": {
                "sap": {
                    "sap_system": True,
                    "sids": ["E01", "E02"],
                    "instance_number": "00",
                    "version": "2.00.122.04.1478575636"
                }
            }
        },
        "reporter": "puptoo",
        "per_reporter_staleness": {"puptoo": {
            "stale_timestamp": stale_time,
            "stale_warning_timestamp": stale_warn_time,
            "culled_timestamp": cull_time
        }},
        "groups": [],
    }
}
delete_host_msg: dict[str, JsonValue] = {  # Pick a host with acks, hostacks, etc.
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

    def setUp(self):
        for inv_host in InventoryHost.objects.all():
            AdvisorInventoryHost.objects.update_or_create(
                inventory_id=inv_host.id,
                org_id=inv_host.org_id,
                defaults={
                    'account': inv_host.account,
                    'display_name': inv_host.display_name,
                    'tags': inv_host.tags,
                    'updated': inv_host.updated,
                    'created': inv_host.created,
                    'last_check_in': inv_host.last_check_in,
                    'stale_timestamp': inv_host.stale_timestamp,
                    'insights_id': inv_host.insights_id,
                    'reporter': inv_host.reporter,
                    'per_reporter_staleness': inv_host.per_reporter_staleness,
                }
            )

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_message_dispatch(self):
        """
        Test that the handle_inventory_event function dispatches messages
        correctly.
        """
        with self.assertLogs(logger='advisor-log') as logs:
            # No 'type' field in message
            handle_inventory_event('topic', [{'key': 'value'}])
            self.assertEqual(
                "INFO:advisor-log:Processing batch of 1 inventory events",
                logs.output[0]
            )
            self.assertEqual(
                "ERROR:advisor-log:Message received on topic topic with no 'type' field",
                logs.output[1]
            )
            # Unknown message type
            handle_inventory_event('topic', [{'type': 'foo'}])
            self.assertEqual(
                "ERROR:advisor-log:Inventory event: Unknown message type: foo",
                logs.output[3]
            )
        # Test the actual calls to create and delete in their own test methods.

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_created_message_success(self):
        """
        Test successful creation and updating of hosts.
        """
        # Start by processing the create message using handle_inventory_event
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            handle_inventory_event('topic', [create_new_host_msg])
            # We aim to remove this debug log soon but in the meantime
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Processing batch of 1 inventory events",
                log_lines[0]
            )
            self.assertTrue(
                any("Handling 'created' event" in line for line in log_lines),
                "Should log handling of created event"
            )
            self.assertTrue(
                any("Bulk upserted 1 AdvisorInventoryHost records" in line for line in log_lines),
                "Should log bulk upsert of AdvisorInventoryHost"
            )
            self.assertTrue(
                any("Bulk upserted 1 Host records" in line for line in log_lines),
                "Should log bulk upsert of Host"
            )
            self.assertEqual(
                AdvisorInventoryHost.objects.filter(inventory_id=new_host_id).count(),
                1
            )
            new_ihost = AdvisorInventoryHost.objects.get(inventory_id=new_host_id)
            self.assertEqual(str(new_ihost.inventory_id), new_host_id)
            self.assertEqual(new_ihost.account, constants.standard_acct)
            self.assertEqual(new_ihost.org_id, constants.standard_org)
            self.assertEqual(new_ihost.display_name, new_host_name)
            self.assertEqual(str(new_ihost.workspace_id), "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
            self.assertEqual(new_ihost.workspace_name, "test-workspace")
            self.assertEqual(new_ihost.os_name, "RHEL")
            self.assertEqual(new_ihost.os_major, 9)
            self.assertEqual(new_ihost.os_minor, 4)
            self.assertEqual(new_ihost.host_type, "edge")
            self.assertEqual(new_ihost.bootc_booted_image, "quay.io/example/rhel:9.4")
            self.assertEqual(new_ihost.bootc_booted_image_digest, "sha256:abc123")
            self.assertEqual(str(new_ihost.owner_id), "55df28a7-d7ef-48c5-bc57-8967025399b1")
            self.assertEqual(str(new_ihost.rhc_client_id), "66ef39b8-e8f0-59d6-ca68-cee5983500c2")
            self.assertEqual(new_ihost.workloads, {
                "sap": {
                    "sap_system": True,
                    "sids": ["E01", "E02"],
                    "instance_number": "00",
                    "version": "2.00.122"
                },
                "ansible": {
                    "controller_version": "4.6.0",
                    "hub_version": "4.9.0"
                },
                "mssql": {
                    "version": "16.0.1000"
                }
            })
            self.assertEqual(new_ihost.system_update_method, "dnf")
            # Check existence of Host record
            self.assertEqual(
                Host.objects.filter(inventory_id=new_host_id).count(),
                1
            )
            new_host = Host.objects.get(inventory_id=new_host_id)
            self.assertEqual(str(new_host.satellite_id).upper(), new_host_satid)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_created_message_fail_missing_key(self):
        """
        Test all the missing keys being detected in the create message
        """
        modified_msg: dict[str, JsonValue]
        for missing_field in (
            'metadata', 'request_id', 'host', 'id', 'display_name', 'org_id',
            'tags', 'groups', 'created', 'updated', 'insights_id',
        ):
            with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
                modified_msg = deepcopy(create_new_host_msg)
                # Have to delete bits of the structure - not linear
                match missing_field:
                    case 'request_id':
                        del modified_msg['metadata']['request_id']
                    case 'host' | 'metadata':
                        del modified_msg[missing_field]
                    case host_field:  # everything else inside host
                        del modified_msg['host'][host_field]
                result = parse_created_event(modified_msg)
                # We aim to remove this debug log soon but in the meantime
                log_lines: list[str] = list(filter(
                    lambda line: 'Using Cyndi replication view' not in line, logs.output
                ))
                self.assertTrue(
                    any("Handling 'created' event" in line for line in log_lines),
                    "Should log handling of created event"
                )
                if missing_field == 'metadata':
                    this_req_id = 'metadata'
                elif missing_field == 'request_id':
                    this_req_id = 'unknown request_id'
                else:
                    this_req_id = modified_msg['metadata']['request_id']
                self.assertTrue(
                    any(
                        "Request %s: Inventory created event did not contain required key '%s'" % (
                            this_req_id, missing_field
                        ) in line
                        for line in log_lines
                    ),
                    f"Field {missing_field} is required"
                )
                self.assertIsNone(result)
        # The optional fields should allow a success though.
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            modified_msg = deepcopy(create_new_host_msg)
            del modified_msg['host']['account']
            result = parse_created_event(modified_msg)
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertTrue(
                any("Handling 'created' event" in line for line in log_lines),
                "Should log handling of created event"
            )
            self.assertIsNotNone(result)
            self.assertIsNone(result.account)
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            modified_msg = deepcopy(create_new_host_msg)
            del modified_msg['host']['satellite_id']
            result = parse_created_event(modified_msg)
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertTrue(
                any("Handling 'created' event" in line for line in log_lines),
                "Should log handling of created event"
            )
            self.assertIsNotNone(result)
            self.assertIsNone(result.satellite_id)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_updated_message_success(self):
        """
        Test successful updating of existing host.
        """
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            # Call via handle_inventory_event to exercise update handling
            handle_inventory_event('topic', [update_host_msg])
            # Now check the logs
            # We aim to remove this debug log soon but in the meantime
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Processing batch of 1 inventory events",
                log_lines[0]
            )
            self.assertTrue(
                any("Handling 'updated' event" in line for line in log_lines),
                "Should log handling of updated event"
            )
            self.assertTrue(
                any("Bulk upserted" in line for line in log_lines),
                "Should log bulk upsert"
            )

            inv_host = AdvisorInventoryHost.objects.get(inventory_id=constants.host_01_uuid)
            self.assertEqual(inv_host.os_name, "RHEL")
            self.assertEqual(inv_host.os_major, 7)
            self.assertEqual(inv_host.os_minor, 5)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_deleted_message_success(self):
        """
        Test successful deletion of existing host.
        """
        # Call handle_inventory_event with batch
        with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
            handle_inventory_event('topic', [delete_host_msg])
            # Now check the logs
            # We aim to remove this debug log soon but in the meantime
            log_lines: list[str] = list(filter(
                lambda line: 'Using Cyndi replication view' not in line, logs.output
            ))
            self.assertEqual(
                "INFO:advisor-log:Processing batch of 1 inventory events",
                log_lines[0]
            )
            self.assertEqual(
                "INFO:advisor-log:Handling 'deleted' event",
                log_lines[1]
            )
            self.assertTrue(
                any(
                    "Received DELETE event from Inventory for host %s." % constants.host_01_uuid in line
                    for line in log_lines
                ),
                "Should log the DELETE event details"
            )
            self.assertTrue(
                any("Batch deleted" in line and "Host" in line for line in log_lines),
                "Should log batch deletion of Host"
            )
            self.assertTrue(
                any("Batch deleted" in line and "AdvisorInventoryHost" in line for line in log_lines),
                "Should log batch deletion of AdvisorInventoryHost"
            )
        # Now test that we actually deleted all those things:
        self.assertEqual(
            AdvisorInventoryHost.objects.filter(inventory_id=constants.host_01_uuid).count(),
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

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_deleted_message_fail_missing_key(self):
        """
        Test all the missing keys being detected in the delete message
        """
        # account is optional and missing account is tested above.
        for missing_field in ('id', 'org_id', 'request_id'):
            with self.assertLogs(logger='advisor-log', level='DEBUG') as logs:
                modified_msg: dict[str, JsonValue] = deepcopy(delete_host_msg)
                del modified_msg[missing_field]
                result = parse_deleted_event(modified_msg)
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
                    "ERROR:advisor-log:Request %s: Inventory delete event did not contain required key '%s'" % (
                        this_req_id, missing_field
                    ),
                    log_lines[1],
                    f"Field {missing_field} is required"
                )
                self.assertEqual(len(log_lines), 2)
                self.assertIsNone(result)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_created_nullable_fields(self):
        """
        Test that the handler works when optional system_profile fields are missing.
        """
        modified_msg = deepcopy(create_new_host_msg)
        modified_msg['host']['system_profile'] = {}
        modified_msg['host']['groups'] = []
        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [modified_msg])
        inv_host = AdvisorInventoryHost.objects.get(inventory_id=new_host_id)
        self.assertIsNone(inv_host.workspace_id)
        self.assertIsNone(inv_host.workspace_name)
        self.assertIsNone(inv_host.os_name)
        self.assertIsNone(inv_host.os_major)
        self.assertIsNone(inv_host.os_minor)
        self.assertIsNone(inv_host.host_type)
        self.assertIsNone(inv_host.bootc_booted_image)
        self.assertIsNone(inv_host.bootc_booted_image_digest)
        self.assertIsNone(inv_host.owner_id)
        self.assertIsNone(inv_host.rhc_client_id)
        self.assertEqual(inv_host.workloads, {})
        self.assertIsNone(inv_host.system_update_method)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_batch_created_and_updated(self):
        """Test that handle_inventory_event processes a batch of create and update messages."""
        batch = [create_new_host_msg, update_host_msg]
        handle_inventory_event('topic', batch)

        # New host was created
        self.assertTrue(
            AdvisorInventoryHost.objects.filter(
                inventory_id=new_host_id, org_id=constants.standard_org
            ).exists()
        )
        self.assertTrue(
            Host.objects.filter(inventory_id=new_host_id).exists()
        )
        # Existing host was updated
        inv_host = AdvisorInventoryHost.objects.get(
            inventory_id=constants.host_01_uuid, org_id=constants.standard_org
        )
        self.assertEqual(inv_host.display_name, constants.host_01_name)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_batch_deleted(self):
        """Test that handle_inventory_event processes a batch of delete messages."""
        # First create the host so we can delete it
        handle_inventory_event('topic', [create_new_host_msg])
        self.assertTrue(Host.objects.filter(inventory_id=new_host_id).exists())

        delete_new_host_msg = {
            "type": "delete",
            "id": new_host_id,
            "timestamp": "<delete timestamp>",
            "org_id": constants.standard_org,
            "insights_id": "FFEEDDCC-BBAA-9988-7766-554433221120",
            "request_id": "<request id>",
        }
        handle_inventory_event('topic', [delete_new_host_msg])

        self.assertFalse(Host.objects.filter(inventory_id=new_host_id).exists())
        self.assertFalse(
            AdvisorInventoryHost.objects.filter(
                inventory_id=new_host_id, org_id=constants.standard_org
            ).exists()
        )

    def test_batch_ignored_when_flag_disabled(self):
        """
        Test that batched messages are ignored when INVENTORY_EVENT_REPLICATION
        is disabled (env + feature flag), and that no DB changes occur.
        """
        batch = [create_new_host_msg]

        with self.assertLogs(logger='advisor-log') as logs:
            handle_inventory_event('topic', batch)

        self.assertTrue(
            any("feature flag not enabled, ignoring" in line for line in logs.output),
            msg="Expected 'feature flag not enabled, ignoring' log message",
        )
        self.assertFalse(
            AdvisorInventoryHost.objects.filter(
                inventory_id=new_host_id, org_id=constants.standard_org
            ).exists()
        )
        self.assertFalse(
            Host.objects.filter(inventory_id=new_host_id).exists()
        )

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_batch_skips_invalid_messages(self):
        """Test that invalid messages in a batch are skipped while valid ones proceed."""
        invalid_msg_no_type = {'key': 'value'}
        invalid_msg_unknown_type = {'type': 'foo'}
        batch = [invalid_msg_no_type, invalid_msg_unknown_type, create_new_host_msg]

        with self.assertLogs(logger='advisor-log') as logs:
            handle_inventory_event('topic', batch)

        # Valid create message should still succeed
        self.assertTrue(
            AdvisorInventoryHost.objects.filter(
                inventory_id=new_host_id, org_id=constants.standard_org
            ).exists()
        )
        # Error logs for the invalid messages
        self.assertTrue(any("no 'type' field" in line for line in logs.output))
        self.assertTrue(any("Unknown message type: foo" in line for line in logs.output))

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_malformed_host_payload_does_not_abort_batch(self):
        """Test that a message with wrong shape (e.g. host as string) is skipped."""
        malformed_msg = deepcopy(create_new_host_msg)
        malformed_msg['host'] = "oops"

        batch = [malformed_msg, create_new_host_msg]

        with self.assertLogs(logger='advisor-log') as logs:
            handle_inventory_event('topic', batch)

        self.assertTrue(
            any("Failed to parse inventory event" in line for line in logs.output)
        )
        self.assertTrue(
            AdvisorInventoryHost.objects.filter(
                inventory_id=new_host_id, org_id=constants.standard_org
            ).exists()
        )

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_stale_update_does_not_overwrite_newer_data(self):
        """Test that an event with an older last_check_in is filtered out."""
        newer_ts = "2026-06-01T12:00:00Z"
        older_ts = "2025-01-01T00:00:00Z"

        # Insert host with newer last_check_in
        msg = deepcopy(create_new_host_msg)
        msg['host']['last_check_in'] = newer_ts
        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [msg])

        inv_host = AdvisorInventoryHost.objects.get(inventory_id=new_host_id)
        original_display_name = inv_host.display_name

        # Send update with older last_check_in and different display_name
        stale_msg = deepcopy(create_new_host_msg)
        stale_msg['type'] = 'updated'
        stale_msg['host']['last_check_in'] = older_ts
        stale_msg['host']['display_name'] = 'stale-name-should-not-appear'
        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [stale_msg])

        inv_host.refresh_from_db()
        self.assertEqual(inv_host.display_name, original_display_name)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_newer_update_overwrites_older_data(self):
        """Test that an event with a newer last_check_in updates the record."""
        older_ts = "2025-01-01T00:00:00Z"
        newer_ts = "2026-06-01T12:00:00Z"

        # Insert host with older last_check_in
        msg = deepcopy(create_new_host_msg)
        msg['host']['last_check_in'] = older_ts
        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [msg])

        # Send update with newer last_check_in and different display_name
        update_msg = deepcopy(create_new_host_msg)
        update_msg['type'] = 'updated'
        update_msg['host']['last_check_in'] = newer_ts
        update_msg['host']['display_name'] = 'updated-name'
        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [update_msg])

        inv_host = AdvisorInventoryHost.objects.get(inventory_id=new_host_id)
        self.assertEqual(inv_host.display_name, 'updated-name')

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_batch_dedup_keeps_latest_timestamp(self):
        """Test that duplicate host events in a batch keep the one with latest last_check_in."""
        older_msg = deepcopy(create_new_host_msg)
        older_msg['host']['last_check_in'] = "2025-01-01T00:00:00Z"
        older_msg['host']['display_name'] = 'old-name'

        newer_msg = deepcopy(create_new_host_msg)
        newer_msg['host']['last_check_in'] = "2026-06-01T12:00:00Z"
        newer_msg['host']['display_name'] = 'new-name'

        # Send older first, newer second
        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [older_msg, newer_msg])

        inv_host = AdvisorInventoryHost.objects.get(inventory_id=new_host_id)
        self.assertEqual(inv_host.display_name, 'new-name')

        # Clean up and test reverse order
        AdvisorInventoryHost.objects.filter(inventory_id=new_host_id).delete()
        Host.objects.filter(inventory_id=new_host_id).delete()

        with self.assertLogs(logger='advisor-log', level='DEBUG'):
            handle_inventory_event('topic', [newer_msg, older_msg])

        inv_host = AdvisorInventoryHost.objects.get(inventory_id=new_host_id)
        self.assertEqual(inv_host.display_name, 'new-name')

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    @patch.object(prometheus.INVENTORY_EVENT_MALFORMED, 'inc')
    def test_malformed_messages_increment_prometheus_counter(self, mock_malformed_inc):
        """Malformed messages increment INVENTORY_EVENT_MALFORMED once per skipped message."""
        malformed_msg = deepcopy(create_new_host_msg)
        malformed_msg['host'] = "oops"
        batch = [
            {'key': 'value'},           # no type
            {'type': 'foo'},            # unknown type
            malformed_msg,              # unexpected parse error
            deepcopy(delete_host_msg),  # missing request_id
        ]
        del batch[3]['request_id']

        with self.assertLogs(logger='advisor-log'):
            handle_inventory_event('topic', batch)

        self.assertEqual(mock_malformed_inc.call_count, 4)

    @set_unleash_flag(FLAG_INVENTORY_EVENT_REPLICATION, True)
    def test_delete_failure_prevents_batch_ack(self):
        """A failed delete commit must fail the batch so offsets are not committed."""
        from django.db import close_old_connections

        consumer = DummyConsumer()
        consumer.add_message('topic', delete_host_msg)

        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('topic', handle_inventory_event, batch=True)

        request_started.disconnect(close_old_connections)
        request_finished.disconnect(close_old_connections)
        try:
            with patch(
                'api.management.commands.advisor_inventory_service.bulk_delete_hosts',
                side_effect=RuntimeError("delete failed"),
            ):
                messages = consumer.consume(num_messages=1, timeout=1)
                with self.assertLogs(logger='advisor-log'):
                    result = dispatcher._handle_batch_messages(messages)
        finally:
            request_started.connect(close_old_connections)
            request_finished.connect(close_old_connections)

        self.assertFalse(result)
        self.assertEqual(consumer.commit_count, 0)
        self.assertTrue(
            Host.objects.filter(inventory_id=constants.host_01_uuid).exists()
        )
