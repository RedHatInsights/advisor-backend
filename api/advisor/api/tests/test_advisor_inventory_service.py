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
from datetime import datetime, timedelta

from django.test import TestCase  # , override_settings
from django.utils import timezone

from kafka_utils import JsonValue
# from project_settings import kafka_settings
from api.management.commands.advisor_inventory_service import (
    handle_inventory_event  # , handle_created_event, handle_deleted_event
)
from api.tests import constants

#############################################################################
# Message structures
#############################################################################
new_host_id: str = "00112233-4455-6677-8899-012345678920"
new_host_name: str = "new_host_20.example.org"
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
        "satellite_id": "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE20",
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
