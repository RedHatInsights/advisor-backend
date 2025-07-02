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

import json
import os

from confluent_kafka import Producer

BOOTSTRAP_SERVERS = os.environ.get('BOOTSTRAP_SERVERS', 'localhost:9092')
PLAYBOOK_RUN_TOPIC = os.environ.get('ENGINE_RESULTS_TOPIC', 'platform.playbook-dispatcher.runs')


print('Using BOOTSTRAP_SERVERS %s' % (BOOTSTRAP_SERVERS))

p = Producer({'bootstrap.servers': BOOTSTRAP_SERVERS})


engine_results_message = {
        "event_type": "create",
        "payload": {
          "id": "00112233-4455-6677-8899-012345670001",
          "account": "901578",
          "recipient": "dd018b96-da04-4651-84d1-187fa5c23f6c",
          "correlation_id": "fbf49ad9-ea79-41fb-9f6c-cb13307e993d",
          "service": "remediations",
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


def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        print(f'Message delivery failed: {err}')
    else:
        print(f'Message delivered to {msg.topic()} [{msg.partition()}]')


for x in range(1):  # increase this for more messages
    p.poll(0)
    p.produce(PLAYBOOK_RUN_TOPIC, json.dumps(engine_results_message).encode(), callback=delivery_report)


p.flush()

print('done')
