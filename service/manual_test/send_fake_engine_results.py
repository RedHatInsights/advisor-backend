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

import argparse
import json
import os
import uuid

from confluent_kafka import Producer
from insert_inventory_host import insert_host

BOOTSTRAP_SERVERS = os.environ.get('BOOTSTRAP_SERVERS', 'localhost:9092')
ENGINE_RESULTS_TOPIC = os.environ.get('ENGINE_RESULTS_TOPIC', 'platform.engine.results')
ENGINE_RESULTS_FILE = os.path.basename(os.environ.get('ENGINE_RESULTS_FILE', 'fake_engine_result_rhel.json'))
THIS_DIR = os.path.dirname(os.path.realpath(__file__))

parser = argparse.ArgumentParser(description='Send fake engine results to Kafka')
parser.add_argument(
    '--groups', type=str, default=None,
    help=(
        'Comma-separated host group names to assign to the host. '
        'Each name gets a deterministic UUID. '
        'Example: --groups "group_1,group_2"'
    ),
)
parser.add_argument(
    '--group-ids', type=str, default=None,
    help=(
        'Comma-separated id:name pairs to assign to the host. '
        'Use this to specify exact UUIDs (e.g. to match Kessel --host-groups). '
        'Example: --group-ids "11111111-1111-1111-1111-111111111111:my_group"'
    ),
)
args = parser.parse_args()

print('Using BOOTSTRAP_SERVERS %s' % (BOOTSTRAP_SERVERS))

p = Producer({'bootstrap.servers': BOOTSTRAP_SERVERS})

with open(os.path.join(THIS_DIR, ENGINE_RESULTS_FILE)) as f:
    engine_results_message = json.load(f)

host_data = engine_results_message['input']['host']

# Inject host groups if --groups or --group-ids is specified
groups = []
if args.groups:
    for name in args.groups.split(','):
        name = name.strip()
        # Generate a deterministic UUID from the group name so that
        # re-running with the same name produces the same ID.
        group_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
        groups.append({'id': group_id, 'name': name})
if args.group_ids:
    for pair in args.group_ids.split(','):
        pair = pair.strip()
        if ':' in pair:
            group_id, name = pair.split(':', 1)
        else:
            group_id = pair
            name = pair
        groups.append({'id': group_id, 'name': name})
if groups:
    host_data['groups'] = groups
    print(f'Host groups: {groups}')

# Insert the host into inventory.hosts_table so the API can find it
insert_host(host_data)


def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        print(f'Message delivery failed: {err}')
    else:
        print(f'Message delivered to {msg.topic()} [{msg.partition()}]')


for x in range(1):  # increase this for more messages
    p.poll(0)
    p.produce(ENGINE_RESULTS_TOPIC, json.dumps(engine_results_message).encode(), callback=delivery_report)


p.flush()

print('done')
