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
ENGINE_RESULTS_TOPIC = os.environ.get('ENGINE_RESULTS_TOPIC', 'platform.engine.results')
ENGINE_RESULTS_FILE = os.path.basename(os.environ.get('ENGINE_RESULTS_FILE', 'fake_engine_result_rhel.json'))
THIS_DIR = os.path.dirname(os.path.realpath(__file__))

print('Using BOOTSTRAP_SERVERS %s' % (BOOTSTRAP_SERVERS))

p = Producer({'bootstrap.servers': BOOTSTRAP_SERVERS})

with open(os.path.join(THIS_DIR, ENGINE_RESULTS_FILE)) as f:
    engine_results_message = json.load(f)


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
