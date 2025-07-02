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
TASKS_UPLOAD_TOPIC = os.environ.get('TASKS_UPLOAD_TOPIC', 'platform.upload.announce')


print('Using BOOTSTRAP_SERVERS %s' % (BOOTSTRAP_SERVERS))

p = Producer({'bootstrap.servers': BOOTSTRAP_SERVERS})


ingress_message = {
       "account": "540155",
       "org_id": "540155",
       "category": "payload",
       "content_type": "application/vnd.redhat.tasks.payload+tgz",
       "request_id": "00000000-0000-0000-0000-000000000000",
       "principal": "540155",
       "service": "tasks",
       "size": "1337",
       "url": "http://s3bucket/file.tar.gz",
       "id": "00000000-0000-0000-0000-000000000000",
       "b64_identity": "base64 identity header",
       "timestamp": "2023-06-28T17:01:07Z",
       "metadata": ""
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
    p.produce(TASKS_UPLOAD_TOPIC,
              json.dumps(ingress_message).encode(),
              callback=delivery_report,
              headers={"service": "tasks"}
              )


p.flush()

print('done')
