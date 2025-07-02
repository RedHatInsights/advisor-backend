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
INVENTORY_ENGINE_MESSAGE_TOPIC = os.environ.get('INVENTORY_ENGINE_MESSAGE_TOPIC', 'platform.inventory.host-egress')

p = Producer({'bootstrap.servers': BOOTSTRAP_SERVERS})

archive_message = {
    'host': {'id': '57c4c38b-a8c6-4289-9897-223681fd804d',
             'updated': '2020-02-12T12:30:21.825723+00:00',
             'insights_id': '45bdd8ce-36e6-4861-a4dd-cd69af79f6f1',
             'satellite_id': None,
             'ip_addresses': None,
             'bios_uuid': None,
             'fqdn': 'RHIQE.d60db782-8462-410e-b0fc-f4ee97d985cb.test',
             'stale_timestamp': '2020-02-13T14:30:21.813559+00:00',
             'tags': [{"namespace": "foo", "key": "bar", "value": "buzz"},
                      {"namespace": "sample", "key": "tag", "value": "1"},
                      {"namespace": "sample", "key": "tag", "value": "2"}],
             'stale_warning_timestamp': '2020-02-20T14:30:21.813559+00:00',
             'reporter': 'puptoo',
             'subscription_manager_id': 'f0025e01-52ce-4681-ab88-f3ed0657fa95',
             'rhel_machine_id': None,
             'mac_addresses': None,
             'created': '2020-02-12T12:30:20.636290+00:00',
             'culled_timestamp': '2020-02-27T14:30:21.813559+00:00',
             'ansible_host': None,
             'display_name': 'RHIQE.d60db782-8462-410e-b0fc-f4ee97d985cb.test',
             'external_id': None,
             'account': '477931',
             'system_profile': {}},
    'platform_metadata': {'account': '477931',
                          'category': 'collection',
                          'metadata': {'insights_id': '45bdd8ce-36e6-4861-a4dd-cd69af79f6f1',
                                       'machine_id': '436b7059-6588-4873-9592-61c1174613e0',
                                       'fqdn': 'RHIQE.d60db782-8462-410e-b0fc-f4ee97d985cb.test'},
                          'request_id': '33689b60f49144abb64450e30b8c0f95',
                          'principal': '711497',
                          'service': 'advisor',
                          'size': 524,
                          'url': 'http://localhost/sample_archive_rhel.tar.gz',
                          'id': '57c4c38b-a8c6-4289-9897-223681fd804d',
                          'b64_identity': 'eyJpZGVudGl0eSI6eyJpbnRlcm5hbCI6eyJvcmdfaWQiOiI3MTE0OTciLCJhdXRoX3RpbWUiOjB9LCJhY2NvdW50X251bWJlciI6IjQ3NzkzMSIsImF1dGhfdHlwZSI6ImJhc2ljLWF1dGgiLCJ1c2VyIjp7ImZpcnN0X25hbWUiOiJRdWFsaXR5IiwibGFzdF9uYW1lIjoiQXNzdXJhbmNlIiwiaXNfaW50ZXJuYWwiOnRydWUsImlzX2FjdGl2ZSI6dHJ1ZSwibG9jYWxlIjoiZW5fVVMiLCJpc19vcmdfYWRtaW4iOnRydWUsInVzZXJuYW1lIjoicWFAcmVkaGF0LmNvbSIsImVtYWlsIjoicWErcWFAcmVkaGF0LmNvbSJ9LCJ0eXBlIjoiVXNlciJ9LCJlbnRpdGxlbWVudHMiOnsiaW5zaWdodHMiOnsiaXNfZW50aXRsZWQiOnRydWV9LCJjb3N0X21hbmFnZW1lbnQiOnsiaXNfZW50aXRsZWQiOnRydWV9LCJhbnNpYmxlIjp7ImlzX2VudGl0bGVkIjpmYWxzZX0sIm9wZW5zaGlmdCI6eyJpc19lbnRpdGxlZCI6dHJ1ZX0sInNtYXJ0X21hbmFnZW1lbnQiOnsiaXNfZW50aXRsZWQiOnRydWV9LCJtaWdyYXRpb25zIjp7ImlzX2VudGl0bGVkIjp0cnVlfX19',
                          'timestamp': '2020-02-12T12:30:20.713120676Z',
                          'elapsed_time': 1581510621.724584},
    'timestamp': '2020-02-12T12:30:21.831767+00:00',
    'type': 'updated'}


def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        print(f'Message delivery failed: {err}')
    else:
        print(f'Message delivered to {msg.topic()} [{msg.partition()}]')


for x in range(1):  # increase this for more messages
    p.poll(0)
    p.produce(INVENTORY_ENGINE_MESSAGE_TOPIC, json.dumps(archive_message).encode(), callback=delivery_report)


p.flush()

print('done')
