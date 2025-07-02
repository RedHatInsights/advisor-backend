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

import app_common_python
from advisor_logging import logger
from confluent_kafka import Producer
from json import dumps as json_dumps

from project_settings import kafka_settings as kafka_settings

cfg = app_common_python.LoadedConfig


def topic(t):
    return app_common_python.KafkaTopics[t].name


def write_cert(cert):
    with open('/opt/certs/kafka-cacert', 'w') as f:
        f.write(cert)


producer = None
if kafka_settings.WEBHOOKS_TOPIC:
    logger.debug(f"Creating producer for topic: {kafka_settings.WEBHOOKS_TOPIC}")
    producer = Producer(kafka_settings.KAFKA_SETTINGS)


def report_delivery_callback(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        logger.error('Webhook event message delivery failed: {}'.format(err))
    else:
        logger.info('Webhook event message delivered to {} [{}]'.format(msg.topic(), msg.partition()))


def send_webhook_event(event_msg):
    if kafka_settings.WEBHOOKS_TOPIC:
        producer.poll(0)
        logger.info("Producing webhook event msg: %s", event_msg)
        send_msg = json_dumps(event_msg).encode('utf-8')
        producer.produce(
            kafka_settings.WEBHOOKS_TOPIC, send_msg,
            callback=report_delivery_callback
        )
        producer.flush()
