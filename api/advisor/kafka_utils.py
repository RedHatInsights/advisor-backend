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
from confluent_kafka import Consumer, Producer
from datetime import datetime
import json
from typing import Callable
from uuid import uuid4

import confluent_kafka
from project_settings import kafka_settings as kafka_settings

from django.core.signals import request_started, request_finished

cfg = app_common_python.LoadedConfig


def topic(t: str) -> str:
    return app_common_python.KafkaTopics[t].name


def write_cert(cert: str):
    with open('/opt/certs/kafka-cacert', 'w') as f:
        f.write(cert)


class DummyProducer(Producer):
    """
    A dummy Kafka producer for use during testing.
    """
    def __init__(self, *args, **kwargs):
        self.poll_calls = 0
        self.produce_calls = []
        self.flush_calls = 0

    def poll(self, time):
        self.poll_calls += 1

    def produce(self, topic, message, callback=None):
        self.produce_calls.append({
            'topic': topic,
            'message': message,
            'callback': callback,
        })

    def flush(self):
        self.flush_calls += 1


producer = None
if not kafka_settings.KAFKA_SETTINGS:
    # This means that we've been misconfigured
    logger.error("Tasks views require Kafka producer settings to send messages")
elif not kafka_settings.KAFKA_SETTINGS['bootstrap.servers']:
    # This means that we've been configured but from the Dev environment,
    # which doesn't include a default bootstrap server.  So we use the dummy
    # class above to just pretend to do stuff.
    logger.warning("Using dummy Kakfa producer")
    producer = DummyProducer()
else:
    producer = Producer(kafka_settings.KAFKA_SETTINGS)


# Message delivery callback

def report_delivery_callback(err: Exception | None, msg: confluent_kafka.Message):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is None:
        logger.info(
            'Webhook event message delivered to %s [%s]',
            msg.topic(), msg.partition()
        )
    else:
        logger.error('Webhook event message delivery failed: {}'.format(err))


def send_kakfa_message(topic, message):
    producer.poll(0)
    encoded_message = json.dumps(message).encode('utf8')
    producer.produce(topic, encoded_message, callback=report_delivery_callback)
    producer.flush()


def send_webhook_event(event_msg):
    # For compatibility - replace with direct calls to send_kakfa_message
    send_kakfa_message(kafka_settings.WEBHOOKS_TOPIC, event_msg)


class KafkaDispatcher(object):
    """
    Dispatches messages from Kafka to handlers based on their topic.  This
    handles the necessary boilerplate around receiving the message from Kafka,
    checking that it's valid, decoding it from JSON into a structure, and
    then processing that structure.

    Usage:

    >>> def topic_handler_fn(topic, body):
    ...     print(f"Received {body['name']} message from {topic}")
    ...
    >>> dispatcher = KafkaDispatcher()
    >>> dispatcher.register_handler("this topic", topic_handler_fn)
    >>> dispatcher.receive()

    A topic handler function can do anything, including setting the object's
    `quit` property to True which will cause the receive loop to exit at the
    next timeout of the wait for Kafka (defaults to 10 seconds).  Any return
    value from the topic handler function is ignored.

    Only one message handler can be registered to any topic.  If you need to
    do two or more things with a message, then give this a single handler
    function that then calls your other handlers.  This makes sure they're
    called in the order _you_ want, rather than the arbitrary order we might
    call them here.  Calling `register_handler` more than once will generate
    a warning and ignore the new handler function given.
    """
    def __init__(self):
        self.registered_handlers: dict[str, dict[str, Callable | dict[str, str]]] = {}
        self.quit: bool = False
        self.loop_timeout: int = 1
        # Own consumer for own set of topics
        self.consumer: Consumer = Consumer(kafka_settings.KAFKA_SETTINGS)

    def register_handler(self, topic: str, handler_fn: Callable, **kwargs):
        if topic in self.registered_handlers:
            logger.warn(
                'Topic %s already has function %s registered when trying to ' +
                'register function %s.  Ignoring this new handler.',
                topic, self.registered_handlers[topic]['handler'].__name__,
                handler_fn.__name__,
            )
            return
        self.registered_handlers[topic] = {
            'handler': handler_fn,
            'filters': kwargs
        }

    def _handle_message(self, message: confluent_kafka.Message | None):
        """
        Receive a message, find the handler for this topic, and run the
        message handler for this topic.
        """
        if message is None:
            return
        if message.error():
            logger.error(message.error())
            return

        topic = message.topic()
        if topic not in self.registered_handlers:
            # Would this be too noisy?
            logger.info("Received message for unregistered topic '%s'", topic)
            return

        # It is important we filter by headers so that we don't json.loads
        # every upload that is sent to CRC.
        # The headers come in as a list of tuples.  The filters is a dictionary.
        # Example Filters: {'service': 'tasks'}
        # Example Headers: [('service', b'tasks')]
        headers: list[tuple[str, bytes]] | None = message.headers()
        if headers is None:
            headers = []
        header_filters: dict[str, str] = self.registered_handlers[topic]['filters']

        # It's a toss-up here whether converting this to a dictionary makes
        # for faster comparisons, but it makes the code easier to read.
        header_dict: dict[str, str] = {
            key: value.decode('utf-8')
            for key, value in headers
        }
        filters_matched = all(
            (key in header_dict and header_dict[key] == value)
            for key, value in header_filters.items()
        )

        if not filters_matched:
            return

        # Decode JSON
        try:
            body = json.loads(message.value().decode('utf-8').strip('"'))
        except:
            logger.exception(f"Malformed JSON when handling {topic}")
            return
        # Tell Django we're starting a 'request' (db connection restarts...)
        request_started.send(sender=self.__class__)
        # Call handler with JSON
        try:
            handler = self.registered_handlers[topic]['handler']
            assert isinstance(handler, Callable)
            handler(topic, body)
        except:
            logger.exception(
                "Error processing kafka message",
                extra={
                    'topic': topic,
                    'payload': body
                }
            )
        # and we're finishing the 'request'
        request_finished.send(sender=self.__class__)

    def receive(self):
        """
        Run the receive loop continuously until told to stop.
        """
        self.consumer.subscribe(list(self.registered_handlers.keys()))

        while not self.quit:
            # longer polling timeouts mean fewer iterations through this loop,
            # but a longer time to respond to SIGTERM.  Here's the compromise:
            self._handle_message(self.consumer.poll(self.loop_timeout))
        self.consumer.close()
