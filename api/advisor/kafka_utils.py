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
# from collections.abc import Callable as AbcCallable
from confluent_kafka import Consumer, KafkaError, Producer
import json
from typing import Callable, TypedDict

import confluent_kafka
from project_settings import kafka_settings as kafka_settings

from django.core.signals import request_started, request_finished

cfg = app_common_python.LoadedConfig

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
type HandlerFunc = Callable[[str, JsonValue], None]


class HandlerEntry(TypedDict):
    handler: HandlerFunc
    filters: dict[str, str]


type HandlerDataValue = HandlerEntry


duplicate_handler_warning_message = (
    'Topic %s already has function %s registered when trying to ' +  # noqa: W504
    'register function %s.  Ignoring this new handler.'
)


#############################################################################
# These two copied from the service, but do we use them?
def topic(t: str) -> str:
    return app_common_python.KafkaTopics[t].name


def write_cert(cert: str):
    with open('/opt/certs/kafka-cacert', 'w') as f:
        f.write(cert)


#############################################################################
# Dummy classes for use during testing

class DummyProducer:
    """
    A dummy Kafka producer for use during testing.
    """
    def __init__(self, *args, **kwargs):
        self.poll_calls: int = 0
        self.produce_calls: list[dict[str, str | None]] = []
        self.flush_calls: int = 0

    def poll(self, _time: int):
        self.poll_calls += 1

    def produce(self, topic: str, message: str, callback: str | None = None):
        self.produce_calls.append({
            'topic': topic,
            'message': message,
            'callback': callback,
        })

    def flush(self):
        self.flush_calls += 1


class DummyMessage():
    """
    A dummy Kafka message for use during testing.

    Do not base this on confluent_kafka.Message because it seems to have a
    weird initialisation process that we don't want to follow for tests.
    """
    def __init__(self, topic: str, value: bytes, headers: list[tuple[str, bytes]] | None = None):
        self._topic: str = topic
        self._value: bytes = value
        self._headers: list[tuple[str, bytes]] | None = headers
        self._error: str = None

    def topic(self) -> str:
        return self._topic

    def value(self) -> bytes:
        return self._value

    def headers(self) -> list[tuple[str, bytes]] | None:
        return self._headers

    def set_error(self, error: str):
        self._error = error

    def error(self):
        return self._error


class DummyConsumer():
    """
    A dummy Kafka consumer for use during testing.

    Usage:
        consumer = DummyConsumer()
        consumer.add_message('topic-name', {'key': 'value'})
        consumer.add_message('topic-name', {'key': 'value2'}, headers=[('service', b'tasks')])

        # Now when poll() is called, it will return these messages in order
    """
    def __init__(self, *args, **kwargs):
        self.messages: list[DummyMessage | None] = []
        self.message_index: int = 0
        self.subscribed_topics: list[str] = []
        self.closed: bool = False
        self.dispatcher_to_quit: 'KafkaDispatcher' | None = None

    def add_message(
        self, topic: str, value: JsonValue, headers: list[tuple[str, bytes]] | None = None
    ):
        """
        Add a message to the queue that will be returned by poll().
        """
        message_value = json.dumps(value).encode('utf-8')
        self.messages.append(DummyMessage(topic, message_value, headers))

    def add_message_obj(self, message: DummyMessage):
        """
        Add a message object to the queue that will be returned by poll().
        """
        self.messages.append(message)

    def set_dispatcher_quit(self, dispatcher: 'KafkaDispatcher'):
        """
        When we reach the end of the message queue, set the 'quit' flag on
        the dispatcher.  This is mainly for testing, to save having to have a
        sentinel message.
        """
        self.dispatcher_to_quit = dispatcher

    def subscribe(self, topics: list[str]):
        """
        Subscribe to topics.
        """
        self.subscribed_topics = topics
        # Because the handler subscribes to the list of topics after the dummy
        # consumer has added them as test data, should we check at this point
        # that indeed those messages are all in the subscribed topics?  Maybe
        # we want to see if the handler fails correctly?

    def poll(self, timeout: int = 0) -> DummyMessage | None:
        """
        Return the next message in the queue, or None if no more messages.
        """
        if self.closed:
            if self.dispatcher_to_quit:
                self.dispatcher_to_quit.quit = True
                return None
            else:
                raise KafkaError(KafkaError._PARTITION_EOF, "Consumer is closed")
        if self.message_index < len(self.messages):
            message = self.messages[self.message_index]
            self.message_index += 1
            return message
        self.closed = True
        # This would be a good point for the calling message handler to have
        # set up a function which sets the KafkaHandler's `quit` property.
        return None

    def close(self):
        """Close the consumer."""
        self.closed = True


#############################################################################
# Setup

producer = None
if not kafka_settings.KAFKA_SETTINGS:
    # This means that we've been misconfigured
    logger.error("Kafka producer settings required to send messages")
elif not kafka_settings.KAFKA_SETTINGS.get('bootstrap.servers'):
    # This means that we've been configured but from the Dev environment,
    # which doesn't include a default bootstrap server.  So we use the dummy
    # class above to just pretend to do stuff.
    logger.warning("Using dummy Kakfa producer")
    producer = DummyProducer()
else:
    producer = Producer(kafka_settings.KAFKA_SETTINGS)


#############################################################################
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


def send_kafka_message(topic: str, message: JsonValue):
    if producer is None:
        logger.error("Kafka producer is not initialized")
        return
    producer.poll(0)
    encoded_message = json.dumps(message).encode('utf8')
    producer.produce(topic, encoded_message, callback=report_delivery_callback)
    producer.flush()


def send_webhook_event(event_msg: JsonValue):
    # For compatibility - replace with direct calls to send_kafka_message
    send_kafka_message(kafka_settings.WEBHOOKS_TOPIC, event_msg)


#############################################################################
# Kafka message dispatch service class

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
    def __init__(self, consumer: Consumer | None = None):
        self.registered_handlers: dict[str, HandlerEntry] = {}
        self.quit: bool = False
        self.loop_timeout: int = 1
        # When being tested, supply a DummyConsumer object that has added
        # messages via consumer.add_message().  Those messages will be processed
        # in the order they were added.
        if consumer is not None:
            self.consumer = consumer
        else:
            self.consumer: Consumer = Consumer(kafka_settings.KAFKA_SETTINGS)

    def register_handler(self, topic: str, handler_fn: HandlerFunc, **filters: dict[str, str]):
        if topic in self.registered_handlers:
            logger.warning(
                duplicate_handler_warning_message,
                topic, self.registered_handlers[topic]['handler'].__name__,
                handler_fn.__name__,
            )
            return
        self.registered_handlers[topic] = {
            'handler': handler_fn,
            'filters': filters
        }

    def _handle_message(self, message: confluent_kafka.Message | DummyMessage | None):
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
        except Exception as e:
            logger.exception(f"Malformed JSON when handling {topic}: {e}")
            return
        # Tell Django we're starting a 'request' (db connection restarts...)
        request_started.send(sender=self.__class__)
        # Call handler with JSON
        try:
            handler = self.registered_handlers[topic]['handler']
            # assert isinstance(handler, AbcCallable)
            handler(topic, body)
        except Exception as e:
            logger.exception(
                "Error processing kafka message",
                extra={
                    'topic': topic,
                    'payload': body,
                    'error': str(e)
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
