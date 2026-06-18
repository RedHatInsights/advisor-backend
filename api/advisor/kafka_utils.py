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
from django.conf import settings

from django.core.signals import request_started, request_finished

cfg = app_common_python.LoadedConfig

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
type HandlerFunc = Callable[[str, JsonValue], None]


class HandlerEntry(TypedDict):
    handler: HandlerFunc
    filters: dict[str, str]
    batch: bool


type HandlerDataValue = HandlerEntry


class ProducerEntry(TypedDict):
    topic: str
    message: bytes | None
    callback: str | None


type ProducerEntryValue = ProducerEntry


duplicate_handler_warning_message = (
    'Topic %s already has function %s registered when trying to ' +  # noqa: W504
    'register function %s.  Ignoring this new handler.'
)


#############################################################################
# Dummy classes for use during testing

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
        self._partition: int = 0
        self._error: str = ''

    def topic(self) -> str:
        return self._topic

    def value(self) -> bytes:
        return self._value

    def headers(self) -> list[tuple[str, bytes]] | None:
        return self._headers

    def set_partition(self, partition: int):
        self._partition = partition

    def partition(self) -> int:
        return self._partition

    def set_error(self, error: str):
        self._error = error

    def error(self):
        return self._error


class DummyProducer:
    """
    A dummy Kafka producer for use during testing.
    """
    def __init__(self, *args, **kwargs):
        self.poll_calls: int = 0
        self.produce_calls: list[ProducerEntryValue] = []
        self.flush_calls: int = 0

    def poll(self, _time: int):
        self.poll_calls += 1

    def produce(self, topic: str, message: bytes, callback: Callable | None = None):
        self.produce_calls.append({
            'topic': topic,
            'message': message,
            'callback': callback.__name__ if callback else None,
        })
        if callback:
            dummy_message = DummyMessage(topic, message, headers=None)
            callback(err=None, msg=dummy_message)

    def flush(self):
        self.flush_calls += 1

    def reset_calls(self):
        self.poll_calls = 0
        self.produce_calls = []
        self.flush_calls = 0


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
        self.commit_count: int = 0
        self.store_offsets_count: int = 0
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

    def consume(self, num_messages: int = 1, timeout: float = 1.0) -> list[DummyMessage]:
        """
        Return up to num_messages from the queue, or an empty list if exhausted.
        """
        batch = []
        try:
            for _ in range(num_messages):
                msg = self.poll(timeout)
                if msg is None:
                    break
                batch.append(msg)
        except KafkaError:
            pass
        return batch

    def store_offsets(self, message=None, offsets=None):
        self.store_offsets_count += 1

    def commit(self, asynchronous=False):
        self.commit_count += 1

    def close(self):
        """Close the consumer."""
        self.closed = True


#############################################################################
# Setup

producer = None
if not settings.KAFKA_SETTINGS:
    # This means that we've been misconfigured
    logger.error("Kafka producer settings required to send messages")
elif not settings.KAFKA_SETTINGS.get('bootstrap.servers'):
    # This means that we've been configured but from the Dev environment,
    # which doesn't include a default bootstrap server.  So we use the dummy
    # class above to just pretend to do stuff.
    logger.warning("Using dummy Kakfa producer")
    producer = DummyProducer()
else:
    producer = Producer(settings.KAFKA_SETTINGS)


#############################################################################
# Message delivery callback

def report_delivery_callback(
    err: Exception | None, msg: confluent_kafka.Message | DummyMessage
):
    """
    Called once for each message produced to indicate delivery result.
    Triggered by poll() or flush().
    """
    if err is None:
        logger.info(
            'Kafka message delivered to %s [%s]',
            msg.topic(), msg.partition()
        )
    else:
        logger.error('Kafka message delivery failed: {}'.format(err))


def send_kafka_message(topic: str, message: JsonValue):
    """
    Simple helper to send a message on that topic.
    """
    if producer is None:
        logger.error("Kafka producer is not initialized")
        return
    producer.poll(0)
    encoded_message = json.dumps(message).encode('utf8')
    producer.produce(topic, encoded_message, callback=report_delivery_callback)
    producer.flush()


def send_webhook_event(event_msg: JsonValue):
    # For compatibility - replace with direct calls to send_kafka_message
    send_kafka_message(settings.WEBHOOKS_TOPIC, event_msg)


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
        self.loop_timeout: float = 0.5
        # When being tested, supply a DummyConsumer object that has added
        # messages via consumer.add_message().  Those messages will be processed
        # in the order they were added.
        if consumer is not None:
            self.consumer = consumer
        else:
            self.consumer: Consumer = Consumer(settings.KAFKA_SETTINGS)

    def register_handler(self, topic: str, handler_fn: HandlerFunc, batch: bool = False, **filters: dict[str, str]):
        if topic in self.registered_handlers:
            logger.warning(
                duplicate_handler_warning_message,
                topic, self.registered_handlers[topic]['handler'].__name__,
                handler_fn.__name__,
            )
            return
        self.registered_handlers[topic] = {
            'handler': handler_fn,
            'filters': filters,
            'batch': batch,
        }

    def _prepare_message(
        self, message: confluent_kafka.Message | DummyMessage | None
    ) -> tuple[str, JsonValue] | None:
        """
        Validate a raw Kafka message: check for errors, verify topic
        registration, match header filters, and decode JSON.

        Returns (topic, body) or None if the message should be skipped.
        """
        if message is None:
            return None
        if message.error():
            logger.error(message.error())
            return None

        topic = message.topic()
        if topic not in self.registered_handlers:
            logger.info("Received message for unregistered topic '%s'", topic)
            return None

        headers: list[tuple[str, bytes]] | None = message.headers()
        if headers is None:
            headers = []
        header_filters: dict[str, str] = self.registered_handlers[topic]['filters']
        header_dict: dict[str, str] = {
            key: value.decode('utf-8')
            for key, value in headers
            if value
        }
        filters_matched = all(
            (key in header_dict and header_dict[key] == value)
            for key, value in header_filters.items()
        )
        if not filters_matched:
            return None

        try:
            body = json.loads(message.value().decode('utf-8').strip('"'))
        except Exception as e:
            logger.exception(f"Malformed JSON when handling {topic}: {e}")
            return None

        return topic, body

    def _handle_message(self, message: confluent_kafka.Message | DummyMessage | None):
        """
        Receive a message, find the handler for this topic, and run the
        message handler for this topic.
        """
        prepared = self._prepare_message(message)
        if prepared is None:
            return

        topic, body = prepared
        handler_entry = self.registered_handlers[topic]
        if handler_entry['batch']:
            logger.error(
                "Handler for topic '%s' requires batch mode but receive() "
                "was called without batch_size — skipping message", topic
            )
            return

        request_started.send(sender=self.__class__)
        try:
            handler = handler_entry['handler']
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
        request_finished.send(sender=self.__class__)

    def _handle_batch_messages(self, messages: list[confluent_kafka.Message | DummyMessage]) -> bool:
        """
        Handle a batch of messages: group by topic, call each handler once
        with the full list of parsed bodies.

        Returns True if all batch handlers succeeded, False if any raised.
        """
        grouped: dict[str, list[JsonValue]] = {}
        for message in messages:
            prepared = self._prepare_message(message)
            if prepared is None:
                continue
            topic, body = prepared
            if topic not in grouped:
                grouped[topic] = []
            grouped[topic].append(body)

        batch_success = True
        for topic, bodies in grouped.items():
            handler_entry = self.registered_handlers[topic]
            handler = handler_entry['handler']
            invocations = [bodies] if handler_entry['batch'] else bodies

            for payload in invocations:
                request_started.send(sender=self.__class__)
                try:
                    handler(topic, payload)
                except Exception as e:
                    batch_success = False
                    logger.exception(
                        "Error processing kafka message",
                        extra={
                            'topic': topic,
                            'error': str(e)
                        }
                    )
                request_finished.send(sender=self.__class__)

        return batch_success

    def _store_offsets(self, messages: list[confluent_kafka.Message | DummyMessage]) -> None:
        for message in messages:
            if message.error():
                continue
            self.consumer.store_offsets(message=message)

    def _receive_batch(self, batch_size: int):
        while not self.quit:
            try:
                messages = self.consumer.consume(num_messages=batch_size, timeout=self.loop_timeout)
            except Exception as e:
                logger.exception("Error consuming Kafka messages: %s", e)
                continue
            if not messages:
                continue
            success = self._handle_batch_messages(messages)
            if success:
                try:
                    logger.debug("Storing offsets for %d messages", len(messages))
                    self._store_offsets(messages)
                    logger.debug("Committing offsets for %d messages", len(messages))
                    self.consumer.commit(asynchronous=False)
                    logger.debug("Offsets committed successfully")
                except Exception as e:
                    logger.exception("Error committing Kafka offsets: %s", e)

    def _receive_single(self):
        while not self.quit:
            self._handle_message(self.consumer.poll(self.loop_timeout))

    def receive(self, batch_size: int | None = None):
        """
        Run the receive loop continuously until told to stop.
        When batch_size is provided, consume messages in batches.
        """
        self.consumer.subscribe(list(self.registered_handlers.keys()))

        if batch_size is not None:
            self._receive_batch(batch_size)
        else:
            self._receive_single()

        self.consumer.close()
