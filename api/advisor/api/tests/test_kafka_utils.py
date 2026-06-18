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

from django.test import TestCase  # , override_settings

from kafka_utils import (
    DummyMessage, DummyConsumer, JsonValue, KafkaDispatcher,
    send_kafka_message,
)


class DummyHandler:
    """
    Record the messages sent to the handler by the dispatcher.
    """
    def __init__(self, name: str):
        self.handled: dict[str, list[JsonValue]] = {}
        self.__name__: str = name

    def __call__(self, topic: str, message: JsonValue):
        if topic not in self.handled:
            self.handled[topic] = []
        self.handled[topic].append(message)

    def reset(self):
        self.handled = {}


class DummyBatchHandler:
    """
    Record the batch of messages sent to the handler by the dispatcher.
    """
    def __init__(self, name: str):
        self.handled: dict[str, list[list[JsonValue]]] = {}
        self.__name__: str = name

    def __call__(self, topic: str, messages: list[JsonValue]):
        if topic not in self.handled:
            self.handled[topic] = []
        self.handled[topic].append(messages)

    def reset(self):
        self.handled = {}


class TestKafkaUtils(TestCase):
    """
    Test the Kafka Utils functionality, particularly around the KafkaDispatcher.
    """

    def test_message_failures(self):
        """
        Test that the server handles malformed and incorrect messages correctly.
        """
        consumer = DummyConsumer()
        # A malformed message
        malformed = DummyMessage(topic="malformed", value=b'JSON{no=work}')
        consumer.add_message_obj(malformed)
        # A message for a spurious topic
        consumer.add_message(topic="spurious", value={"key": "value"})
        # A message with a set error
        error_msg = DummyMessage(topic="error", value=b'{"error": "error"}')
        error_msg.set_error("Dramatic exit, scene left!")
        # Just test that we can set a partition, it's ignored.
        error_msg.set_partition(1)
        consumer.add_message_obj(error_msg)

        def error_prone_handler(topic: str, body: JsonValue):
            raise ValueError(f"Error from {topic=} with {body=}")

        consumer.add_message(topic='error', value={'data': 'something else'})

        # Call the server with the consumer
        dispatcher = KafkaDispatcher(consumer)
        handler = DummyHandler('malform_handler')
        with self.assertLogs(logger='advisor-log') as logs:
            dispatcher.register_handler('malformed', handler)
            # Duplicate handler check
            dispatcher.register_handler('malformed', handler)
            # Error thrown by handler
            dispatcher.register_handler('error', error_prone_handler)
            # quit out cleanly when we run out of messages
            consumer.set_dispatcher_quit(dispatcher)
            dispatcher.receive()
            # No messages handled because it caught errors.
            self.assertEqual(handler.handled, {})
            # Logs should recognise failures:
            self.assertIn(
                'Topic malformed already has function malform_handler '
                'registered when trying to register function malform_handler.  '
                'Ignoring this new handler.',
                logs.output[0]
            )
            self.assertIn(  # full log includes a traceback...
                'Malformed JSON when handling malformed',
                logs.output[1]
            )
            self.assertEqual(
                "INFO:advisor-log:Received message for unregistered topic 'spurious'",
                logs.output[2]
            )
            self.assertEqual(
                "ERROR:advisor-log:Dramatic exit, scene left!",
                logs.output[3]
            )
            self.assertIn(  # full log includes a traceback...
                "ValueError: Error from topic='error' with body={'data': 'something else'}",
                logs.output[4]
            )

    def test_send_kafka_message(self):
        import kafka_utils
        current_producer = kafka_utils.producer

        # Test logs if no producer
        kafka_utils.producer = None
        with self.assertLogs(logger='advisor-log') as logs:
            send_kafka_message('test_topic', {'data': 'test_data'})
            self.assertEqual(
                logs.output[0], "ERROR:advisor-log:Kafka producer is not initialized"
            )
        kafka_utils.producer = current_producer
        current_producer.reset_calls()

        # Now test that we actually did something with our producer
        with self.assertLogs(logger='advisor-log') as logs:
            send_kafka_message('test_topic', {'data': 'test_data'})
            self.assertEqual(current_producer.poll_calls, 1)
            self.assertEqual(
                current_producer.produce_calls[0]['topic'], 'test_topic'
            )
            self.assertEqual(
                current_producer.produce_calls[0]['message'], b'{"data": "test_data"}'
            )
            self.assertEqual(
                current_producer.produce_calls[0]['callback'], 'report_delivery_callback'
            )
            self.assertEqual(current_producer.flush_calls, 1)
            # The report_delivery_callback function should have logged
            # delivery of the message.
            self.assertEqual(
                logs.output[0], "INFO:advisor-log:Kafka message delivered to test_topic [0]"
            )

    def test_dummy_consumer_consume(self):
        """Test that DummyConsumer.consume() returns batches of messages."""
        consumer = DummyConsumer()
        consumer.add_message('topic1', {'key': 'value1'})
        consumer.add_message('topic1', {'key': 'value2'})
        consumer.add_message('topic1', {'key': 'value3'})

        # Consume batch of 2 — should return first 2
        batch = consumer.consume(num_messages=2, timeout=1)
        self.assertEqual(len(batch), 2)
        self.assertEqual(batch[0].topic(), 'topic1')
        self.assertEqual(batch[1].topic(), 'topic1')

        # Consume next batch of 2 — only 1 left
        batch = consumer.consume(num_messages=2, timeout=1)
        self.assertEqual(len(batch), 1)

        # Consume again — empty, triggers close
        batch = consumer.consume(num_messages=2, timeout=1)
        self.assertEqual(len(batch), 0)
        self.assertTrue(consumer.closed)

    def test_batch_message_handling(self):
        """Test that _handle_batch_messages processes a batch and calls the handler once per topic."""
        consumer = DummyConsumer()
        consumer.add_message('batch-topic', {'key': 'value1'})
        consumer.add_message('batch-topic', {'key': 'value2'})
        consumer.add_message('batch-topic', {'key': 'value3'})

        batch_handler = DummyBatchHandler('batch_handler')
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('batch-topic', batch_handler, batch=True)

        messages = consumer.consume(num_messages=3, timeout=1)
        dispatcher._handle_batch_messages(messages)

        self.assertIn('batch-topic', batch_handler.handled)
        self.assertEqual(len(batch_handler.handled['batch-topic']), 1)
        bodies = batch_handler.handled['batch-topic'][0]
        self.assertEqual(len(bodies), 3)
        self.assertEqual(bodies[0], {'key': 'value1'})
        self.assertEqual(bodies[1], {'key': 'value2'})
        self.assertEqual(bodies[2], {'key': 'value3'})

    def test_batch_message_skips_errors_and_unmatched(self):
        """Test that _handle_batch_messages skips errors, malformed JSON, and unmatched topics."""
        consumer = DummyConsumer()
        # A good message
        consumer.add_message('batch-topic', {'key': 'good'})
        # A message for an unregistered topic
        consumer.add_message('unknown-topic', {'key': 'lost'})
        # An error message
        error_msg = DummyMessage(topic='batch-topic', value=b'{"key": "err"}')
        error_msg.set_error("Test error")
        consumer.add_message_obj(error_msg)
        # A malformed JSON message
        malformed = DummyMessage(topic='batch-topic', value=b'not{json')
        consumer.add_message_obj(malformed)
        # Another good message
        consumer.add_message('batch-topic', {'key': 'also-good'})

        batch_handler = DummyBatchHandler('batch_handler')
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('batch-topic', batch_handler, batch=True)

        messages = consumer.consume(num_messages=10, timeout=1)
        with self.assertLogs(logger='advisor-log'):
            dispatcher._handle_batch_messages(messages)

        # Only the 2 good messages should reach the handler
        bodies = batch_handler.handled['batch-topic'][0]
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0], {'key': 'good'})
        self.assertEqual(bodies[1], {'key': 'also-good'})

    def test_receive_with_batch_size(self):
        """Test that receive(batch_size=N) uses consume() and _handle_batch_messages."""
        consumer = DummyConsumer()
        consumer.add_message('batch-topic', {'msg': 1})
        consumer.add_message('batch-topic', {'msg': 2})
        consumer.add_message('batch-topic', {'msg': 3})

        batch_handler = DummyBatchHandler('batch_handler')
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('batch-topic', batch_handler, batch=True)
        consumer.set_dispatcher_quit(dispatcher)

        dispatcher.receive(batch_size=2)

        # Handler should have been called with batches
        self.assertIn('batch-topic', batch_handler.handled)
        all_bodies = []
        for call in batch_handler.handled['batch-topic']:
            all_bodies.extend(call)
        self.assertEqual(len(all_bodies), 3)

    def test_non_batch_handler_with_batch_receive(self):
        """Test that a non-batch handler is called once per message even with batch_size."""
        consumer = DummyConsumer()
        consumer.add_message('topic', {'msg': 1})
        consumer.add_message('topic', {'msg': 2})
        consumer.add_message('topic', {'msg': 3})

        handler = DummyHandler('single_handler')
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('topic', handler)
        consumer.set_dispatcher_quit(dispatcher)

        dispatcher.receive(batch_size=10)

        self.assertIn('topic', handler.handled)
        self.assertEqual(len(handler.handled['topic']), 3)
        self.assertEqual(handler.handled['topic'][0], {'msg': 1})
        self.assertEqual(handler.handled['topic'][1], {'msg': 2})
        self.assertEqual(handler.handled['topic'][2], {'msg': 3})
