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

from kafka_utils import DummyMessage, DummyConsumer, JsonValue, KafkaDispatcher


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
