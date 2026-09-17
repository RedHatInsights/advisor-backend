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

from django.test import SimpleTestCase as TestCase  # , override_settings

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

    def test_handle_batch_messages_returns_true_on_success(self):
        """Test that _handle_batch_messages returns True when all handlers succeed."""
        consumer = DummyConsumer()
        consumer.add_message('topic', {'msg': 1})

        batch_handler = DummyBatchHandler('batch_handler')
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('topic', batch_handler, batch=True)

        messages = consumer.consume(num_messages=1, timeout=1)
        result = dispatcher._handle_batch_messages(messages)

        self.assertTrue(result)

    def test_handle_batch_messages_returns_false_on_handler_exception(self):
        """Test that _handle_batch_messages returns False when a batch handler raises."""
        consumer = DummyConsumer()
        consumer.add_message('topic', {'msg': 1})

        def failing_handler(topic, messages):
            raise RuntimeError("DB is down")

        failing_handler.__name__ = 'failing_handler'
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('topic', failing_handler, batch=True)

        messages = consumer.consume(num_messages=1, timeout=1)
        with self.assertLogs(logger='advisor-log'):
            result = dispatcher._handle_batch_messages(messages)

        self.assertFalse(result)

    def test_receive_commits_on_success(self):
        """Test that receive() commits offsets after successful batch processing."""
        consumer = DummyConsumer()
        consumer.add_message('topic', {'msg': 1})
        consumer.add_message('topic', {'msg': 2})

        batch_handler = DummyBatchHandler('batch_handler')
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('topic', batch_handler, batch=True)
        consumer.set_dispatcher_quit(dispatcher)

        dispatcher.receive(batch_size=10)

        self.assertGreater(consumer.store_offsets_count, 0)
        self.assertGreater(consumer.commit_count, 0)

    def test_receive_does_not_commit_on_failure(self):
        """Test that receive() skips commit when a batch handler raises."""
        consumer = DummyConsumer()
        consumer.add_message('topic', {'msg': 1})

        def failing_handler(topic, messages):
            raise RuntimeError("DB is down")

        failing_handler.__name__ = 'failing_handler'
        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('topic', failing_handler, batch=True)
        consumer.set_dispatcher_quit(dispatcher)

        with self.assertLogs(logger='advisor-log'):
            dispatcher.receive(batch_size=10)

        self.assertEqual(consumer.store_offsets_count, 0)
        self.assertEqual(consumer.commit_count, 0)

    def test_prepare_message_preserves_headers(self):
        """Test that _prepare_message returns (topic, body, headers) without discarding headers."""
        consumer = DummyConsumer()
        headers = [('traceparent', b'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')]
        msg = DummyMessage('test_topic', b'{"key": "val"}', headers=headers)

        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('test_topic', lambda t, b: None)

        prepared = dispatcher._prepare_message(msg)
        self.assertIsNotNone(prepared)
        topic, body, ret_headers = prepared
        self.assertEqual(topic, 'test_topic')
        self.assertEqual(body, {'key': 'val'})
        self.assertEqual(ret_headers, headers)

    def test_handle_message_trace_propagation(self):
        """Test that _handle_message creates a CONSUMER span inheriting parent trace context."""
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            import telemetry
        except ImportError:
            self.skipTest("OpenTelemetry dependencies not installed yet")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        if hasattr(trace, "_TRACER_PROVIDER_SET_ONCE"):
            trace._TRACER_PROVIDER_SET_ONCE._done = False
        trace.set_tracer_provider(provider)
        telemetry._IS_INITIALIZED = True

        trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        span_id = "00f067aa0ba902b7"
        headers = [('traceparent', f"00-{trace_id}-{span_id}-01".encode())]
        msg = DummyMessage('test_topic', b'{"status": "ok"}', headers=headers)

        handler = DummyHandler('test_handler')
        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler('test_topic', handler)
        dispatcher._handle_message(msg)

        self.assertEqual(len(handler.handled['test_topic']), 1)
        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(format(spans[0].context.trace_id, "032x"), trace_id)
        self.assertEqual(format(spans[0].parent.span_id, "016x"), span_id)

    def test_handle_batch_messages_span_links(self):
        """Test that _handle_batch_messages creates a batch span with Links to each message's trace."""
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            import telemetry
        except ImportError:
            self.skipTest("OpenTelemetry dependencies not installed yet")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        if hasattr(trace, "_TRACER_PROVIDER_SET_ONCE"):
            trace._TRACER_PROVIDER_SET_ONCE._done = False
        trace.set_tracer_provider(provider)
        telemetry._IS_INITIALIZED = True

        trace_1 = "4bf92f3577b34da6a3ce929d0e0e4736"
        trace_2 = "6cf92f3577b34da6a3ce929d0e0e4799"
        msg1 = DummyMessage('batch_topic', b'{"id": 1}', headers=[('traceparent', f"00-{trace_1}-00f067aa0ba902b7-01".encode())])
        msg2 = DummyMessage('batch_topic', b'{"id": 2}', headers=[('traceparent', f"00-{trace_2}-00f067aa0ba902c8-01".encode())])

        batch_handler = DummyBatchHandler('batch_handler')
        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler('batch_topic', batch_handler, batch=True)
        dispatcher._handle_batch_messages([msg1, msg2])

        spans = exporter.get_finished_spans()
        batch_span = next((s for s in spans if "batch process" in s.name), None)
        self.assertIsNotNone(batch_span)
        self.assertEqual(len(batch_span.links), 2)
        linked_traces = {format(link.context.trace_id, "032x") for link in batch_span.links}
        self.assertEqual(linked_traces, {trace_1, trace_2})

    def test_handle_message_records_exception_and_error_status(self):
        """Test that _handle_message records exception and sets StatusCode.ERROR on span when handler fails."""
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            from opentelemetry.trace import StatusCode
            from unittest.mock import patch
        except ImportError:
            self.skipTest("OpenTelemetry dependencies not installed yet")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("advisor-kafka")

        def failing_handler(topic, payload):
            raise ValueError("Simulated handler crash")

        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler('error_topic', failing_handler)
        msg = DummyMessage('error_topic', b'{"data": "test"}')

        with patch("telemetry.get_tracer", return_value=tracer):
            dispatcher._handle_message(msg)

        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.status.status_code, StatusCode.ERROR)
        self.assertEqual(span.status.description, "Simulated handler crash")
        self.assertEqual(len(span.events), 1)
        self.assertEqual(span.events[0].name, "exception")
        self.assertEqual(span.events[0].attributes["exception.type"], "ValueError")
        self.assertEqual(span.events[0].attributes["exception.message"], "Simulated handler crash")

    def test_handle_batch_messages_records_exception_and_error_status(self):
        """Test that _handle_batch_messages records exception and sets StatusCode.ERROR on batch span when batch handler fails."""
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            from opentelemetry.trace import StatusCode
            from unittest.mock import patch
        except ImportError:
            self.skipTest("OpenTelemetry dependencies not installed yet")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("advisor-kafka")

        def failing_batch_handler(topic, bodies):
            raise RuntimeError("Batch processing error")

        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler('error_batch_topic', failing_batch_handler, batch=True)
        msg1 = DummyMessage('error_batch_topic', b'{"id": 1}')
        msg2 = DummyMessage('error_batch_topic', b'{"id": 2}')

        with patch("telemetry.get_tracer", return_value=tracer):
            result = dispatcher._handle_batch_messages([msg1, msg2])

        self.assertFalse(result)
        spans = exporter.get_finished_spans()
        batch_span = next((s for s in spans if "batch process" in s.name), None)
        self.assertIsNotNone(batch_span)
        self.assertEqual(batch_span.status.status_code, StatusCode.ERROR)
        self.assertEqual(batch_span.status.description, "Batch processing error")
        self.assertEqual(len(batch_span.events), 1)
        self.assertEqual(batch_span.events[0].name, "exception")
        self.assertEqual(batch_span.events[0].attributes["exception.type"], "RuntimeError")
        self.assertEqual(batch_span.events[0].attributes["exception.message"], "Batch processing error")

    def test_handle_batch_messages_non_batch_records_exception_and_error_status(self):
        """Test that _handle_batch_messages records exception and sets StatusCode.ERROR on per-item span when non-batch handler fails."""
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            from opentelemetry.trace import StatusCode
            from unittest.mock import patch
        except ImportError:
            self.skipTest("OpenTelemetry dependencies not installed yet")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("advisor-kafka")

        def failing_item_handler(topic, payload):
            raise KeyError("Missing field in payload")

        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler('error_item_topic', failing_item_handler, batch=False)
        msg = DummyMessage('error_item_topic', b'{"id": 100}')

        with patch("telemetry.get_tracer", return_value=tracer):
            result = dispatcher._handle_batch_messages([msg])

        self.assertFalse(result)
        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.status.status_code, StatusCode.ERROR)
        self.assertEqual(span.status.description, "'Missing field in payload'")
        self.assertEqual(len(span.events), 1)
        self.assertEqual(span.events[0].name, "exception")
        self.assertEqual(span.events[0].attributes["exception.type"], "KeyError")

    def test_prepare_message_throughput_benchmark(self):
        """Verifies that _prepare_message executes in < 10 microseconds per message over 10,000 calls."""
        import time

        consumer = DummyConsumer()
        headers = [('traceparent', b'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')]
        msg = DummyMessage('bench_topic', b'{"system_id": "123", "data": "test"}', headers=headers)

        dispatcher = KafkaDispatcher(consumer)
        dispatcher.register_handler('bench_topic', lambda t, b: None)

        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            dispatcher._prepare_message(msg)
        duration = time.perf_counter() - start

        avg_per_call = duration / iterations
        self.assertLess(avg_per_call, 0.000010, f"_prepare_message too slow: {avg_per_call * 1e6:.2f}us/msg")

    def test_batch_dispatch_throughput_with_span_links(self):
        """Verifies that _handle_batch_messages processes 500 batches of 20 messages in < 2.0 seconds (> 5000 msg/sec)."""
        import time

        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler('throughput_topic', lambda t, b: None, batch=True)

        batch = [
            DummyMessage(
                'throughput_topic',
                f'{{"id": {i}, "name": "host-{i}"}}'.encode(),
                headers=[('traceparent', b'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')]
            )
            for i in range(20)
        ]

        iterations = 500
        start = time.perf_counter()
        for _ in range(iterations):
            dispatcher._handle_batch_messages(batch)
        duration = time.perf_counter() - start

        total_messages = iterations * 20
        rate = total_messages / duration
        self.assertGreater(rate, 5000, f"Batch dispatch throughput too low: {rate:.0f} msg/sec")

    def test_kafka_dispatcher_dormant_when_telemetry_uninitialized(self):
        """
        Verifies that when telemetry is uninitialized/disabled,
        KafkaDispatcher dispatching (single & batch) performs zero span operations
        and does not invoke header extraction.
        """
        import telemetry
        from unittest.mock import patch

        telemetry._IS_INITIALIZED = False
        dispatcher = KafkaDispatcher(DummyConsumer())
        msg = DummyMessage('test_topic', b'{"id": 1}', headers=[('traceparent', b'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')])

        handled_single = []
        dispatcher.register_handler('test_topic', lambda t, b: handled_single.append(b), batch=False)

        handled_batch = []
        dispatcher.register_handler('test_batch_topic', lambda t, b: handled_batch.append(b), batch=True)
        batch_msg = DummyMessage('test_batch_topic', b'{"id": 2}', headers=[('traceparent', b'00-6cf92f3577b34da6a3ce929d0e0e4799-00f067aa0ba902c8-01')])

        with patch("telemetry.extract_kafka_headers_to_context") as mock_extract:
            # Single message dispatch
            dispatcher._handle_message(msg)
            # Batch message dispatch
            dispatcher._handle_batch_messages([batch_msg])

            # Handlers must execute successfully
            self.assertEqual(len(handled_single), 1)
            self.assertEqual(len(handled_batch), 1)

            # Header extraction MUST NOT be called when disabled
            mock_extract.assert_not_called()
