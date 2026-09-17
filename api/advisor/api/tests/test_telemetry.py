# Copyright 2016-2026 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

import os
from django.test import SimpleTestCase
import thread_storage
import telemetry

try:
    from opentelemetry import baggage
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class TestTelemetryBase(SimpleTestCase):
    def test_string_to_bool(self):
        # Standard truthy strings
        self.assertTrue(telemetry.string_to_bool("true"))
        self.assertTrue(telemetry.string_to_bool("True"))
        self.assertTrue(telemetry.string_to_bool("TRUE"))
        self.assertTrue(telemetry.string_to_bool("1"))
        self.assertTrue(telemetry.string_to_bool("yes"))
        self.assertTrue(telemetry.string_to_bool("YES"))
        self.assertTrue(telemetry.string_to_bool("t"))
        self.assertTrue(telemetry.string_to_bool("T"))
        # Whitespace-padded truthy strings
        self.assertTrue(telemetry.string_to_bool("  true  "))
        self.assertTrue(telemetry.string_to_bool(" 1 "))

        # Standard falsy strings
        self.assertFalse(telemetry.string_to_bool("false"))
        self.assertFalse(telemetry.string_to_bool("False"))
        self.assertFalse(telemetry.string_to_bool("FALSE"))
        self.assertFalse(telemetry.string_to_bool("0"))
        self.assertFalse(telemetry.string_to_bool("no"))
        self.assertFalse(telemetry.string_to_bool("NO"))
        self.assertFalse(telemetry.string_to_bool("f"))
        self.assertFalse(telemetry.string_to_bool("F"))
        # Whitespace-padded falsy strings
        self.assertFalse(telemetry.string_to_bool("  false  "))
        self.assertFalse(telemetry.string_to_bool(" 0 "))

        # Edge cases (None, empty, non-boolean words)
        self.assertFalse(telemetry.string_to_bool(None))
        self.assertFalse(telemetry.string_to_bool(""))
        self.assertFalse(telemetry.string_to_bool("   "))
        self.assertFalse(telemetry.string_to_bool("disabled"))
        self.assertFalse(telemetry.string_to_bool("unknown"))

    def test_extract_kafka_headers_to_context_empty(self):
        """Issue 08: When headers are missing or empty, returns None so ambient context is inherited."""
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        ctx = telemetry.extract_kafka_headers_to_context(None)
        self.assertIsNone(ctx)
        ctx_empty = telemetry.extract_kafka_headers_to_context([])
        self.assertIsNone(ctx_empty)

    def test_extract_kafka_headers_to_context_with_traceparent(self):
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        span_id = "00f067aa0ba902b7"
        headers = [("traceparent", f"00-{trace_id}-{span_id}-01".encode())]
        ctx = telemetry.extract_kafka_headers_to_context(headers)
        self.assertIsNotNone(ctx)

    def test_init_telemetry_disabled_by_default(self):
        telemetry._IS_INITIALIZED = False
        telemetry._INITIALIZED_PID = None
        os.environ["OTEL_ENABLED"] = "false"
        telemetry.init_telemetry(service_name="test-advisor")
        self.assertFalse(telemetry._IS_INITIALIZED)

    def test_init_telemetry_enabled(self):
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        telemetry._IS_INITIALIZED = False
        telemetry._INITIALIZED_PID = None
        os.environ["OTEL_ENABLED"] = "true"
        telemetry.init_telemetry(service_name="test-advisor", force_reinit=True)
        self.assertTrue(telemetry._IS_INITIALIZED)
        self.assertEqual(telemetry._INITIALIZED_PID, os.getpid())

    def test_shutdown_telemetry(self):
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        telemetry._IS_INITIALIZED = True
        telemetry.shutdown_telemetry()


class TestTelemetrySpanEnrichment(SimpleTestCase):
    def setUp(self):
        super().setUp()
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("test-advisor-api")

    def test_django_response_hook_enriches_root_span(self):
        """Verifies that _django_response_hook attaches rh.org_id, rh.request_id, and rh.account to the root SERVER span."""
        from telemetry import _django_response_hook

        with self.tracer.start_as_current_span("GET /api/insights/v1/rule/") as span:
            mock_request = type("Request", (), {
                "org_id": "1979710",
                "account": "540155",
                "META": {"HTTP_X_RH_INSIGHTS_REQUEST_ID": "test-req-123"}
            })()
            _django_response_hook(span, mock_request, None)

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        root_span = spans[0]
        self.assertEqual(root_span.attributes.get("rh.org_id"), "1979710")
        self.assertEqual(root_span.attributes.get("rh.request_id"), "test-req-123")
        self.assertEqual(root_span.attributes.get("rh.account"), "540155")


class TestRHAttributeSpanProcessor(SimpleTestCase):
    def setUp(self):
        super().setUp()
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.processor = telemetry.RHAttributeSpanProcessor()
        self.provider.add_span_processor(self.processor)
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("test-processor")
        thread_storage.set_value("org_id", None)
        thread_storage.set_value("request_id", None)
        thread_storage.set_value("request", None)

    def tearDown(self):
        super().tearDown()
        thread_storage.set_value("org_id", None)
        thread_storage.set_value("request_id", None)
        thread_storage.set_value("request", None)

    def test_rh_attribute_span_processor_service_name(self):
        """Verifies that rh.service is set on all spans."""
        with self.tracer.start_as_current_span("test_operation"):
            pass
        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes.get("rh.service"), "advisor")

    def test_rh_attribute_span_processor_baggage_propagation(self):
        """Verifies that rh.org_id and rh.request_id propagate from parent baggage."""
        ctx = baggage.set_baggage("rh.org_id", "12345")
        ctx = baggage.set_baggage("rh.request_id", "req-abc", context=ctx)

        with self.tracer.start_as_current_span("test_baggage", context=ctx):
            pass

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes.get("rh.org_id"), "12345")
        self.assertEqual(spans[0].attributes.get("rh.request_id"), "req-abc")

    def test_rh_attribute_span_processor_thread_storage_fallback(self):
        """Verifies fallback to thread_storage values when baggage is absent."""
        thread_storage.set_value("org_id", "98765")
        thread_storage.set_value("request_id", "req-xyz")

        with self.tracer.start_as_current_span("test_thread_storage"):
            pass

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes.get("rh.org_id"), "98765")
        self.assertEqual(spans[0].attributes.get("rh.request_id"), "req-xyz")

    def test_rh_attribute_span_processor_request_fallback(self):
        """Verifies fallback to request object in thread_storage."""
        mock_request = type("Request", (), {
            "org_id": "45678",
            "META": {"HTTP_X_RH_INSIGHTS_REQUEST_ID": "req-meta-999"}
        })()
        thread_storage.set_value("request", mock_request)

        with self.tracer.start_as_current_span("test_request_fallback"):
            pass

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes.get("rh.org_id"), "45678")
        self.assertEqual(spans[0].attributes.get("rh.request_id"), "req-meta-999")


class TestOTelLoggingCorrelation(SimpleTestCase):
    def setUp(self):
        super().setUp()
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("test-logging")
        self.log_filter = telemetry.OTelContextualFilter()

    def test_otel_contextual_filter_inside_active_span(self):
        """Verifies that OTelContextualFilter injects trace_id and span_id into log records inside active span."""
        import logging

        with self.tracer.start_as_current_span("test_span") as span:
            span_context = span.get_span_context()
            record = logging.LogRecord(
                name="test_logger",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Test message",
                args=(),
                exc_info=None,
            )
            self.assertTrue(self.log_filter.filter(record))
            self.assertEqual(record.trace_id, format(span_context.trace_id, "032x"))
            self.assertEqual(record.span_id, format(span_context.span_id, "016x"))

    def test_otel_contextual_filter_outside_active_span(self):
        """Verifies that OTelContextualFilter sets trace_id and span_id to None when outside any span."""
        import logging

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message outside span",
            args=(),
            exc_info=None,
        )
        self.assertTrue(self.log_filter.filter(record))
        self.assertIsNone(record.trace_id)
        self.assertIsNone(record.span_id)

    def test_our_formatter_json_serialization_with_trace_id(self):
        """Verifies that OurFormatter outputs valid JSON containing trace_id and span_id."""
        import logging
        import json
        from advisor_logging import OurFormatter

        formatter = OurFormatter(fmt=json.dumps({"extra": {"component": "insights-advisor-api"}}))
        with self.tracer.start_as_current_span("test_formatted_span") as span:
            span_context = span.get_span_context()
            record = logging.LogRecord(
                name="advisor-log",
                level=logging.INFO,
                pathname="test.py",
                lineno=20,
                msg="Formatted message with trace context",
                args=(),
                exc_info=None,
            )
            self.log_filter.filter(record)
            formatted_json = formatter.format(record)
            payload = json.loads(formatted_json)

            self.assertEqual(payload.get("trace_id"), format(span_context.trace_id, "032x"))
            self.assertEqual(payload.get("span_id"), format(span_context.span_id, "016x"))

    def test_advisor_stream_handler_filter_registration_not_duplicated(self):
        """Verifies that AdvisorStreamHandler leaves filter attachment to logging_conf.py without duplicate internal filters."""
        from advisor_logging import AdvisorStreamHandler

        handler = AdvisorStreamHandler()
        # Filters are configured in logging_conf.py, so handler.__init__ must not attach duplicate internal filters
        self.assertEqual(len(handler.filters), 0)


class TestOutboundAndDatabaseInstrumentation(SimpleTestCase):
    def test_outbound_request_hook_updates_span_name(self):
        """Verifies that _outbound_request_hook updates span name to 'METHOD /path'."""
        from telemetry import _outbound_request_hook
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("test-requests")

        with tracer.start_as_current_span("HTTP GET") as span:
            mock_request = type("Request", (), {
                "method": "GET",
                "url": "http://rbac.service.local:8080/api/rbac/v1/access/?limit=10",
                "path_url": "/api/rbac/v1/access/?limit=10"
            })()
            _outbound_request_hook(span, mock_request)

        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "GET /api/rbac/v1/access/")

    def test_psycopg2_instrumentation_importable(self):
        """Verifies that Psycopg2Instrumentor is importable and available."""
        try:
            from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
            instrumentor = Psycopg2Instrumentor()
            self.assertIsNotNone(instrumentor)
        except ImportError:
            self.skipTest("Psycopg2Instrumentor not installed yet")

    def test_requests_instrumentation_injects_traceparent(self):
        """Verifies that RequestsInstrumentor injects W3C traceparent into outbound requests."""
        try:
            import requests
            import responses
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            from opentelemetry.instrumentation.requests import RequestsInstrumentor
        except ImportError:
            self.skipTest("Requests instrumentor not installed yet")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        tracer = provider.get_tracer("test-requests-tracer")

        RequestsInstrumentor().instrument()

        try:
            with responses.RequestsMock() as rsps:
                rsps.add(responses.GET, "http://rbac.example.com/api/rbac/v1/access/", json={"status": "ok"}, status=200)

                with tracer.start_as_current_span("parent_client_span") as parent_span:
                    parent_trace_id = format(parent_span.get_span_context().trace_id, "032x")
                    resp = requests.get("http://rbac.example.com/api/rbac/v1/access/")
                    self.assertEqual(resp.status_code, 200)

                # Check headers sent in HTTP request
                self.assertEqual(len(rsps.calls), 1)
                sent_headers = rsps.calls[0].request.headers
                self.assertIn("traceparent", sent_headers)
                self.assertIn(parent_trace_id, sent_headers["traceparent"])
        finally:
            RequestsInstrumentor().uninstrument()


class TestDjangoAndGunicornInstrumentation(SimpleTestCase):
    def test_django_instrumentor_importable(self):
        """Verifies that DjangoInstrumentor is available and can be instantiated."""
        try:
            from opentelemetry.instrumentation.django import DjangoInstrumentor
            instrumentor = DjangoInstrumentor()
            self.assertIsNotNone(instrumentor)
        except ImportError:
            self.skipTest("DjangoInstrumentor not installed yet")

    def test_gunicorn_post_fork_and_child_exit_hooks(self):
        """Verifies that gunicorn post_fork and child_exit execute cleanly."""
        from unittest.mock import MagicMock, patch
        import gunicorn_conf

        server = MagicMock()
        worker = MagicMock()
        worker.pid = 12345

        with patch("feature_flags.Client.connect"), \
             patch("telemetry.init_telemetry") as mock_init_telemetry, \
             patch("telemetry.shutdown_telemetry") as mock_shutdown_telemetry, \
             patch("prometheus_client.multiprocess.mark_process_dead"):

            # Test post_fork
            gunicorn_conf.post_fork(server, worker)
            mock_init_telemetry.assert_called_once_with(service_name="insights-advisor-api", force_reinit=True)

            # Test child_exit
            gunicorn_conf.child_exit(server, worker)
            mock_shutdown_telemetry.assert_called_once()

    def test_wsgi_skips_init_when_gunicorn_imported(self):
        """Issue 01: under gunicorn (--preload) the master must NOT initialize
        telemetry at import time; post_fork does it per-worker."""
        import sys
        from unittest.mock import MagicMock, patch

        with patch.dict(sys.modules, {"gunicorn": MagicMock()}), \
             patch("django.core.wsgi.get_wsgi_application", return_value=MagicMock()), \
             patch("telemetry.init_telemetry") as mock_init_telemetry:
            import importlib
            import project_settings.wsgi as wsgi_mod
            mock_init_telemetry.reset_mock()
            importlib.reload(wsgi_mod)
            mock_init_telemetry.assert_not_called()

    def test_wsgi_initializes_telemetry_for_non_gunicorn(self):
        """Issue 01: for non-gunicorn runtimes (e.g. manage.py runserver),
        wsgi.py must initialize telemetry at import time."""
        import sys
        from unittest.mock import MagicMock, patch

        with patch.dict(sys.modules):
            sys.modules.pop("gunicorn", None)
            with patch("django.core.wsgi.get_wsgi_application", return_value=MagicMock()), \
                 patch("telemetry.init_telemetry") as mock_init_telemetry:
                import importlib
                import project_settings.wsgi as wsgi_mod
                mock_init_telemetry.reset_mock()
                importlib.reload(wsgi_mod)
                mock_init_telemetry.assert_called_once_with(service_name="insights-advisor-api")

    def test_tasks_service_initializes_and_shuts_down_telemetry(self):
        """Verifies that tasks_service command initializes telemetry on startup and flushes on exit."""
        from unittest.mock import patch, MagicMock
        from tasks.management.commands.tasks_service import Command

        cmd = Command()
        with patch("tasks.management.commands.tasks_service.KafkaDispatcher") as mock_dispatcher_cls, \
             patch("telemetry.init_telemetry") as mock_init, \
             patch("telemetry.shutdown_telemetry") as mock_shutdown:
            mock_dispatcher = MagicMock()
            mock_dispatcher_cls.return_value = mock_dispatcher
            cmd.handle()

            mock_init.assert_called_once_with(service_name="insights-advisor-tasks-service")
            mock_dispatcher.receive.assert_called_once()
            mock_shutdown.assert_called_once()

    def test_advisor_inventory_service_initializes_and_shuts_down_telemetry(self):
        """Verifies that advisor_inventory_service command initializes telemetry on startup and flushes on exit."""
        from unittest.mock import patch, MagicMock
        from api.management.commands.advisor_inventory_service import Command

        cmd = Command()
        with patch("api.management.commands.advisor_inventory_service.KafkaDispatcher") as mock_dispatcher_cls, \
             patch("api.management.commands.advisor_inventory_service.start_http_server"), \
             patch("telemetry.init_telemetry") as mock_init, \
             patch("telemetry.shutdown_telemetry") as mock_shutdown:
            mock_dispatcher = MagicMock()
            mock_dispatcher_cls.return_value = mock_dispatcher
            cmd.handle()

            mock_init.assert_called_once_with(service_name="insights-advisor-inventory-service")
            mock_dispatcher.receive.assert_called_once()
            mock_shutdown.assert_called_once()


class TestTelemetryPerformanceAndOptimization(SimpleTestCase):
    """
    Performance and optimization benchmark tests.
    Ensures zero-overhead when disabled and sub-millisecond execution when active.
    """

    def test_disabled_telemetry_zero_overhead_benchmark(self):
        """Verifies that when OTEL is disabled, helper functions execute in < 5 microseconds per call."""
        import time

        start = time.perf_counter()
        iterations = 10000

        for _ in range(iterations):
            _ = telemetry.string_to_bool("false")
            _ = telemetry.extract_kafka_headers_to_context(None)
            telemetry._outbound_request_hook(None, None)
            telemetry._django_response_hook(None, None, None)

        duration = time.perf_counter() - start
        avg_per_call = duration / (iterations * 4)
        self.assertLess(avg_per_call, 0.000005, f"Disabled operations too slow: {avg_per_call * 1e6:.2f}us/call")

    def test_span_processor_throughput_benchmark(self):
        """Verifies that RHAttributeSpanProcessor.on_start executes in < 15 microseconds per span."""
        import time

        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")

        processor = telemetry.RHAttributeSpanProcessor()
        mock_span = type("MockSpan", (), {
            "is_recording": lambda self: True,
            "set_attribute": lambda self, k, v: None,
        })()
        thread_storage.set_value("org_id", "12345")
        thread_storage.set_value("request_id", "req-xyz")

        iterations = 5000
        start = time.perf_counter()
        for _ in range(iterations):
            processor.on_start(mock_span, parent_context=None)
        duration = time.perf_counter() - start

        avg_per_call = duration / iterations
        self.assertLess(avg_per_call, 0.000015, f"Span processor on_start too slow: {avg_per_call * 1e6:.2f}us/call")

    def test_kafka_header_extraction_throughput_benchmark(self):
        """Verifies that extract_kafka_headers_to_context parses 5,000 header sets in < 25 microseconds per message."""
        import time

        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")

        sample_headers = [
            ("traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            ("tracestate", b"congo=t61rcWkgMzE"),
            ("custom_header", b"some-custom-value"),
        ]

        iterations = 5000
        start = time.perf_counter()
        for _ in range(iterations):
            _ = telemetry.extract_kafka_headers_to_context(sample_headers)
        duration = time.perf_counter() - start

        avg_per_call = duration / iterations
        self.assertLess(avg_per_call, 0.000025, f"Header extraction too slow: {avg_per_call * 1e6:.2f}us/call")

    def test_log_filter_throughput_benchmark(self):
        """Verifies that OTelContextualFilter handles over 10,000 log records with < 10 microseconds overhead per record."""
        import logging
        import time

        log_filter = telemetry.OTelContextualFilter()
        record = logging.LogRecord(
            name="advisor-test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Benchmark log message",
            args=(),
            exc_info=None,
        )

        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            log_filter.filter(record)
        duration = time.perf_counter() - start

        avg_per_call = duration / iterations
        self.assertLess(avg_per_call, 0.000010, f"Logging filter too slow: {avg_per_call * 1e6:.2f}us/record")

    def test_kafka_batch_dispatch_linear_scaling_benchmark(self):
        """Verifies that _handle_batch_messages scales linearly O(N) across message counts 10 -> 100."""
        import time
        from kafka_utils import KafkaDispatcher, DummyConsumer, DummyMessage

        dispatcher = KafkaDispatcher(DummyConsumer())
        dispatcher.register_handler("test_batch", lambda t, b: None, batch=True)

        def make_messages(count):
            return [
                DummyMessage("test_batch", f'{{"id": {i}}}'.encode(), headers=[("traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")])
                for i in range(count)
            ]

        batch_10 = make_messages(10)
        batch_100 = make_messages(100)

        # Measure 10 items
        start_10 = time.perf_counter()
        for _ in range(100):
            dispatcher._handle_batch_messages(batch_10)
        time_10 = time.perf_counter() - start_10

        # Measure 100 items
        start_100 = time.perf_counter()
        for _ in range(100):
            dispatcher._handle_batch_messages(batch_100)
        time_100 = time.perf_counter() - start_100

        # Ratio of 100 items to 10 items should be approximately linear (~10x, definitely < 25x)
        scaling_ratio = time_100 / max(time_10, 1e-6)
        self.assertLess(scaling_ratio, 25.0, f"Non-linear scaling detected: {scaling_ratio:.2f}x for 10x data")


class TestKafkaConsumerSpanContextManagers(SimpleTestCase):
    """
    Direct unit tests for the kafka_consumer_span and kafka_batch_consumer_span
    context managers introduced in telemetry.py (Issue 03 & 04).
    """

    def setUp(self):
        super().setUp()
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))

    def test_kafka_consumer_span_when_disabled(self):
        """Verifies that when telemetry is uninitialized, kafka_consumer_span yields None and executes body."""
        telemetry._IS_INITIALIZED = False
        executed = False
        with telemetry.kafka_consumer_span("test.topic", None) as span:
            executed = True
            self.assertIsNone(span)
        self.assertTrue(executed)

    def test_kafka_consumer_span_when_enabled(self):
        """Verifies that kafka_consumer_span creates a CONSUMER span with messaging attributes and parent context."""
        from unittest.mock import patch
        from opentelemetry.trace import SpanKind

        trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        span_id = "00f067aa0ba902b7"
        headers = [("traceparent", f"00-{trace_id}-{span_id}-01".encode())]

        tracer = self.provider.get_tracer("advisor-service")
        with patch("telemetry.get_tracer", return_value=tracer):
            with telemetry.kafka_consumer_span("platform.engine.results", headers) as span:
                self.assertIsNotNone(span)

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.name, "platform.engine.results process")
        self.assertEqual(span.kind, SpanKind.CONSUMER)
        self.assertEqual(span.attributes.get("messaging.system"), "kafka")
        self.assertEqual(span.attributes.get("messaging.destination.name"), "platform.engine.results")
        self.assertEqual(span.attributes.get("messaging.operation"), "process")
        self.assertEqual(format(span.context.trace_id, "032x"), trace_id)
        self.assertEqual(format(span.parent.span_id, "016x"), span_id)

    def test_kafka_batch_consumer_span_when_disabled(self):
        """Verifies that when telemetry is uninitialized, kafka_batch_consumer_span yields None and executes body."""
        telemetry._IS_INITIALIZED = False
        executed = False
        with telemetry.kafka_batch_consumer_span("test.batch.topic", None, message_count=5) as span:
            executed = True
            self.assertIsNone(span)
        self.assertTrue(executed)

    def test_kafka_batch_consumer_span_when_enabled(self):
        """Verifies that kafka_batch_consumer_span creates a batch span with trace links and message count."""
        from unittest.mock import patch
        from opentelemetry.trace import SpanKind

        trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        span_id = "00f067aa0ba902b7"
        headers_list = [[("traceparent", f"00-{trace_id}-{span_id}-01".encode())], []]

        tracer = self.provider.get_tracer("advisor-kafka")
        with patch("telemetry.get_tracer", return_value=tracer):
            with telemetry.kafka_batch_consumer_span("platform.inventory.events", headers_list=headers_list, message_count=2) as span:
                self.assertIsNotNone(span)

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.name, "platform.inventory.events batch process")
        self.assertEqual(span.kind, SpanKind.CONSUMER)
        self.assertEqual(span.attributes.get("messaging.system"), "kafka")
        self.assertEqual(span.attributes.get("messaging.destination.name"), "platform.inventory.events")
        self.assertEqual(span.attributes.get("messaging.batch.message_count"), 2)
        self.assertEqual(len(span.links), 1)
        self.assertEqual(format(span.links[0].context.trace_id, "032x"), trace_id)
        self.assertEqual(format(span.links[0].context.span_id, "016x"), span_id)

    def test_kafka_batch_consumer_span_fault_tolerance_with_corrupt_header(self):
        """
        Verifies that if one message in a batch has a corrupted/failing header,
        the error is caught and skipped, the batch span is still created, and valid links are preserved.
        """
        from unittest.mock import patch
        from opentelemetry.trace import SpanKind

        trace_id_1 = "4bf92f3577b34da6a3ce929d0e0e4736"
        trace_id_3 = "6cf92f3577b34da6a3ce929d0e0e4799"

        # 1 valid header, 1 malformed header, 1 valid header
        headers_list = [
            [("traceparent", f"00-{trace_id_1}-00f067aa0ba902b7-01".encode())],
            [("traceparent", b"INVALID_CORRUPT_BYTES_\xff\xfe_NON_W3C_DATA")],
            [("traceparent", f"00-{trace_id_3}-00f067aa0ba902c8-01".encode())],
        ]

        tracer = self.provider.get_tracer("advisor-kafka")
        with patch("telemetry.get_tracer", return_value=tracer):
            with telemetry.kafka_batch_consumer_span("platform.inventory.events", headers_list=headers_list, message_count=3) as span:
                self.assertIsNotNone(span)

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        batch_span = spans[0]

        # 1. Batch span was created successfully despite the corrupted second message
        self.assertEqual(batch_span.name, "platform.inventory.events batch process")
        self.assertEqual(batch_span.kind, SpanKind.CONSUMER)
        self.assertEqual(batch_span.attributes.get("messaging.batch.message_count"), 3)

        # 2. Links list contains exactly the 2 valid traces (corrupted message was safely skipped)
        self.assertEqual(len(batch_span.links), 2)
        linked_traces = {format(link.context.trace_id, "032x") for link in batch_span.links}
        self.assertEqual(linked_traces, {trace_id_1, trace_id_3})

    def test_enrich_span_from_thread_storage_helper(self):
        """Verifies _enrich_span_from_thread_storage sets org_id and request_id and handles edge cases."""
        thread_storage.set_value("org_id", "112233")
        thread_storage.set_value("request_id", "req-enrich-test")

        mock_span = type("MockSpan", (), {
            "attributes": {},
            "is_recording": lambda self: True,
            "set_attribute": lambda self, k, v: self.attributes.update({k: v}),
        })()

        telemetry._enrich_span_from_thread_storage(mock_span)
        self.assertEqual(mock_span.attributes.get("rh.org_id"), "112233")
        self.assertEqual(mock_span.attributes.get("rh.request_id"), "req-enrich-test")

        # Edge cases: None span or non-recording span must not raise
        telemetry._enrich_span_from_thread_storage(None)
        non_recording = type("NonRecSpan", (), {"is_recording": lambda self: False})()
        telemetry._enrich_span_from_thread_storage(non_recording)

        thread_storage.set_value("org_id", None)
        thread_storage.set_value("request_id", None)

    def test_kafka_consumer_span_enriches_from_thread_storage_after_execution(self):
        """Verifies kafka_consumer_span enriches the outer span with thread_storage set during handler execution."""
        from unittest.mock import patch

        tracer = self.provider.get_tracer("advisor-service")
        with patch("telemetry.get_tracer", return_value=tracer):
            with telemetry.kafka_consumer_span("platform.engine.results", None) as span:
                self.assertIsNotNone(span)
                # Mid-handler execution populates thread_storage
                thread_storage.set_value("org_id", "998877")
                thread_storage.set_value("request_id", "req-mid-handler-01")

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        finished_span = spans[0]
        self.assertEqual(finished_span.attributes.get("rh.org_id"), "998877")
        self.assertEqual(finished_span.attributes.get("rh.request_id"), "req-mid-handler-01")

        thread_storage.set_value("org_id", None)
        thread_storage.set_value("request_id", None)

    def test_kafka_batch_consumer_span_enriches_from_thread_storage_after_execution(self):
        """Verifies kafka_batch_consumer_span enriches the outer span with thread_storage set during handler execution."""
        from unittest.mock import patch

        tracer = self.provider.get_tracer("advisor-kafka")
        with patch("telemetry.get_tracer", return_value=tracer):
            with telemetry.kafka_batch_consumer_span("platform.inventory.events", None, message_count=1) as span:
                self.assertIsNotNone(span)
                thread_storage.set_value("org_id", "445566")
                thread_storage.set_value("request_id", "req-batch-handler-02")

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        finished_span = spans[0]
        self.assertEqual(finished_span.attributes.get("rh.org_id"), "445566")
        self.assertEqual(finished_span.attributes.get("rh.request_id"), "req-batch-handler-02")

        thread_storage.set_value("org_id", None)
        thread_storage.set_value("request_id", None)

    def test_kafka_consumer_span_enriches_even_on_exception(self):
        """Verifies that if an exception occurs mid-handler, finally block still enriches the span."""
        from unittest.mock import patch

        tracer = self.provider.get_tracer("advisor-service")
        with patch("telemetry.get_tracer", return_value=tracer):
            with self.assertRaises(ValueError):
                with telemetry.kafka_consumer_span("platform.engine.results", None) as span:
                    self.assertIsNotNone(span)
                    thread_storage.set_value("org_id", "777888")
                    thread_storage.set_value("request_id", "req-error-handler-03")
                    raise ValueError("Simulated handler failure")

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        finished_span = spans[0]
        self.assertEqual(finished_span.attributes.get("rh.org_id"), "777888")
        self.assertEqual(finished_span.attributes.get("rh.request_id"), "req-error-handler-03")

        thread_storage.set_value("org_id", None)
        thread_storage.set_value("request_id", None)


class TestReviewCommentsIssues(SimpleTestCase):
    """
    Test suite reproducing the four review comment findings.
    """

    def test_comment1_init_telemetry_sets_provider_once_per_process(self):
        """
        Comment 1 (Issue 01): init_telemetry sets the TracerProvider exactly once
        per process without the _TRACER_PROVIDER_SET_ONCE hack. Under gunicorn (--preload),
        the master skips init (wsgi.py guard) and workers initialize once in post_fork.
        """
        if not OTEL_AVAILABLE:
            self.skipTest("OpenTelemetry packages not installed yet")
        from opentelemetry import trace
        os.environ["OTEL_ENABLED"] = "true"

        telemetry.init_telemetry(service_name="first-service", force_reinit=True)
        first_provider = trace.get_tracer_provider()

        telemetry.init_telemetry(service_name="second-service", force_reinit=True)
        second_provider = trace.get_tracer_provider()

        # Same-process re-init does NOT replace the provider (hack removed)
        self.assertIs(first_provider, second_provider)

    def test_comment2_shutdown_telemetry_invokes_provider_methods(self):
        """
        Comment 2: Verifies that telemetry.shutdown_telemetry() directly calls
        force_flush and shutdown on the active TracerProvider.
        """
        from unittest.mock import MagicMock, patch

        mock_provider = MagicMock()
        with patch("opentelemetry.trace.get_tracer_provider", return_value=mock_provider):
            telemetry._IS_INITIALIZED = True
            telemetry.shutdown_telemetry(timeout_millis=5000)

            mock_provider.force_flush.assert_called_once_with(timeout_millis=5000)
            mock_provider.shutdown.assert_called_once()

    def test_comment3_shutdown_telemetry_resets_initialized_state(self):
        """
        Comment 3: Verifies that shutdown_telemetry() resets _IS_INITIALIZED to False
        and _INITIALIZED_PID to None so subsequent initializations are not blocked.
        """
        from unittest.mock import MagicMock, patch

        with patch("opentelemetry.trace.get_tracer_provider", return_value=MagicMock()):
            telemetry._IS_INITIALIZED = True
            telemetry._INITIALIZED_PID = os.getpid()

            telemetry.shutdown_telemetry()

            # Must reset state
            self.assertFalse(telemetry._IS_INITIALIZED)
            self.assertIsNone(telemetry._INITIALIZED_PID)

    def test_comment4_get_tracer_returns_none_when_uninitialized(self):
        """
        Comment 4: Verifies that get_tracer() returns None when telemetry is disabled/uninitialized,
        preventing dormant no-op tracing overhead in message handlers.
        """
        telemetry._IS_INITIALIZED = False
        tracer = telemetry.get_tracer("advisor-kafka")

        # Must return None so callers like kafka_utils skip tracing overhead entirely
        self.assertIsNone(tracer)
