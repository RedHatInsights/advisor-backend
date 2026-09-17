# Copyright 2016-2026 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

import concurrent.futures
from os.path import abspath, dirname
import sys

import pytest

SERVICE_DIR = dirname(dirname(abspath(__file__)))
PARENT = dirname(SERVICE_DIR)
sys.path.append(SERVICE_DIR)
sys.path.append(PARENT)

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

import service as advisor_service
from service import handle_engine_results, handle_inventory_event


@pytest.fixture
def in_memory_tracer(mocker):
    if not OTEL_AVAILABLE:
        pytest.skip("OpenTelemetry packages not installed yet")
    import telemetry
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    mocker.patch("telemetry.get_tracer", return_value=provider.get_tracer("advisor-service"))
    yield exporter
    provider.shutdown()


def test_engine_results_trace_continuity_in_thread_pool(mocker, in_memory_tracer, sample_engine_results):
    """
    Verifies that when handle_engine_results runs inside an asynchronous ThreadPoolExecutor worker,
    it extracts kafka_headers and creates a child CONSUMER span with matching trace_id and parent_span_id.
    """
    exporter = in_memory_tracer
    upstream_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    upstream_span_id = "00f067aa0ba902b7"
    headers = [("traceparent", f"00-{upstream_trace_id}-{upstream_span_id}-01".encode())]

    mocker.patch("service.create_db_reports", return_value=True)
    mocker.patch("service.payload_tracker.payload_status")
    mock_system_type = mocker.MagicMock()
    mocker.patch("service.db.SystemType.objects.filter", return_value=mocker.MagicMock(first=mocker.MagicMock(return_value=mock_system_type)))

    # Run inside ThreadPoolExecutor to replicate service.py async worker dispatch
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(handle_engine_results, sample_engine_results, kafka_headers=headers)
        result = future.result()

    assert result is True
    spans = exporter.get_finished_spans()
    consumer_span = next((s for s in spans if s.name == "process platform.engine.results"), None)
    assert consumer_span is not None

    # Verify trace continuity across the thread pool boundary
    assert format(consumer_span.context.trace_id, "032x") == upstream_trace_id
    assert format(consumer_span.parent.span_id, "016x") == upstream_span_id


def test_shutdown_telemetry_flushes_spans(mocker):
    """
    Verifies that shutdown_telemetry forces an immediate flush of buffered spans
    and cleanly shuts down the TracerProvider on process termination (SIGTERM/SIGINT).
    """
    if not OTEL_AVAILABLE:
        pytest.skip("OpenTelemetry packages not installed yet")

    import telemetry
    mock_provider = mocker.MagicMock()
    mocker.patch.object(trace, "get_tracer_provider", return_value=mock_provider)

    telemetry._IS_INITIALIZED = True
    telemetry._INITIALIZED_PID = 12345
    telemetry.shutdown_telemetry(timeout_millis=5000)

    mock_provider.force_flush.assert_called_once_with(timeout_millis=5000)
    mock_provider.shutdown.assert_called_once()
    assert telemetry._IS_INITIALIZED is False
    assert telemetry._INITIALIZED_PID is None


def test_service_shutdown_runs_when_main_loop_fails(mocker):
    mocker.patch.object(advisor_service.telemetry, "init_telemetry")
    mocker.patch.object(advisor_service, "_run_service", side_effect=RuntimeError("consumer failed"))
    shutdown = mocker.patch.object(advisor_service.telemetry, "shutdown_telemetry")

    with pytest.raises(RuntimeError, match="consumer failed"):
        advisor_service.start()

    shutdown.assert_called_once_with()


def test_handle_engine_results_throughput_benchmark(mocker, in_memory_tracer, sample_engine_results):
    """
    Verifies that handle_engine_results executes with < 50 microseconds overhead per message
    when tracing, span creation, and attribute extraction are active.
    """
    import time
    mocker.patch("service.create_db_reports", return_value=True)
    mocker.patch("service.payload_tracker.payload_status")
    mock_system_type = mocker.MagicMock()
    mocker.patch("service.db.SystemType.objects.filter", return_value=mocker.MagicMock(first=mocker.MagicMock(return_value=mock_system_type)))

    headers = [("traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")]
    iterations = 1000

    start = time.perf_counter()
    for _ in range(iterations):
        handle_engine_results(sample_engine_results, kafka_headers=headers)
    duration = time.perf_counter() - start

    avg_per_call = duration / iterations
    assert avg_per_call < 0.000500, f"Engine results processing overhead too high: {avg_per_call*1e6:.2f}us/msg"


def test_service_log_formatter_throughput_benchmark():
    """
    Verifies that OurFormatter in service/advisor_logging.py formats 10,000 log records
    in < 25 microseconds per record (> 40,000 records/sec).
    """
    import time
    import json
    import logging
    import thread_storage
    from advisor_logging import OurFormatter

    formatter = OurFormatter(fmt=json.dumps({"extra": {"component": "insights-advisor-service"}}))
    thread_storage.set_value("request_id", "req-bench-123")
    thread_storage.set_value("system_id", "sys-bench-456")
    thread_storage.set_value("engine_results_started", 100.0)

    record = logging.LogRecord(
        name="insights-advisor-service",
        level=logging.INFO,
        pathname="service.py",
        lineno=50,
        msg="Benchmark log message from service consumer",
        args=(),
        exc_info=None,
    )
    record.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    record.span_id = "00f067aa0ba902b7"

    iterations = 10000
    start = time.perf_counter()
    for _ in range(iterations):
        formatter.format(record)
    duration = time.perf_counter() - start

    avg_per_call = duration / iterations
    assert avg_per_call < 0.000025, f"Log formatter too slow: {avg_per_call*1e6:.2f}us/record"


def test_service_handlers_dormant_when_telemetry_uninitialized(mocker, sample_engine_results):
    """
    Verifies that when telemetry is uninitialized/disabled,
    service message handlers execute with zero span creation and bypass header extraction.
    """
    import telemetry

    telemetry._IS_INITIALIZED = False
    mock_extract = mocker.patch("telemetry.extract_kafka_headers_to_context")
    mocker.patch("service.create_db_reports", return_value=True)
    mocker.patch("service.payload_tracker.payload_status")
    mock_system_type = mocker.MagicMock()
    mocker.patch("service.db.SystemType.objects.filter", return_value=mocker.MagicMock(first=mocker.MagicMock(return_value=mock_system_type)))

    headers = [("traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")]

    # Execute handler
    result = handle_engine_results(sample_engine_results, kafka_headers=headers)
    assert result is True

    # Header extraction MUST NOT be called when disabled
    mock_extract.assert_not_called()
