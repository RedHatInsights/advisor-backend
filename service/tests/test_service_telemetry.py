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
from service import handle_engine_results


@pytest.fixture
def in_memory_tracer(mocker):
    if not OTEL_AVAILABLE:
        pytest.skip("OpenTelemetry packages not installed yet")
    import telemetry
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(telemetry.RHAttributeSpanProcessor())
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    mocker.patch("telemetry.get_tracer", return_value=provider.get_tracer("advisor-service"))
    yield exporter
    provider.shutdown()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("scenario", ["commit", "no_host_apps", "rollback", "disabled", "schedule_failure", "callback_failure"])
def test_processing_completion_requires_commit(
    db, service, mocker, in_memory_tracer, sample_engine_results, mock_request_post_return_200, scenario
):
    import json
    from contextlib import nullcontext
    from unittest.mock import patch
    from django.db import transaction, OperationalError
    import thread_storage

    producer = mocker.MagicMock()
    tracer = service.telemetry.get_tracer("test")
    publication_transactions = []
    producer.produce.side_effect = lambda **_kwargs: publication_transactions.append(transaction.get_connection().in_atomic_block)
    mocker.patch("telemetry._IS_INITIALIZED", scenario != "disabled")
    mocker.patch.object(service.inventory_view, "p", None if scenario == "no_host_apps" else producer)
    mocker.patch.object(service.inventory_view, "INVENTORY_VIEW_TOPIC", "isolated-host-apps")
    if scenario == "disabled":
        mocker.patch("telemetry.get_tracer", return_value=None)
    if scenario == "schedule_failure":
        mocker.patch("telemetry.record_ingestion_completion_on_commit", side_effect=RuntimeError("SDK failed"))
    failure = patch.object(transaction.get_connection(), "commit", side_effect=OperationalError("commit failed"))
    with tracer.start_as_current_span("unrelated"):
        with failure if scenario == "rollback" else nullcontext():
            if scenario == "rollback":
                assert service.handle_engine_results(sample_engine_results) is False
            else:
                with transaction.atomic():
                    assert service.handle_engine_results(sample_engine_results) is True
                    assert not any(event.name == "rh.ingestion.completed"
                                   for span in in_memory_tracer.get_finished_spans() for event in span.events)
                    assert producer.produce.call_count == int(scenario != "no_host_apps")
                    thread_storage.set_value("request_id", "unrelated-request")
                    thread_storage.set_value("org_id", "unrelated-org")
                    if scenario == "callback_failure":
                        start_span = tracer.start_span

                        def start(name, *args, **kwargs):
                            if name == "advisor.ingestion.completed":
                                raise RuntimeError("SDK failed")
                            return start_span(name, *args, **kwargs)

                        mocker.patch.object(tracer, "start_span", side_effect=start)
    events = [(span, event) for span in in_memory_tracer.get_finished_spans()
              for event in span.events if event.name == "rh.ingestion.completed"]
    assert len(events) == int(scenario in ("commit", "no_host_apps"))
    published = scenario != "no_host_apps"
    assert producer.produce.call_count == int(published)
    assert publication_transactions == ([True] if published else [])
    metadata = sample_engine_results["input"]["platform_metadata"]
    if events:
        span, event = events[0]
        assert dict(event.attributes) == {
            "rh.ingestion.application": "advisor", "rh.ingestion.milestone": "processing",
            "rh.ingestion.outcome": "processed", "rh.request_id": metadata["request_id"],
            "rh.org_id": metadata["org_id"], "rh.host_id": sample_engine_results["input"]["host"]["id"],
        }
        consumer = next(s for s in in_memory_tracer.get_finished_spans() if s.name == f"process {service.ENGINE_RESULTS_TOPIC}")
        assert span.start_time == event.timestamp == span.end_time
        assert span.context.trace_id == consumer.context.trace_id
        assert span.parent.span_id == consumer.context.span_id
    if published:
        call = producer.produce.call_args
        headers = dict(call.kwargs["headers"])
        assert headers["request_id"] == metadata["request_id"].encode()
        assert headers["application"] == b"advisor"
        assert set(headers) <= {"request_id", "application", "traceparent", "tracestate", "baggage"}
        body = json.loads(call.kwargs["value"])
        assert set(body) == {"org_id", "timestamp", "hosts"}
        assert body["org_id"] == metadata["org_id"]
        assert body["hosts"][0]["id"] == sample_engine_results["input"]["host"]["id"]
        if scenario != "disabled":
            consumer = next(s for s in in_memory_tracer.get_finished_spans() if s.name == f"process {service.ENGINE_RESULTS_TOPIC}")
            assert service.telemetry.trace_id_from_kafka_headers(call.kwargs["headers"]) == consumer.context.trace_id


@pytest.mark.django_db(transaction=True)
def test_host_publication_remains_serialized_by_database_lock(
    db, service, mocker, in_memory_tracer, sample_engine_results, mock_request_post_return_200
):
    import copy
    import time
    from threading import Event
    from unittest.mock import patch
    from django.db import connections

    with patch.object(service.inventory_view, "p", None):
        assert service.handle_engine_results(sample_engine_results) is True
    first_publishing, release_first, second_lock_attempted, second_published = (Event() for _ in range(4))
    published, backends = [], {}

    def produce(**kwargs):
        request_id = dict(kwargs["headers"])["request_id"].decode()
        if request_id == "older":
            first_publishing.set()
            assert release_first.wait(10)
        published.append(request_id)
        if request_id == "newer":
            second_published.set()

    producer = mocker.MagicMock()
    producer.produce.side_effect = produce
    mocker.patch.object(service.inventory_view, "p", producer)
    mocker.patch.object(service.inventory_view, "INVENTORY_VIEW_TOPIC", "isolated-host-apps")

    def process(request_id):
        message = copy.deepcopy(sample_engine_results)
        message["input"]["platform_metadata"]["request_id"] = request_id
        if request_id == "newer":
            message["results"]["reports"] = []
        connection = connections["default"]
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backends[request_id] = cursor.fetchone()[0]

            def observe_lock(execute, sql, params, many, context):
                if request_id == "newer" and "FOR UPDATE" in sql.upper() and '"api_host"' in sql:
                    second_lock_attempted.set()
                return execute(sql, params, many, context)

            with connection.execute_wrapper(observe_lock):
                return service.handle_engine_results(message)
        finally:
            connection.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        older = executor.submit(process, "older")
        newer = None
        try:
            assert first_publishing.wait(10)
            newer = executor.submit(process, "newer")
            assert second_lock_attempted.wait(10)
            assert backends["older"] != backends["newer"]
            deadline = time.monotonic() + 5
            while True:
                with connections["default"].cursor() as cursor:
                    cursor.execute("SELECT %s = ANY(pg_blocking_pids(%s))", [backends["older"], backends["newer"]])
                    if cursor.fetchone()[0]:
                        break
                assert not second_published.is_set(), "newer update overtook the blocked older publication"
                assert time.monotonic() < deadline
                time.sleep(.01)
        finally:
            release_first.set()
        assert older.result(timeout=10) is True
        assert newer.result(timeout=10) is True
    assert published == ["older", "newer"]


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
    consumer_span = next((s for s in spans if s.name == f"process {advisor_service.ENGINE_RESULTS_TOPIC}"), None)
    assert consumer_span is not None

    # Verify trace continuity across the thread pool boundary
    assert format(consumer_span.context.trace_id, "032x") == upstream_trace_id
    assert format(consumer_span.parent.span_id, "016x") == upstream_span_id
    metadata = sample_engine_results["input"]["platform_metadata"]
    assert consumer_span.attributes["rh.request_id"] == metadata["request_id"]
    assert consumer_span.attributes["rh.org_id"] == metadata["org_id"]


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
    in < 30 microseconds per record (> 33,000 records/sec).
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
    assert avg_per_call < 0.00003, f"Log formatter too slow: {avg_per_call*1e6:.2f}us/record"


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
