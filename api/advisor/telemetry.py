# Copyright 2016-2026 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

"""
Centralized OpenTelemetry configuration and instrumentation module for Insights Advisor.
"""

import os
import logging
from contextlib import contextmanager
from typing import Optional
from urllib.parse import urlparse

import thread_storage
from project_settings.settings import string_to_bool

logger = logging.getLogger("advisor-telemetry")

_INITIALIZED_PID: Optional[int] = None
_IS_INITIALIZED = False


try:
    from opentelemetry import trace, baggage, propagate
    from opentelemetry.sdk.trace import SpanProcessor, ReadableSpan
    from opentelemetry.trace import SpanKind
    OTEL_AVAILABLE = True

    class RHAttributeSpanProcessor(SpanProcessor):
        """
        SpanProcessor following HBI / Puptoo pattern:
        - Sets 'rh.service' = 'advisor' on all spans.
        - Propagates 'rh.org_id' and 'rh.request_id' onto child spans,
          falling back to thread_storage context (and Django request META).
        """

        def __init__(self):
            pass

        def on_start(self, span, parent_context: Optional[trace.Context] = None) -> None:
            if not span.is_recording():
                return

            # 1. Set Red Hat standard service identifier
            span.set_attribute("rh.service", "advisor")

            # 2. Extract org_id and request_id with precedence: Baggage -> thread_storage -> Request META
            org_id = None
            request_id = None

            if parent_context is not None:
                org_id = baggage.get_baggage("rh.org_id", parent_context)
                request_id = baggage.get_baggage("rh.request_id", parent_context)

            if not org_id:
                org_id = thread_storage.get_value("org_id")
            if not request_id:
                request_id = thread_storage.get_value("request_id")

            # Fallback to Django request object stored in thread_storage (API flow)
            if not (org_id and request_id):
                req = thread_storage.get_value("request")
                if req:
                    if not request_id and hasattr(req, "META"):
                        request_id = req.META.get("HTTP_X_RH_INSIGHTS_REQUEST_ID")
                    if not org_id:
                        org_id = getattr(req, "org_id", None)

            if org_id:
                span.set_attribute("rh.org_id", str(org_id))
            if request_id:
                span.set_attribute("rh.request_id", str(request_id))

        def on_end(self, span: ReadableSpan) -> None:
            pass

        def shutdown(self) -> None:
            pass

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    class FilteringSpanProcessor(SpanProcessor):
        """Forwards spans to a wrapped processor only when predicate returns True."""

        def __init__(self, wrapped: SpanProcessor, predicate=None):
            self._wrapped = wrapped
            self._predicate = predicate or _should_export_span

        def on_start(self, span, parent_context: Optional[trace.Context] = None) -> None:
            self._wrapped.on_start(span, parent_context)

        def on_end(self, span: ReadableSpan) -> None:
            try:
                if not self._predicate(span):
                    return
            except Exception:
                logger.debug("Span export predicate failed; exporting span anyway", exc_info=True)
            self._wrapped.on_end(span)

        def shutdown(self) -> None:
            self._wrapped.shutdown()

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return self._wrapped.force_flush(timeout_millis)

except ImportError:
    OTEL_AVAILABLE = False

    class RHAttributeSpanProcessor:  # type: ignore[no-redef]
        def __init__(self):
            pass

    class FilteringSpanProcessor:  # type: ignore[no-redef]
        def __init__(self, wrapped, predicate=None):
            pass


class OTelContextualFilter(logging.Filter):
    """
    Logging filter that injects hex-encoded trace_id and span_id into log records.
    Safely emits None when outside an active span.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            span = trace.get_current_span()
            span_context = span.get_span_context() if span else None

            if span_context and span_context.is_valid:
                record.trace_id = format(span_context.trace_id, "032x")
                record.span_id = format(span_context.span_id, "016x")
            else:
                record.trace_id = None
                record.span_id = None
        except Exception:
            record.trace_id = None
            record.span_id = None
        return True


def _outbound_request_hook(span, request, *_args, **_kwargs):
    """Standardizes outbound HTTP span names to 'METHOD /path'."""
    if not span or not span.is_recording():
        return
    parsed = urlparse(request.url if hasattr(request, 'url') else request.path_url)
    path = parsed.path or "/"
    span.update_name(f"{request.method} {path}")


def _django_response_hook(span, request, response):
    """
    Executes after view processing to enrich the root SERVER span with
    rh.org_id, rh.request_id, and rh.account once DRF authentication has resolved.
    """
    if not span or not span.is_recording():
        return
    org_id = getattr(request, "org_id", None)
    if org_id:
        span.set_attribute("rh.org_id", str(org_id))
    request_id = request.META.get("HTTP_X_RH_INSIGHTS_REQUEST_ID") if hasattr(request, "META") else None
    if request_id:
        span.set_attribute("rh.request_id", str(request_id))
    account = getattr(request, "account", None)
    if account:
        span.set_attribute("rh.account", str(account))


def _reload_django_wsgi_middleware():
    """
    DjangoInstrumentor only inserts its middleware into settings.MIDDLEWARE.

    Under gunicorn --preload, get_wsgi_application() already ran in the master
    process, so the live WSGIHandler middleware chain is frozen *without* the
    OTel SERVER span.

    Reload the already-constructed handler from settings. Use sys.modules so
    this is a no-op while wsgi.py is still importing (application not bound yet);
    that path calls get_wsgi_application() afterwards and picks up the middleware
    naturally.
    """
    try:
        import sys

        wsgi_mod = sys.modules.get("project_settings.wsgi")
        if wsgi_mod is None:
            return
        app = getattr(wsgi_mod, "application", None)
        if app is not None and hasattr(app, "load_middleware"):
            app.load_middleware()
            logger.info("Reloaded Django WSGI middleware after OpenTelemetry instrumentation")
    except Exception as e:
        logger.warning("Failed to reload Django WSGI middleware after OTel instrumentation: %s", e)


def _normalize_db_statement(statement: Optional[str]) -> str:
    if not statement:
        return ""
    return " ".join(str(statement).strip().rstrip(";").lower().split())


def _is_db_probe_span(span) -> bool:
    """True for connection pings such as Django's `SELECT 1;` health check."""
    attrs = getattr(span, "attributes", None) or {}
    statement = attrs.get("db.statement") or attrs.get("db.query.text") or ""
    return _normalize_db_statement(statement) == "select 1"


def _should_export_span(span) -> bool:
    """
    Drop liveness/readiness DB pings and unparented SQL."""
    if _is_db_probe_span(span):
        return False
    if not OTEL_AVAILABLE:
        return True
    attrs = getattr(span, "attributes", None) or {}
    is_db = any(key in attrs for key in ("db.system", "db.statement", "db.query.text"))
    parent = getattr(span, "parent", None)
    kind = getattr(span, "kind", None)
    if is_db and parent is None and kind == SpanKind.CLIENT:
        return False
    return True


def init_telemetry(
    service_name: str = "advisor",
    excluded_urls: str = "metrics,healthz,health,status",
    force_reinit: bool = False,
) -> None:
    """
    Initialize OpenTelemetry tracer provider, sampler, processors, and auto-instrumentations.
    Fork-safe: re-initializes TracerProvider and BatchSpanProcessor if running in a forked child process.
    """
    global _IS_INITIALIZED, _INITIALIZED_PID
    current_pid = os.getpid()

    # OpenTelemetry's global provider cannot be replaced in-process. A changed
    # PID is sufficient to detect the fork; retain force_reinit for caller
    # compatibility, but never leak a second provider in the same process.
    if _IS_INITIALIZED and _INITIALIZED_PID == current_pid:
        if force_reinit:
            logger.debug("Ignoring same-process OpenTelemetry reinitialization request")
        return

    otel_enabled = string_to_bool(os.getenv("OTEL_ENABLED", "false"))
    if not otel_enabled:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider, SpanLimits
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
        from opentelemetry.exporter.otlp.proto.http import Compression
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    except ImportError as e:
        logger.warning("OpenTelemetry packages not installed, skipping initialization: %s", e)
        return

    if _INITIALIZED_PID is not None and _INITIALIZED_PID != current_pid:
        logger.info(
            "Process fork detected (Parent PID %s -> Child PID %s). Reinitializing OpenTelemetry...",
            _INITIALIZED_PID,
            current_pid,
        )

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    if not endpoint.endswith("/v1/traces"):
        endpoint = f"{endpoint.rstrip('/')}/v1/traces"

    raw_rate = os.getenv("OTEL_SAMPLING_RATE", "0.05")
    try:
        sampling_rate = min(max(float(raw_rate), 0.0), 1.0)
    except ValueError:
        sampling_rate = 0.05

    image_tag = os.getenv("IMAGE_TAG", os.getenv("OPENSHIFT_BUILD_COMMIT", "unknown"))
    env_name = os.getenv("ADVISOR_ENV", os.getenv("ENV_NAME", "dev"))
    resolved_service_name = os.getenv("OTEL_SERVICE_NAME", service_name)

    resource = Resource.create(
        {
            SERVICE_NAME: resolved_service_name,
            SERVICE_VERSION: image_tag,
            "deployment.environment": env_name,
        }
    )

    sampler = ParentBased(root=TraceIdRatioBased(sampling_rate))
    span_limits = SpanLimits(
        max_attributes=int(os.getenv("OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "64")),
        max_attribute_length=int(os.getenv("OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", "1024")),
    )

    provider = TracerProvider(resource=resource, sampler=sampler, span_limits=span_limits)
    provider.add_span_processor(RHAttributeSpanProcessor())

    compression_map = {"gzip": Compression.Gzip, "deflate": Compression.Deflate}
    compression = compression_map.get(
        os.getenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip").lower(),
        Compression.NoCompression,
    )
    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        compression=compression,
        timeout=int(os.getenv("OTEL_EXPORTER_OTLP_TIMEOUT", "10")),
    )
    bsp = BatchSpanProcessor(
        exporter,
        max_queue_size=int(os.getenv("OTEL_BSP_MAX_QUEUE_SIZE", "8192")),
        schedule_delay_millis=int(os.getenv("OTEL_BSP_SCHEDULE_DELAY", "2000")),
        max_export_batch_size=int(os.getenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "256")),
        export_timeout_millis=int(os.getenv("OTEL_BSP_EXPORT_TIMEOUT", "10000")),
    )
    provider.add_span_processor(FilteringSpanProcessor(bsp))
    trace.set_tracer_provider(provider)

    try:
        from opentelemetry.instrumentation.django import DjangoInstrumentor
        DjangoInstrumentor().instrument(excluded_urls=excluded_urls, response_hook=_django_response_hook)
        _reload_django_wsgi_middleware()
    except Exception as e:
        logger.warning("Django instrumentation failed or skipped: %s", e)

    try:
        from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
        Psycopg2Instrumentor().instrument(enable_commenter=False)
    except Exception as e:
        logger.warning("Psycopg2 instrumentation failed or skipped: %s", e)

    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        RequestsInstrumentor().instrument(request_hook=_outbound_request_hook)
    except Exception as e:
        logger.warning("Requests instrumentation failed or skipped: %s", e)

    try:
        from opentelemetry.instrumentation.confluent_kafka import ConfluentKafkaInstrumentor
        ConfluentKafkaInstrumentor().instrument()
    except Exception as e:
        logger.warning("Confluent Kafka instrumentation failed or skipped: %s", e)

    _IS_INITIALIZED = True
    _INITIALIZED_PID = current_pid
    logger.info("OpenTelemetry initialized for %s (PID %s, sampler=%s)", resolved_service_name, current_pid, sampler)


def is_enabled() -> bool:
    """Return whether telemetry is initialized and available in this process."""
    return _IS_INITIALIZED and OTEL_AVAILABLE


def get_tracer(name: str = "advisor"):
    """Return tracer only if OpenTelemetry is initialized and enabled."""
    if not is_enabled():
        return None
    try:
        return trace.get_tracer(name)
    except Exception:
        return None


def extract_kafka_headers_to_context(headers: Optional[list[tuple[str, bytes]]]):
    """Extract W3C trace context from Kafka message headers. Returns None if headers are absent."""
    if not headers or not OTEL_AVAILABLE:
        return None
    try:
        carrier = {}
        for key, val in headers:
            if isinstance(val, bytes):
                carrier[key] = val.decode("utf-8", errors="replace")
            elif isinstance(val, str):
                carrier[key] = val
        return propagate.extract(carrier)
    except Exception:
        return None


def trace_id_from_kafka_headers(headers: Optional[list[tuple[str, bytes]]]):
    """Return the W3C trace id from Kafka headers, or None if absent/invalid."""
    ctx = extract_kafka_headers_to_context(headers)
    if not ctx or not OTEL_AVAILABLE:
        return None
    try:
        span_ctx = trace.get_current_span(ctx).get_span_context()
        if span_ctx.is_valid:
            return span_ctx.trace_id
    except Exception:
        return None
    return None


def inject_trace_context_to_kafka_headers(headers: Optional[list[tuple[str, bytes]]] = None):
    """
    Copy W3C trace context from the current span into Kafka headers.
    Downstream consumers can extract this with extract_kafka_headers_to_context.
    """
    existing = list(headers) if headers else []
    if not OTEL_AVAILABLE or not _IS_INITIALIZED:
        return existing
    try:
        carrier = {}
        propagate.inject(carrier)
        injected_keys = set(carrier.keys())
        merged = [(k, v) for k, v in existing if k not in injected_keys]
        for key, val in carrier.items():
            if isinstance(val, bytes):
                merged.append((key, val))
            else:
                merged.append((key, str(val).encode("utf-8")))
        return merged
    except Exception:
        logger.debug("Failed to inject trace context into Kafka headers", exc_info=True)
        return existing


@contextmanager
def kafka_producer_span(topic: str, tracer_name: str = "advisor-service"):
    """Messaging PRODUCER span for an outbound Kafka send."""
    tracer = get_tracer(tracer_name)
    if not tracer:
        yield None
        return

    span_name = f"{topic} send"
    attributes = {
        "messaging.system": "kafka",
        "messaging.destination.name": topic,
        "messaging.operation.name": "send",
    }
    with tracer.start_as_current_span(
        span_name,
        kind=SpanKind.PRODUCER,
        attributes=attributes,
    ) as span:
        try:
            yield span
        except Exception as e:
            if span and span.is_recording():
                try:
                    from opentelemetry.trace import Status, StatusCode
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                except Exception:
                    pass
            raise
        finally:
            _enrich_span_from_thread_storage(span)


def _enrich_span_from_thread_storage(span):
    """
    Enrich a span with rh.org_id and rh.request_id from thread_storage.
    Called after the handler body has run.
    This ensures root consumer spans carry tenant attributes even though
    thread_storage is only populated mid-handler (after payload parsing).
    """
    if not span or not span.is_recording():
        return
    org_id = thread_storage.get_value("org_id")
    if org_id:
        span.set_attribute("rh.org_id", str(org_id))
    request_id = thread_storage.get_value("request_id")
    if request_id:
        span.set_attribute("rh.request_id", str(request_id))


@contextmanager
def kafka_consumer_span(topic: str, kafka_headers=None, tracer_name: str = "advisor-service"):
    """
    Standard OpenTelemetry Messaging CONSUMER span wrapper for Kafka message processing.
    Extracts W3C trace context from Kafka headers, sets semantic convention attributes,
    and no-ops cleanly if OpenTelemetry is uninitialized or disabled.
    """
    tracer = get_tracer(tracer_name)
    if not tracer:
        yield None
        return

    try:
        extracted_ctx = extract_kafka_headers_to_context(kafka_headers)
    except Exception:
        yield None
        return

    span_name = f"process {topic}"
    attributes = {
        "messaging.system": "kafka",
        "messaging.destination.name": topic,
        "messaging.operation.name": "process",
    }
    with tracer.start_as_current_span(
        span_name,
        context=extracted_ctx,
        kind=SpanKind.CONSUMER,
        attributes=attributes,
    ) as span:
        try:
            yield span
        finally:
            _enrich_span_from_thread_storage(span)


@contextmanager
def kafka_batch_consumer_span(topic: str, headers_list=None, message_count: int = 0, tracer_name: str = "advisor-kafka"):
    """
    CONSUMER span for a Kafka batch.

    Parent the span on the first valid W3C context so Tempo nests it under the
    upstream producer (ingress → … → inventory.events), matching
    kafka_consumer_span and HBI. Extra messages from *other* traces are attached
    as SpanLinks (a span can have only one parent).
    """
    tracer = get_tracer(tracer_name)
    if not tracer:
        yield None
        return

    extracted_ctx = None
    parent_trace_id = None
    links = []
    if headers_list:
        for h in headers_list:
            if not h:
                continue
            try:
                ctx = extract_kafka_headers_to_context(h)
                if not ctx:
                    continue
                span_ctx = trace.get_current_span(ctx).get_span_context()
                if not span_ctx.is_valid:
                    continue
                if extracted_ctx is None:
                    extracted_ctx = ctx
                    parent_trace_id = span_ctx.trace_id
                elif span_ctx.trace_id != parent_trace_id:
                    links.append(trace.Link(span_ctx))
            except Exception:
                logger.debug("Failed to extract trace context from Kafka header, skipping", exc_info=True)

    span_name = f"process {topic} batch"
    attributes = {
        "messaging.system": "kafka",
        "messaging.destination.name": topic,
        "messaging.operation.name": "process",
        "messaging.batch.message_count": message_count,
    }
    with tracer.start_as_current_span(
        span_name,
        context=extracted_ctx,
        kind=SpanKind.CONSUMER,
        links=links,
        attributes=attributes,
    ) as span:
        try:
            yield span
        finally:
            _enrich_span_from_thread_storage(span)


def shutdown_telemetry(timeout_millis: int = 5000) -> None:
    """
    Flush all buffered spans and cleanly shut down TracerProvider.
    Ensures queued spans in BatchSpanProcessor are exported prior to process exit.
    """
    global _IS_INITIALIZED, _INITIALIZED_PID
    if not _IS_INITIALIZED or not OTEL_AVAILABLE:
        return
    try:
        provider = trace.get_tracer_provider()
        if hasattr(provider, "force_flush"):
            provider.force_flush(timeout_millis=timeout_millis)
        if hasattr(provider, "shutdown"):
            provider.shutdown()
        _IS_INITIALIZED = False
        _INITIALIZED_PID = None
        logger.info("OpenTelemetry telemetry flushed and shut down successfully.")
    except Exception as e:
        logger.warning("Error flushing OpenTelemetry spans on shutdown: %s", e)
