# Gunicorn configuration file

from logging_conf import logconfig_dict

# Use the logging config from logging_conf.py
logconfig_dict = logconfig_dict


def on_starting(server):
    """Start a multiprocess-aware Prometheus metrics server on the Clowder metrics port.

    Clowder configures a separate metricsPort (typically 9000) that Prometheus scrapes.
    django_prometheus's built-in start_http_server() uses the default in-process registry,
    which doesn't work with gunicorn multiprocess mode — it misses all the per-worker
    metrics stored in .db files. Instead, we start a custom HTTP server that uses
    MultiProcessCollector to aggregate metrics from all worker .db files on each scrape.
    """
    import os
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler

    from django.conf import settings
    from advisor_logging import logger

    metrics_port = getattr(settings, 'PROMETHEUS_PORT', None)
    if metrics_port is None or metrics_port == int(os.getenv('GUNICORN_PORT', '8000')):
        return  # Metrics served via Django view on the same port; no separate server needed.

    class MultiProcessMetricsHandler(BaseHTTPRequestHandler):
        """HTTP handler that collects metrics from all gunicorn worker .db files."""

        def do_GET(self):
            try:
                import prometheus_client
                from prometheus_client import CollectorRegistry, generate_latest, multiprocess

                registry = CollectorRegistry()
                multiprocess.MultiProcessCollector(registry)
                output = generate_latest(registry)
                self.send_response(200)
                self.send_header('Content-Type', prometheus_client.CONTENT_TYPE_LATEST)
                self.end_headers()
                self.wfile.write(output)
            except Exception:
                # Return 500 so the endpoint stays available despite collection failures
                logger("Failed to collect multiprocess Prometheus metrics", exc_info=True)
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                try:
                    self.wfile.write(b"Internal Server Error while collecting metrics\n")
                except Exception:
                    # If the client has gone away, just swallow the error; logging above is enough
                    pass

        def log_message(self, format, *args):
            pass  # Suppress per-request access logs

    addr = getattr(settings, 'PROMETHEUS_METRICS_EXPORT_ADDRESS', '')
    httpd = HTTPServer((addr, metrics_port), MultiProcessMetricsHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    server.log.info(f"Multiprocess Prometheus metrics server started on port {metrics_port}")


def post_fork(server, worker):
    """
    This hook is called after a worker has been forked.

    CRITICAL: When using gunicorn --preload, the UnleashClient is created in the parent
    process. After fork(), the worker inherits the client but the background
    scheduler thread doesn't survive (daemon threads die on fork).

    We MUST create a NEW client instance to get fresh scheduler threads.
    """
    import feature_flags
    from feature_flags import Client
    from prometheus_client import values

    server.log.info(f"Worker {worker.pid}: Creating new UnleashClient...")
    feature_flags._client = Client().connect()

    server.log.info("Resetting prometheus state so each worker writes to its own .db file...")
    values.ValueClass = values.MultiProcessValue()


def child_exit(server, worker):
    # Clean up dead worker .db files from /tmp
    from prometheus_client import multiprocess
    multiprocess.mark_process_dead(worker.pid)
