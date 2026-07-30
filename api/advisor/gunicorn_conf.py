# Gunicorn configuration file

from logging_conf import logconfig_dict

# Use the logging config from logging_conf.py
logconfig_dict = logconfig_dict


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
