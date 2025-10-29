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

    server.log.info(f"Worker {worker.pid}: Creating new UnleashClient...")

    feature_flags._client = Client().connect()
