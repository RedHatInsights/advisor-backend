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

import logging
import json
import sys
import traceback
from logstash_formatter import LogstashFormatterV1
import thread_storage
import settings
import watchtower
import boto3


class AdvisorStreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(sys.stdout)
        self.setFormatter(
            OurFormatter(fmt=json.dumps({"extra": {"component": settings.APP_NAME}}))
        )


class OurFormatter(LogstashFormatterV1):

    def format(self, record):
        # for debugging, store all processing statistics
        results_process = {}
        for results_process_key in ('engine_results_error', 'engine_results_error_msg',
                                    'engine_results_started', 'engine_results_finished',
                                    'engine_results_elapsed', 'report_started', 'report_finished',
                                    'report_elapsed', 'report_error', 'report_error_msg',
                                    'db_started', 'db_finished', 'db_elapsed', 'db_error',
                                    'db_error_msg', 'total_elapsed', 'rule_hits_started',
                                    'rule_hits_finished', 'rule_hits_elapsed',
                                    'rule_hits_error', 'rule_hits_error_msg',
                                    'inventory_event_started', 'inventory_event_finished',
                                    'inventory_event_error', 'inventory_event_error_msg'):
            thread_storage_value = thread_storage.get_value(results_process_key)
            if thread_storage_value:
                results_process[results_process_key] = thread_storage_value

        # if we are debugging, add stats to the logged object
        if settings.LOG_LEVEL == 'DEBUG':
            setattr(record, "results_process", results_process)

        # add request id and system id for tracking in kibana
        for info in ['request_id', 'system_id']:
            thread_info = thread_storage.get_value(info)
            if thread_info:
                setattr(record, info, thread_info)

        # log any exception information
        exc = getattr(record, "exc_info")
        if exc:
            setattr(record, "exception", "".join(traceback.format_exception(*exc)))
            setattr(record, "exc_info", None)

        return super(OurFormatter, self).format(record)


def initialize_logging():
    LOG_LEVEL = settings.LOG_LEVEL

    # setup root handlers
    if settings.ENVIRONMENT != "dev":
        if not logging.root.hasHandlers():
            logging.root.setLevel(LOG_LEVEL)
            logging.root.addHandler(AdvisorStreamHandler())
    else:
        logging.basicConfig(level=logging.getLevelName(settings.DEV_LOG_LEVEL),
                        format=settings.DEV_LOG_MSG_FORMAT,
                        datefmt=settings.DEV_LOG_DATE_FORMAT)

    logger = logging.getLogger(settings.APP_NAME)

    # Setup watchtower logging
    if (settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY):
        cw_handler = None
        try:
            CW_CLIENT = boto3.client('logs',
                                     aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                                     aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                                     region_name=settings.AWS_REGION_NAME)

            cw_log_stream_manual = settings.CW_LOG_STREAM_MANUAL
            cw_log_stream_auto = settings.CW_LOG_STREAM_AUTO
            cw_log_stream = cw_log_stream_manual if cw_log_stream_manual else cw_log_stream_auto
            create_log_group = settings.CW_CREATE_LOG_GROUP
            logger.debug("Starting cloud watch log handler...")
            cw_handler = watchtower.CloudWatchLogHandler(boto3_client=CW_CLIENT,
                                                         log_group=settings.CW_LOG_GROUP,
                                                         stream_name=str(cw_log_stream),
                                                         create_log_group=create_log_group)
            cw_handler.setFormatter(
                OurFormatter(fmt=json.dumps({"extra": {"component": settings.APP_NAME}})))
            logging.root.addHandler(cw_handler)
            logger.debug("Cloud watch logging configured")
        except Exception:
            if cw_handler:
                logging.root.removeHandler(cw_handler)
            logger.exception("Cloud watch logging setup encountered an Exception")

    # show django queries specifically
    if settings.LOG_DB_QUERIES:
        db_logger = logging.getLogger('django.db.backends')
        db_logger.setLevel(logging.DEBUG)
        db_logger.addHandler(logging.StreamHandler())

    return logger


# singleton for the whole application
logger = logging.getLogger(settings.APP_NAME)
