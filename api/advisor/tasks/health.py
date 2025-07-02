#!/usr/bin/env python

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

import sys
import os
from os.path import dirname, abspath
import traceback
import time
from confluent_kafka import Consumer

# Access common code
PARENT = dirname(dirname(abspath(__file__)))
sys.path.append(os.path.join(PARENT))

# Setup Django database models
import django
from django.conf import settings
from django.db import connections
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project_settings.settings")
try:
    django.setup()
except:
    pass
import api.models as db  # noqa

from advisor_logging import logger

# Import Kafka stuff
import project_settings.kafka_settings as kafka_settings
kafka_settings.KAFKA_SETTINGS.update({'group.id': settings.GROUP_ID})

# Retry constants
DB_RETRY_COUNT_MAX = 3
DB_COUNT_TIMEOUT_SECONDS = 1
KAFKA_RETRY_MAX = 3
KAFKA_COUNT_TIMEOUT_SECONDS = 5
KAFKA_SOCKET_TIMEOUT_MS = 5000


def check_db_connection():
    logger.debug('Attempting to establish a DB Connection %s times', DB_RETRY_COUNT_MAX)
    for count in range(0, DB_RETRY_COUNT_MAX):
        try:
            logger.debug('Database connection attempt %s', (count + 1))
            django.db.connection.ensure_connection()
            logger.debug('Valid DB Connection established.')
            return
        except:
            error_msg = traceback.format_exc()
            logger.debug('Received database connection attempt error: %s', error_msg)
            time.sleep(DB_COUNT_TIMEOUT_SECONDS)
    logger.error('Database retry count max hit for valid connection. Health check failed.')
    sys.exit(1)


def check_sql_execution():
    logger.debug('Attempting to run basic SQL Execution %s times', DB_RETRY_COUNT_MAX)
    for count in range(0, DB_RETRY_COUNT_MAX):
        try:
            logger.debug('SQL Execution attempt %s', (count + 1))
            db_conn = connections['default']
            c = db_conn.cursor()
            c.execute("""SELECT 1;""")
            c.fetchone()
            logger.debug('SQL Execution successful')
            return
        except:
            error_msg = traceback.format_exc()
            logger.debug('Received database SQL Execution error:', error_msg)
            time.sleep(DB_COUNT_TIMEOUT_SECONDS)
    logger.error('Databse SQL Execution retry max hit. Health check failed.')
    sys.exit(1)


def check_kafka_connection():
    logger.debug('Attempting to check if Kafka Consumer is valid and connection is valid.')
    for count in range(0, KAFKA_RETRY_MAX):
        try:
            logger.debug('Kafka connection attempt %s', (count + 1))
            # Setup Consumer
            c = Consumer(kafka_settings.KAFKA_SETTINGS)
            # Get topics
            kafka_topics = [kafka_settings.TASKS_SOURCES_TOPIC, kafka_settings.TASKS_UPDATES_TOPIC]
            for topic in kafka_topics:
                topic_info = c.list_topics(topic, timeout=KAFKA_SOCKET_TIMEOUT_MS)
                logger.debug('Topic info found for %s: %s', topic, topic_info)
            return
        except:
            error_msg = traceback.format_exc()
            logger.debug('Received Kafka Consumer error: %s', error_msg)
            time.sleep(KAFKA_COUNT_TIMEOUT_SECONDS)
    logger.error('Kafka Consumer could not be established. Health check failed.')
    sys.exit(1)


def health_check():
    # Check DB connection
    check_db_connection()

    # Do simple DB call
    check_sql_execution()

    # Check Kafka Consumer connection
    check_kafka_connection()

    # Everything checks out
    logger.debug('All Health Checks passed.')
    sys.exit(0)


# Perform health check
health_check()
