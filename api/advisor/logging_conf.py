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

#
# Shared logging config for both the Django and gunicorn loggers
#
import json
import os
from os import getenv
import app_common_python
ENVIRONMENT = getenv('ADVISOR_ENV', 'dev').lower()
LOG_LEVEL = getenv('LOG_LEVEL', 'INFO').upper()
USE_CLOUDWATCH_LOGGING = getenv('USE_CLOUDWATCH_LOGGING', 'false').lower()

cfg = app_common_python.LoadedConfig
CLOWDER_ENABLED = os.getenv('CLOWDER_ENABLED', '').lower() == 'true'


def hide_metrics(record):
    # show metrics if in DEBUG
    if LOG_LEVEL == 'DEBUG':
        return True

    # otherwise do not
    record_name = getattr(record, "name", 'none')
    record_args = getattr(record, "args", None)
    if record_name in ('django.request', 'django.server') and record_args and isinstance(record_args, str):
        args = record_args.split()
        if len(args) > 1 and args[0] == 'GET' and args[1] == '/metrics':
            return False
    elif record_name == 'gunicorn.access' and record_args and isinstance(record_args, dict) and record_args.get('U') == '/metrics':
        return False
    return True


# Used by Django's settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler' if ENVIRONMENT == 'dev' else 'advisor_logging.AdvisorStreamHandler',
            'filters': ['hide_metrics']
        },
    },
    'formatters': {
        'json': {
            'class': 'advisor_logging.OurFormatter',
            'format': json.dumps({"extra": {"component": 'insights-advisor-api'}}),
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False
        },
        'advisor-log': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'gunicorn': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'api.management': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
        }
    },
    'filters': {
        'hide_metrics': {
            '()': 'django.utils.log.CallbackFilter',
            'callback': hide_metrics
        }
    },
}


def load_cloudwatch_logging():
    if CLOWDER_ENABLED:
        cw = cfg.logging.cloudwatch
        AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', cw.accessKeyId)
        AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', cw.secretAccessKey)
        AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', cw.region)
        CW_LOG_GROUP = os.environ.get('CW_LOG_GROUP', cw.logGroup)
    else:
        AWS_ACCESS_KEY_ID = getenv('AWS_ACCESS_KEY_ID')
        AWS_SECRET_ACCESS_KEY = getenv('AWS_SECRET_ACCESS_KEY')
        AWS_REGION_NAME = getenv('AWS_REGION_NAME', 'us-east-1')
        CW_LOG_GROUP = getenv('CW_LOG_GROUP', 'platform-dev')

    CW_CREATE_LOG_GROUP = os.environ.get('CW_CREATE_LOG_GROUP', "").lower() == "true"
    CW_LOG_STREAM = os.environ.get('HOSTNAME', os.uname())

    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:

        import boto3
        CW_CLIENT = boto3.client(
            'logs',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION_NAME
        )

        LOGGING['handlers']['cloudwatch'] = {
            'level': LOG_LEVEL,
            'class': 'watchtower.CloudWatchLogHandler',
            'boto3_client': CW_CLIENT,
            'log_group': CW_LOG_GROUP,
            'stream_name': str(CW_LOG_STREAM),
            'formatter': 'json',
            'create_log_group': CW_CREATE_LOG_GROUP,
            'filters': ['hide_metrics']
        }
        for logger in LOGGING['loggers']:
            LOGGING['loggers'][logger]['handlers'].append('cloudwatch')


if USE_CLOUDWATCH_LOGGING == 'true':
    load_cloudwatch_logging()


# Used by gunicorn's --config option
logconfig_dict = LOGGING
