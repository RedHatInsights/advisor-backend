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

import os
import sys
import app_common_python
from os.path import dirname, abspath

# Setup the API Environment so we can import shared models
# and other logic
PARENT = dirname(dirname(abspath(__file__)))
sys.path.append(os.path.join(PARENT, 'api', 'advisor'))

TEST_RUNNER = 'project_settings.testrunner.CyndiTestRunner'

def get_namespace():
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as f:
            namespace = f.read()
        return namespace
    except EnvironmentError:
        print("Not running in openshift")


cfg = app_common_python.LoadedConfig
CLOWDER_ENABLED = os.getenv('CLOWDER_ENABLED', '').lower() == 'true'

INSTALLED_APPS = [
    'api.apps.ApiConfig',
]

# APP_NAME
APP_NAME = "insights-advisor-service"

# Define the Django psycopg2 options
# This allows us to insert the application name for metadata
DJANGO_DB_OPTIONS = {'application_name': APP_NAME}

# Toggle for Clowder
if CLOWDER_ENABLED:
    db = cfg.database
    DATABASES = {
        'default': {
            'ENGINE': os.environ.get('ADVISOR_DB_ENGINE', 'django_prometheus.db.backends.postgresql'),
            'NAME': os.environ.get('ADVISOR_DB_NAME', db.name),
            'USER': os.environ.get('ADVISOR_DB_USER', db.username),
            'PASSWORD': os.environ.get('ADVISOR_DB_PASSWORD', db.password),
            'HOST': os.environ.get('ADVISOR_DB_HOST', db.hostname),
            'PORT': db.port,
            'OPTIONS': DJANGO_DB_OPTIONS
        },
    }

    cw = cfg.logging.cloudwatch
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', cw.accessKeyId)
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', cw.secretAccessKey)
    AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', cw.region)
    CW_LOG_GROUP = os.environ.get('CW_LOG_GROUP', cw.logGroup)
    CW_LOG_STREAM_MANUAL = os.environ.get('CW_LOG_STREAM')
    CW_LOG_STREAM_AUTO = os.environ.get('HOSTNAME', os.uname())

    PROMETHEUS_PATH = os.environ.get('PROMETHEUS_PATH', cfg.metricsPath)  # this is not actually used with the prometheus client libs
    PROMETHEUS_PORT = os.environ.get('PROMETHEUS_PORT', cfg.metricsPort)

else:

    DATABASES = {
        'default': {
            'ENGINE': os.environ.get('ADVISOR_DB_ENGINE', 'django_prometheus.db.backends.postgresql'),
            'NAME': os.environ.get('ADVISOR_DB_NAME', 'insightsapi'),
            'USER': os.environ.get('ADVISOR_DB_USER', 'insightsapi'),
            'PASSWORD': os.environ.get('ADVISOR_DB_PASSWORD', 'InsightsData'),
            'HOST': os.environ.get('ADVISOR_DB_HOST', 'localhost'),
            'PORT': '5432',
            'OPTIONS': DJANGO_DB_OPTIONS
        },
    }

    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME')

    CW_LOG_GROUP = os.environ.get('CW_LOG_GROUP', 'platform-dev')
    CW_LOG_STREAM_MANUAL = os.environ.get('CW_LOG_STREAM')
    CW_LOG_STREAM_AUTO = os.environ.get('HOSTNAME', 'insights-advisor-service-dev')

    PROMETHEUS_PATH = os.environ.get('PROMETHEUS_PATH', '/')  # this is not actually used with the prometheus client libs
    PROMETHEUS_PORT = os.environ.get('PROMETHEUS_PORT', 8000)


CW_CREATE_LOG_GROUP = os.environ.get('CW_CREATE_LOG_GROUP', "").lower() == "true"
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# SECURITY WARNING: don't run with debug turned on in production!
ENVIRONMENT = os.environ.get('ADVISOR_ENV', 'dev')
DEBUG = ENVIRONMENT in ('dev', 'ci', 'qa')

# Logging settings
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
DEV_LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
DEV_LOG_MSG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] " \
            "[%(thread)d  %(threadName)s] [%(process)d] %(message)s"
DEV_LOG_DATE_FORMAT = "%H:%M:%S"
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'stdout': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler' if ENVIRONMENT == 'dev'
                     else 'advisor_logging.AdvisorStreamHandler',

        },
    },
    'loggers': {
        'django': {
            'handlers': ['stdout'],
            'level': os.environ.get('LOG_LEVEL', 'INFO'),
            'propagate': True,
        },
    },
}

GROUP_ID = os.environ.get('GROUP_ID', 'advisor_results')
DISABLE_PROMETHEUS = os.environ.get('DISABLE_PROMETHEUS', "").lower() == "true"

DB_RETRY_CONSTANT = int(os.environ.get('DB_RETRY_CONSTANT', 3))
THREAD_POOL_SIZE = int(os.environ.get('THREAD_POOL_SIZE', 30))
# FILTER_OUT_NON_RHEL should be true by default
FILTER_OUT_NON_RHEL = os.environ.get('FILTER_OUT_NON_RHEL', "true").lower() == "true"
OTHER_LINUX_SYSTEM_IDS = 'other_linux_system|OTHER_LINUX_SYSTEM,other_linux_system|OTHER_LINUX_SYSTEM_V2,other_linux_system|CONVERT2RHEL_SUPPORTED'
FILTER_OUT_NON_RHEL_RULE_ID = os.environ.get('FILTER_OUT_NON_RHEL_RULE_ID',
                                             OTHER_LINUX_SYSTEM_IDS).split(',')
# RHEL6 systems will only report RHEL6_UPGRADE_RULE_IDS from July 1st, 2024
FILTER_OUT_RHEL6 = os.environ.get('FILTER_OUT_RHEL6', "true").lower() == "true"
RHEL6_UPGRADE_RULE_IDS = 'rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN,rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1,rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_ERROR'
FILTER_OUT_RHEL6_RULE_IDS = os.environ.get('FILTER_OUT_RHEL6_RULE_IDS', RHEL6_UPGRADE_RULE_IDS).split(',')

LOG_DB_QUERIES = os.environ.get('LOG_DB_QUERIES', "").lower() == 'true'
BUILD_NAME = os.getenv('OPENSHIFT_BUILD_NAME', 'dev')
BUILD_ID = os.getenv('OPENSHIFT_BUILD_COMMIT', 'dev')
BUILD_REF = os.getenv('OPENSHIFT_BUILD_REFERENCE', '')
NAMESPACE = get_namespace()

AUTOACK = {
    'TAG': 'autoack',
    'CREATED_BY': 'Red Hat Insights',
    'JUSTIFICATION': 'Disabled by default - enable to begin detection'
}

KESSEL_ENABLED = os.getenv("KESSEL_ENABLED", "false").lower == 'true'
KESSEL_SERVER_NAME = os.getenv('KESSEL_SERVER_NAME', 'device under test')
KESSEL_SERVER_PORT = os.getenv('KESSEL_SERVER_PORT', '50051')
KESSEL_SERVER_PASSWORD = os.getenv('KESSEL_SERVER_PASSWORD', 'mykey')
