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

import pytest
import json
import os
from shutil import copyfile

from django.core.management import call_command
import requests


THIS_DIR = os.path.dirname(os.path.realpath(__file__))
TEST_ENV_VARS = {
    "BOOTSTRAP_SERVERS": "localhost:9092",
    "ENGINE_RESULTS_TOPIC": "platform.engine.results",
    "RULE_HITS_TOPIC": "platform.insights.rule-hits",
    "WEBHOOKS_TOPIC": "webhooks",
    "INVENTORY_EVENTS_TOPIC": "platform.inventory.events",
    "THREAD_POOL_SIZE": "2",
    "DISABLE_PROMETHEUS": "True",
    "DJANGO_SETTINGS_MODULE": "settings",
    "FILTER_OUT_NON_RHEL": "False",
    "S3_RETRY_TIMES": "3",
    "S3_RETRY_SECONDS": "1",
}
os.environ.update(TEST_ENV_VARS)
pytest_plugins = ['pytest_server_fixtures.http']


@pytest.fixture
def db(request, django_db_setup, django_db_blocker):
    """
    Load DB fixtures for any test using this pytest fixture.
    """
    with django_db_blocker.unblock():
        call_command('mock_cyndi_table')
    fixtures = (
        'advisor_service_inventoryhost',
        'service_test_data',
        'basic_test_data',
        'rulesets',
        'rule_categories',
        'system_types',
        'upload_sources',
        'sample_report_rules'
    )
    with django_db_blocker.unblock():
        call_command('loaddata', *fixtures)


def pytest_configure():
    """
    Update env vars here so that when django.setup() runs it loads our test vars
    """
    os.environ.update(TEST_ENV_VARS)


@pytest.fixture
def env():
    return TEST_ENV_VARS


@pytest.fixture
def sample_report_data():
    with open(os.path.join(THIS_DIR, "sample_report.json")) as f:
        return json.load(f)


@pytest.fixture
def sample_engine_results():
    with open(os.path.join(THIS_DIR, "sample_engine_results.json")) as f:
        return json.load(f)


@pytest.fixture
def sample_satellite_engine_results():
    with open(os.path.join(THIS_DIR, "sample_satellite_engine_results.json")) as f:
        return json.load(f)


@pytest.fixture
def sample_rhel6_engine_results():
    with open(os.path.join(THIS_DIR, "sample_rhel6_engine_results.json")) as f:
        return json.load(f)


@pytest.fixture
def sample_rule_hits():
    with open(os.path.join(THIS_DIR, "sample_rule_hits.json")) as f:
        return json.load(f)


@pytest.fixture(scope="function")
def service(mocker, monkeypatch):
    """
    Fixture which imports 'service' and completely mocks out kafka producer/consumer.

    Important to patch os.environ before we import 'service',
    since "stuff" is loaded at import time which may cause service to not use our patched objects
    """
    import service

    service.report_hooks.p = mocker.MagicMock()
    service.c = mocker.MagicMock()
    yield service


@pytest.fixture
def mock_request_post_return_200(mocker):
    mock_response = mocker.Mock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.content = "SOME CONTENT!"
    mocker.patch.object(requests, "post", return_value=mock_response)
