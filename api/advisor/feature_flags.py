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

from UnleashClient import UnleashClient


# Define actual feature flags here, to be used as module properties.
FLAG_ADVISOR_KESSEL_ENABLED = "advisor.kessel_enabled"
FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION = "advisor.inventory_hosts_db_logical_replication"


def setting(name, default=None):
    from django.conf import settings

    """
    Helper function to get a Django setting by name.
    If setting doesn't exist it will return a default.
    """
    return getattr(settings, name, default)


class Client:
    def __init__(self):
        custom_headers = setting("UNLEASH_CUSTOM_HEADERS")
        custom_options = setting("UNLEASH_CUSTOM_OPTIONS")
        custom_strategies = {}

        self._url = setting("UNLEASH_URL")
        self._app_name = setting("UNLEASH_APP_NAME")
        self._environment = setting("UNLEASH_ENVIRONMENT", "default")
        self._instance_id = setting("UNLEASH_INSTANCE_ID", "unleash-client-python")
        self._refresh_interval = setting("UNLEASH_REFRESH_INTERVAL", 5)
        self._refresh_jitter = setting("UNLEASH_REFRESH_JITTER", None)
        self._metrics_interval = setting("UNLEASH_METRICS_INTERVAL", 10)
        self._metrics_jitter = setting("UNLEASH_METRICS_JITTER", None)
        self._disable_metrics = setting("UNLEASH_DISABLE_METRICS", False)
        self._disable_registration = setting("UNLEASH_DISABLE_REGISTRATION", False)
        self._custom_headers = custom_headers or {}
        self._custom_options = custom_options or {}
        self._custom_strategies = custom_strategies or {}
        self._cache_directory = setting("UNLEASH_CACHE_DIRECTORY")
        self._project_name = setting("UNLEASH_PROJECT_NAME")
        self._verbose_log_level = setting("UNLEASH_VERBOSE_LOG_LEVEL", logging.WARNING)
        self._token = setting("UNLEASH_TOKEN")
        self._fake_initialize = setting("UNLEASH_FAKE_INITIALIZE", False)

    def _update_custom_header(self):
        auth_header = {
            "Authorization": self._token,
        }
        return self._custom_headers.update(auth_header)

    def _set_log_severity(self):
        for logger_name in ["UnleashClient", "apscheduler.scheduler", "apscheduler.executors"]:
            logging.getLogger(logger_name).setLevel(self._verbose_log_level)

    def connect(self) -> UnleashClient:
        self._update_custom_header()
        self._set_log_severity()

        client = UnleashClient(
            url=self._url,
            app_name=self._app_name,
            custom_headers=self._custom_headers,
            environment=self._environment,
            instance_id=self._instance_id,
            refresh_interval=self._refresh_interval,
            refresh_jitter=self._refresh_jitter,
            metrics_interval=self._metrics_interval,
            metrics_jitter=self._metrics_jitter,
            disable_metrics=self._disable_metrics,
            disable_registration=self._disable_registration,
            custom_options=self._custom_options,
            custom_strategies=self._custom_strategies,
            cache_directory=self._cache_directory,
            project_name=self._project_name,
            verbose_log_level=self._verbose_log_level
        )

        if self._fake_initialize:
            client.is_initialized = True
        else:
            client.initialize_client()

        return client


_client = Client().connect()


def unleash_client() -> UnleashClient:
    return _client


def feature_flag_is_enabled(feature: str, context: dict = None) -> bool:
    return _client.is_enabled(feature, context=context, fallback_function=custom_fallback)


def custom_fallback(feature_name: str, context: dict) -> bool:
    """
    Fallback function for feature flags when Unleash is unavailable.
    
    This function strips the 'advisor.' prefix from the feature name,
    converts it to Django settings format (uppercase with underscores),
    and checks if a corresponding setting exists.
    
    For example:
    - 'advisor.kessel_enabled' -> checks settings.KESSEL_ENABLED
    - 'advisor.inventory_hosts_db_logical_replication' -> checks settings.INVENTORY_HOSTS_DB_LOGICAL_REPLICATION
    
    Args:
        feature_name: The feature flag name
        context: The context dictionary (unused in this implementation)
    
    Returns:
        The value from Django settings if it exists, otherwise False
    """
    stripped_name = feature_name[len('advisor.'):]
    
    return setting(stripped_name.upper(), False)
