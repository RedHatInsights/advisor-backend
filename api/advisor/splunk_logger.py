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

import requests
import json
import time
import socket
from django.conf import settings

from advisor_logging import logger


def log(message, **kwargs):
    if not settings.ENABLE_SPLUNK_HEC:
        return

    log_message = {
        "message": message,
        "timestamp": int(time.time()),
        "namespace": settings.ENV_NAME,
        **kwargs
    }
    payload = {
        "event": json.dumps(log_message),
        "sourcetype": "_json",
        "index": "rh_insights_tasks",
        "host": socket.gethostname(),
        "source": "insights-tasks.log"
    }
    try:
        response = requests.post(settings.SPLUNK_URL, json=payload, headers={"Authorization": f"Splunk {settings.SPLUNK_TOKEN.capitalize()}"}, timeout=2)
        if response.status_code != 200:
            logger.error("Could not upload event to splunk.  Status code: %s  Content: %s", response.status_code, response.content)
    except Exception:
        logger.exception("Error uploading event to splunk")
