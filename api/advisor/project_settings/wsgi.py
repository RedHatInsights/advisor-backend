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

"""
WSGI config for advisor project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/howto/deployment/wsgi/
"""

import os
import sys

from django.core.wsgi import get_wsgi_application
import telemetry

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project_settings.settings")

# Under gunicorn --preload this module is imported in the MASTER before workers
# fork, so initializing here would start BatchSpanProcessor's exporter thread in
# the master and leave workers with an inherited *dead* thread. post_fork in
# gunicorn_conf.py initializes telemetry once per worker instead. Non-gunicorn
# runtimes (e.g. manage.py runserver) have no fork, so init at import is correct.
if "gunicorn" not in sys.modules:
    telemetry.init_telemetry(service_name="insights-advisor-api")
application = get_wsgi_application()
