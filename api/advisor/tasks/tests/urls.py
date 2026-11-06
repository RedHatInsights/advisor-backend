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
URLconf for testing the Tasks views.

The Tasks API has been decommissioned and the project URLconf returns 410 Gone
for all of it (RHINENG-31068).  The views still exist until the Tasks code is
removed, so their tests use this URLconf, which routes the Tasks URLs to them
ahead of the project's 410 routes.
"""

from django.conf import settings
from django.urls import include, path

from project_settings.urls import urlpatterns as project_urlpatterns

urlpatterns = [
    path(settings.TASKS_PATH_PREFIX, include('tasks.urls')),
    path('internal/' + settings.TASKS_PATH_PREFIX, include('tasks.internal_urls')),
] + project_urlpatterns
