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

from rest_framework.routers import SimpleRouter
from api.views import import_content, playbooks

# Any viewset in here must have `schema = None` set to make sure it doesn't
# get picked up by the schema

private_router = SimpleRouter()
private_router.register(r'import_content', import_content.ImportContentViewSet, basename='import_content')
private_router.register(r'playbooks', playbooks.PlaybooksViewSet, basename='playbooks')
urlpatterns = private_router.urls
