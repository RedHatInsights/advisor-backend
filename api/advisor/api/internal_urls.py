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

from django.urls import path, include

from rest_framework.routers import APIRootView, DefaultRouter

from api.views import rules


class InternalRootView(APIRootView):
    """
    The Insights Advisor API root view for Red Hat associate access only.
    """
    pass


class InternalRouter(DefaultRouter):
    """
    Use our own root view to provide a nicer schema description.
    """
    APIRootView = InternalRootView


router = InternalRouter()
router.register(r'rule', rules.InternalRuleViewSet, basename='internal-rule')

urlpatterns = [
    path(r'', include(router.urls)),
]
