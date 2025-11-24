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

# Flake8 doesn't like star imports, and we can't seem to do 'from api import
# views' and then use views.acks.AckViewSet.  Better solutions welcomed!
from api.views import (
    acks, autosubexclusion, disabled_rules, export, hostacks, kcs,
    rule_categories, rule_ratings, rule_topics, rules, pathways,
    stats, status, swagger, systems, system_types, user_preferences,
    weekly_report_subscriptions, weekly_report_auto_subscribe
)

# The APIRootView docstring gets used to generate the description of the
# API listing; I haven't found a way to override that either in creating the
# router or in setting up the list of URLs.  So we create our own subclasses
# here to contain nice documented strings.


class AdvisorRootView(APIRootView):
    """
    The Insights Advisor API root view.
    """
    # _get_resource needs a base name for all views.
    basename = 'advisor-root'


class AdvisorRouter(DefaultRouter):
    """
    Use our own root view to provide a nicer schema description.
    """
    APIRootView = AdvisorRootView


router = AdvisorRouter()
router.register(r'ack', acks.AckViewSet)
router.register(r'ackcount', acks.AckCountViewSet, basename='ackcount')
router.register(r'autosubexclusion', autosubexclusion.AutosubExclusionViewSet, basename='autosubexclusion')
router.register(r'disabled-rules', disabled_rules.DisabledRulesViewSet, basename='disabled-rules')
router.register(r'hostack', hostacks.HostAckViewSet)
router.register(r'kcs', kcs.KcsViewSet, basename='kcs')
router.register(r'rating', rule_ratings.RuleRatingViewSet)
router.register(r'rule', rules.RuleViewSet)
router.register(r'pathway', pathways.PathwayViewSet, basename='pathway')
router.register(r'rulecategory', rule_categories.RuleCategoryViewSet)
router.register(r'stats', stats.StatsViewSet, basename='stats')
router.register(r'status', status.StatusViewSet, basename='status')
router.register(r'system', systems.SystemViewSet, basename='system')
router.register(r'systemtype', system_types.SystemTypeViewSet)
router.register(r'topic', rule_topics.RuleTopicViewSet)
router.register(r'user-preferences', user_preferences.PreferencesViewSet, basename='user-preferences')
router.register(
    r'weeklyreportsubscription', weekly_report_subscriptions.WeeklyReportSubscriptionViewSet,
    basename='weeklyreportsubscription'
)
router.register(
    r'weeklyreportautosubscribe', weekly_report_auto_subscribe.WeeklyReportAutoSubscribeViewSet,
    basename='weeklyreportautosubscribe'
)

advisor_schema_settings = {
    'TITLE': 'Insights Advisor API',
    'DESCRIPTION': "The API for viewing Red Hat recommendations for your systems",
    # Make sure we don't publish a prefix, as the router uses full paths.
    'SCHEMA_PATH_PREFIX': '',
}

urlpatterns = [
    path(r'', include(router.urls)),
    path(r'export/', include(export.router.urls), name='export-list'),
    path('openapi/', swagger.spectacular_view, name='advisor-openapi-spec'),
    path('openapi.json', swagger.spectacular_json_view, name='advisor-openapi-spec-json'),
    path('openapi/swagger/', swagger.spectacular_ui_view, name='advisor-openapi-ui'),
]
