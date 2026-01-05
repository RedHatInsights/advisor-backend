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

from django.test import TestCase

from api.models import RuleTopic
from api.tests import constants, update_stale_dates
from api.permissions import RHIdentityAuthentication, request_object_for_testing

import uuid


class RuleTopicModelTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def setUp(self):
        update_stale_dates()

    def test_active_rules_topic_model(self):
        active_rules = RuleTopic.objects.get(slug='Active')
        self.assertEqual(active_rules.name, 'Active rules')
        self.assertEqual(active_rules.slug, 'Active')
        self.assertEqual(active_rules.enabled, True)
        self.assertEqual(
            active_rules.description,
            "The set of active rules (including acked rules)"
        )
        self.assertEqual(active_rules.tag.name, 'active')
        self.assertEqual(str(active_rules), "Topic Active rules")
        rq = request_object_for_testing(auth_by=RHIdentityAuthentication)
        rq.account = constants.standard_acct
        rq.auth['org_id'] = constants.standard_org
        self.assertEqual(
            list(active_rules.reports_for_account(rq).order_by(
                'host_id'
            ).distinct('host_id').values_list('host_id', flat=True)),
            [
                uuid.UUID(constants.host_01_uuid),
                uuid.UUID(constants.host_03_uuid),
                uuid.UUID(constants.host_04_uuid),
                uuid.UUID(constants.host_06_uuid),
            ]
        )
        self.assertEqual(active_rules.tagged_rules()[0].rule_id, constants.acked_rule)
        self.assertEqual(active_rules.tagged_rules()[1].rule_id, constants.active_rule)
        self.assertEqual(active_rules.tagged_rules()[2].rule_id, constants.second_rule)
