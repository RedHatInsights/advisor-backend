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
from django.utils import timezone

from api.models import RuleSet, Rule, RuleCategory, RuleImpact, Resolution
from api.tests import constants, update_stale_dates
from api.permissions import RHIdentityAuthentication, request_object_for_testing

import datetime
import pytz
import uuid

# Create your tests here.


class RuleTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'high_severity_rule'
    ]

    def setUp(self):
        # Created/updated timestamps don't contain microseconds?
        self.test_start = timezone.now().replace(microsecond=0)
        update_stale_dates()

    def test_active_rule_properties(self):
        r = Rule.objects.get(rule_id=constants.active_rule)
        self.assertEqual(r.rule_id, constants.active_rule)
        self.assertEqual(r.description, constants.active_title)
        self.assertEqual(r.active, True)
        self.assertEqual(r.reboot_required, False)
        self.assertEqual(r.publish_date, datetime.datetime(
            2018, 5, 23, 15, 38, 55,
            tzinfo=pytz.UTC
        ))
        self.assertEqual(r.node_id, '1048576')
        self.assertEqual(r.summary, r.generic)
        self.assertEqual(str(r), 'test|Active_rule in Advisor')
        self.assertEqual(r.likelihood, 1)

        self.assertEqual(r.total_risk, 1)
        self.assertTrue(r.has_playbook)

        # Proxy test of category and impact properties
        self.assertEqual(str(r.category), "Availability")
        self.assertEqual(str(r.impact), "Invalid Configuration(1)")

        # Proxy test of resolution properties
        self.assertEqual(r.resolution_set.all()[0].resolution_risk_name, 'Adjust Service Status')
        self.assertEqual(r.resolution_set.all()[0].resolution_risk_value, 1)
        self.assertEqual(str(r.resolution_set.all()[0].resolution_risk), 'Adjust Service Status(1)')

        # Test of reports for account?
        rq = request_object_for_testing(auth_by=RHIdentityAuthentication)
        self.assertEqual(
            # Have to do a bit of manipulation to get these into a sensible
            # format to compare, since the page does half of this hard work.
            list(r.reports_for_account(rq).order_by('host_id').values_list('host_id', flat=True)),
            [
                uuid.UUID(constants.host_01_uuid),
                uuid.UUID(constants.host_03_uuid),
                uuid.UUID(constants.host_04_uuid),
                uuid.UUID(constants.host_06_uuid),
            ]
        )

    def test_inactive_rule_properties(self):
        r = Rule.objects.get(rule_id=constants.inactive_rule)
        self.assertEqual(r.rule_id, constants.inactive_rule)
        self.assertEqual(r.description, constants.inactive_title)
        self.assertEqual(r.active, False)
        self.assertEqual(r.reboot_required, False)
        self.assertEqual(r.publish_date, datetime.datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.utc))
        self.assertEqual(r.node_id, '1048577')
        self.assertEqual(r.summary, constants.inactive_title)

    def test_deleted_rule_properties(self):
        r = Rule.objects.get(rule_id=constants.deleted_rule)
        self.assertEqual(r.rule_id, constants.deleted_rule)
        self.assertEqual(r.description, constants.deleted_title)
        self.assertEqual(r.active, False)
        self.assertEqual(r.reboot_required, False)
        self.assertEqual(r.publish_date, datetime.datetime(2018, 5, 23, 15, 38, 55, tzinfo=pytz.utc))
        self.assertEqual(r.node_id, '1048579')
        self.assertEqual(r.summary, constants.deleted_title)

    def test_other_rule_properties(self):
        second_rule = Rule.objects.get(rule_id=constants.second_rule)
        self.assertFalse(second_rule.has_playbook)

    def test_rule_relations(self):
        r = Rule.objects.get(rule_id=constants.active_rule)
        self.assertEqual(r.ruleset.description, 'Advisor')
        self.assertEqual(r.category.name, 'Availability')
        self.assertEqual(r.impact.name, 'Invalid Configuration')

        r = Rule.objects.get(rule_id=constants.acked_rule)
        self.assertEqual(r.ack_set.count(), 2)
        acks = r.ack_set.order_by('org_id')
        self.assertEqual(acks[0].org_id, '9876543')
        self.assertEqual(acks[1].org_id, '9988776')

    def test_rules_have_resolutions(self):
        # All rules in test data and elsewhere must have resolutions or else
        # they don't display properly.
        for rule in Rule.objects.all():
            self.assertTrue(
                Resolution.objects.filter(rule=rule).exists(),
                f"Each rule must have at least one resolution and rule "
                f"'{rule}' does not"
            )

    def test_rules_have_correct_total_risk(self):
        # All rules in test data and elsewhere must have the correct total
        # risk calculated.
        for rule in Rule.objects.all():
            self.assertEqual(
                rule.total_risk,
                int((rule.likelihood + rule.impact.impact) / 2),
                "The rule's total risk must be the average of its likelihood "
                f"and impact score; '{rule}' has total risk {rule.total_risk} "
                f"where likelihood is {rule.likelihood} and impact score is "
                f"{rule.impact.impact}"
            )

    def test_active_rules_have_active_Tag(self):
        for rule in Rule.objects.all():
            self.assertEqual(
                rule.active,
                rule.tags.filter(name='active').exists(),
                f"Rule {rule} has active {rule.active} but active tag presence"
                f"{rule.tags.filter(name='active').exists()} - these must be the same"
            )

    def test_rule_for_account_annotations(self):
        rq = request_object_for_testing(auth_by=RHIdentityAuthentication)
        for rule in Rule.objects.for_account(rq):
            self.assertTrue(hasattr(rule, 'reports_shown'))
            self.assertIsInstance(rule.reports_shown, bool)
            self.assertTrue(hasattr(rule, 'rule_status'))
            self.assertIsInstance(rule.rule_status, str)
            self.assertTrue(hasattr(rule, 'playbook_count'))
            # Playbook count can be None for some things - it's fixed in the
            # serializer.
            self.assertTrue(isinstance(rule.playbook_count, int) or rule.playbook_count is None)
            self.assertTrue(hasattr(rule, 'impacted_systems_count'))
            self.assertIsInstance(rule.impacted_systems_count, int)
            self.assertTrue(hasattr(rule, 'hosts_acked_count'))
            self.assertIsInstance(rule.hosts_acked_count, int)

    def test_timestamps(self):
        # Fixtures have the timestamps loaded from the data, but here we test
        # that the create and update process update the timestamps correctly.
        # So we create another rule from scratch.
        r = Rule.objects.create(
            ruleset=RuleSet.objects.get(description='Advisor'),
            rule_id="New rule",
            description="Test description",
            total_risk=1,
            active=True,
            reboot_required=False,
            publish_date='2018-05-23 15:38:55+00:00',
            impact=RuleImpact.objects.get(id=1),
            likelihood=1,
            category=RuleCategory.objects.get(id=4),
            summary="Spatulas are infesting my wardrobe",
            generic="",
            reason="",
            more_info="",
        )
        current_time = datetime.datetime.now(tz=timezone.get_current_timezone())
        self.assertGreaterEqual(r.created_at, self.test_start)
        self.assertLessEqual(r.created_at, current_time)
        self.assertGreaterEqual(r.updated_at, self.test_start)
        self.assertLessEqual(r.updated_at, current_time)
        # Not deleted yet.
        self.assertIsNone(r.deleted_at)
        create_time = r.created_at
        update_time = r.updated_at

        # Make a change to the model:
        r.reboot_required = True
        r.save()
        # and the create time should stay the same
        self.assertEqual(r.created_at, create_time)
        # but the updated time should have changed (or maybe not if no microsecond)
        self.assertGreaterEqual(r.updated_at, update_time)

    def test_paranoia(self):
        Rule.objects.create(
            ruleset=RuleSet.objects.get(description='Advisor'),
            rule_id="Very temporary rule",
            description="Test description",
            active=True,
            reboot_required=False,
            publish_date='2018-05-23 15:38:55+00:00',
            impact=RuleImpact.objects.get(id=1),
            likelihood=1,
            category=RuleCategory.objects.get(id=3),
            summary="Very temporary rule",
            generic="Very temporary rule",
            reason="",
            more_info="",
        )
        r = Rule.objects.get(rule_id='Very temporary rule')
        # Existing rule does not have a deleted time.
        self.assertIsNone(r.deleted_at)
        # Delete the rule.
        r.delete()
        # We can change something, and in our local copy it's changed,...
        r.reboot_required = True
        r.save()
        self.assertTrue(r.reboot_required)
        # However, deleted_at seems to be accurate to microseconds
        current_time = timezone.now()
        # ... but we can still find this rule!  Bamboozled again!
        r2 = Rule.objects.get(rule_id='Very temporary rule')
        self.assertEqual(r.rule_id, r2.rule_id)
        # It now has a deleted_at date...
        self.assertIsNotNone(r2.deleted_at)
        self.assertGreaterEqual(r.deleted_at, self.test_start)
        self.assertLessEqual(r.deleted_at, current_time)
        # It's been marked inactive
        self.assertFalse(r2.active)
        # and its property remains unchanged.
        self.assertFalse(r2.reboot_required)
        r2.delete()
        # Can we easily test that we can't re-delete this object, without
        # waiting a couple of seconds, deleting it and then checking that
        # the deleted_at time hasn't changed?

    def test_deleting_ruleset_deletes_all_rules(self):
        rs = RuleSet.objects.get(description='Advisor')
        rs.delete()
        # Test that if we delete a rule set, the on_cascade=DELETE property is
        # obeyed
        self.assertEqual(Rule.objects.count(), 0)
