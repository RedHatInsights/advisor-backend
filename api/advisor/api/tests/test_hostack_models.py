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

from django.db.utils import IntegrityError
from django.test import TestCase

from api.models import HostAck, ParanoidTimestampedModel, Rule, RuleCategory, RuleImpact, RuleSet
from api.tests import constants

import datetime
import pytz


class HostAckModelTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    def test_hostack_properties(self):
        ha = HostAck.objects.get(id=1)
        self.assertEqual(ha.rule.rule_id, constants.second_rule)
        self.assertEqual(ha.account, '1234567')
        self.assertEqual(ha.org_id, '9876543')
        self.assertEqual(ha.created_at, datetime.datetime(
            2018, 5, 22, 2, 0, 51, tzinfo=pytz.UTC
        ))
        self.assertEqual(ha.updated_at, datetime.datetime(
            2018, 5, 22, 2, 0, 51, tzinfo=pytz.UTC
        ))
        self.assertEqual(str(ha), "ack for test|Second_rule in Advisor for account 1234567 "
                                  "by org 9876543 for 00112233-4455-6677-8899-012345678901")

    def test_no_duplicate_hostacks(self):
        r = Rule.objects.get(id=5)
        self.assertEqual(HostAck.objects.filter(
            rule=r, account='1234567', org_id='9876543',
            host_id=constants.host_01_uuid,
        ).count(), 1)
        ha2 = HostAck(rule=r, account='1234567', org_id='9876543', host_id=constants.host_01_uuid)
        with self.assertRaises(IntegrityError):
            ha2.save()

    def test_rule_deletion_deletes_hostack(self):
        r = Rule.objects.create(
            ruleset=RuleSet.objects.get(description='Advisor'),
            rule_id="Spatulas are infesting my wardrobe",
            description="Test description",
            total_risk=1,
            active=True,
            reboot_required=False,
            publish_date='2018-05-23 15:38:55+00:00',
            impact=RuleImpact.objects.get(id=1),
            likelihood=1,
            category=RuleCategory.objects.get(id=4),
            summary="Spatulas are infesting my wardrobe",
            generic="re",
            reason="",
            more_info="",
        )
        ha = HostAck.objects.create(rule=r,
                                    host_id=constants.host_01_uuid,
                                    account='1234567', org_id='9876543')
        # Host Ack should now exist in the database:
        self.assertEqual(HostAck.objects.filter(pk=ha.pk).count(), 1)
        # But when we delete the rule normally:
        r.delete()
        # Not only is the rule now marked as deleted (paranoid model)
        self.assertEqual(Rule.objects.filter(pk=r.pk).count(), 1)
        # And not actually deleted:
        r2 = Rule.objects.get(pk=r.pk)
        self.assertIsNotNone(r2.deleted_at)
        # But the Host Ack is not deleted because this kind of deletion doesn't cascade:
        self.assertEqual(HostAck.objects.filter(pk=ha.pk).count(), 1)

        # However, if we invoke the real true ultra delete mode on the rule:
        super(ParanoidTimestampedModel, r).delete()
        # Not only is the rule now actually deleted:
        self.assertEqual(Rule.objects.filter(pk=r.pk).count(), 0)
        # But the Host Ack is also deleted:
        self.assertEqual(HostAck.objects.filter(pk=ha.pk).count(), 0)
