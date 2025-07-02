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

from api.models import CurrentReport, Rule, Upload
from api.tests import constants

import datetime
import uuid
from django.db.utils import IntegrityError
from django.utils import timezone
import pytz

# Create your tests here.


class ReportTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'host_tag_test_data',
    ]

    def test_currentreport_properties(self):
        rp = CurrentReport.objects.get(id=8)
        self.assertEqual(rp.rule.id, 1)
        self.assertEqual(rp.upload.host_id, uuid.UUID(constants.host_01_uuid))
        self.assertEqual(rp.upload.system_type_id, 105)
        self.assertEqual(rp.upload.account, "1234567")
        self.assertIsInstance(rp.details, dict)
        self.assertIn('error_key', rp.details)
        self.assertEqual(rp.details['error_key'], "ACTIVE_RULE")
        self.assertEqual(rp.upload.checked_on, datetime.datetime(
            2018, 12, 4, 5, 10, 36,
            tzinfo=pytz.UTC
        ))
        self.assertEqual(str(rp), "current report of test|Active_rule in upload 4")
        self.assertEqual(rp.impacted_date, datetime.datetime(2018, 12, 4, 5, 10, 36, tzinfo=pytz.UTC))

        # Check properties for a current report with impacted_date set to now()
        rp = CurrentReport.objects.get(id=20)
        self.assertEqual(rp.rule.id, 5)
        self.assertAlmostEqual(rp.impacted_date, timezone.now(), delta=timezone.timedelta(minutes=1))

    def test_report_methods(self):
        rp = CurrentReport.objects.get(id=4)
        self.assertEqual(rp.resolution.id, 1)
        self.assertEqual(rp.resolution.rule_id, 1)
        self.assertEqual(rp.resolution.system_type_id, 105)
        self.assertEqual(
            rp.resolution.resolution,
            "In order to fix this problem, {{=pydata.active}} must equal **bar**"
        )
        self.assertEqual(rp.resolution.resolution_risk_id, 1)

        # Test look-up of resolution where there isn't a resolution for this
        # upload's system type - defaults to getting the rhel/host resolution.
        s4r1 = CurrentReport.objects.get(id=11)
        self.assertEqual(s4r1.upload.system_type_id, 89)
        self.assertEqual(s4r1.resolution.system_type_id, 105)
        # But a rule which is the same system type can also be found.
        s4r5 = CurrentReport.objects.get(id=12)
        self.assertEqual(s4r5.upload.system_type_id, 89)
        self.assertEqual(s4r5.resolution.system_type_id, 89)

    def test_report_deletion(self):
        # Test that if we delete this report, the upload and rule that it
        # referred to are not deleted.
        u = Upload.objects.get(id=1)
        r = Rule.objects.get(id=6)
        # Assert we don't have an existing report of that rule in the upload
        self.assertEqual(u.currentreport_set.filter(rule=r).count(), 0)
        # Create a new report for it
        rp = CurrentReport.objects.create(
            rule=r, upload=u,
            host_id=u.host_id,
            account="1234567",
            details={"error_key": "BAR", "data": {"baz": "boing"}},
        )
        self.assertEqual(rp.rule.id, r.id)
        self.assertEqual(rp.upload, u)
        # Now delete the report...
        rp.delete()
        # And we should not be able to find it...
        self.assertEqual(
            CurrentReport.objects.filter(rule=r, upload=u).count(),
            0,
            "If we delete a report, it should no longer exist"
        )
        # But we should be able to find the rule...
        self.assertEqual(
            Rule.objects.filter(id=r.id).count(), 1,
            "If we delete a report, the rule it's based on should not be deleted"
        )
        self.assertEqual(
            Upload.objects.filter(id=u.id).count(), 1,
            "If we delete a report, the upload it refers to should not be deleted"
        )

    def test_no_duplicate_reports(self):
        u = Upload.objects.get(id=1)
        r = Rule.objects.get(id=6)
        # Assert we don't have an existing report of that rule in the upload
        self.assertEqual(u.currentreport_set.filter(rule=r).count(), 0)

        rp = CurrentReport.objects.create(
            rule=r, upload=u,
            host_id=u.host_id,
            account="1234567",
            details={"error_key": "BAR", "data": {"baz": "boing"}},
        )
        self.assertEqual(rp.rule, r)
        rp2 = CurrentReport(
            rule=r, upload=u,
            host_id=u.host_id,
            account="1234567",
            details={"error_key": "BAR", "data": {"baz": "boing2"}},
        )
        with self.assertRaises(IntegrityError):
            rp2.save()

    def test_current_reports_in_current_uploads(self):
        # Just as a note here: the historic report data matching each current
        # report does not appear in the basic test data because it's created
        # automatically by the trigger.
        for crpt in CurrentReport.objects.all():
            self.assertTrue(
                crpt.upload.current,
                f"Current report {crpt.id} linked to upload {crpt.upload.id} which has current flag False"
            )

    def test_current_reports_match_upload_data(self):
        # Make sure that the system_uuid and account matches between
        # current reports and their related uploads
        for crpt in CurrentReport.objects.all():
            self.assertEqual(crpt.account, crpt.upload.account)
            self.assertEqual(crpt.host_id, crpt.upload.host_id)
