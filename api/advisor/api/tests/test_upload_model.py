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

from api.models import CurrentReport, Host, Rule, Upload
from api.tests import constants, update_stale_dates

import datetime
import uuid
import pytz


class UploadTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_upload_properties(self):
        u = Upload.objects.get(id=4)
        self.assertEqual(u.host_id, uuid.UUID("00112233-4455-6677-8899-012345678901"))
        self.assertEqual(u.system_type_id, 105)
        self.assertEqual(u.account, constants.standard_acct)
        self.assertEqual(u.host.account, constants.standard_acct)
        self.assertEqual(u.checked_on, datetime.datetime(2018, 12, 4, 5, 10, 36, tzinfo=pytz.utc))

        self.assertGreater(u.currentreport_set.count(), 0)
        self.assertEqual(u.currentreport_set.count(), len(u.currentreport_set.all()))

        self.assertEqual(len(u.active_reports()), 1)

        self.assertEqual(
            str(u),
            "host 00112233-4455-6677-8899-012345678901 uploaded on 2018-12-04 05:10:36+00:00"
        )

        # Proxy test of upload source properties
        self.assertEqual(u.source.name, "insights-client")
        self.assertEqual(str(u.source), "upload source 'insights-client'")

    def test_no_duplicate_uploads(self):
        u = Upload.objects.get(id=1)
        u2 = Upload(
            # The fields that can't be the same:
            host=u.host,
            # These fields are allowed to change?
            system_type_id=19, account='1441925', source_id=1
        )
        # Current uploads can't be duplicated.  We no longer care about when
        # it was added, since that was always unique anyway.
        with self.assertRaises(IntegrityError):
            u2.save()

    def test_deleting_an_upload_deletes_its_reports(self):
        host = Host.objects.create(
            inventory_id=uuid.UUID("02132435-4657-6879-8A9B-ACBDCEDFE0F1"),
        )
        u = Upload(
            host=host, checked_on='2018-12-05T01:02:15Z',
            system_type_id=19, account='1441925', source_id=1,
        )
        u.save()
        self.assertGreater(u.id, 0)
        self.assertEqual(u.currentreport_set.count(), 0)
        r = Rule.objects.get(id=1)
        rdetails = '{"details": null}'
        rp1 = CurrentReport(
            rule=r, upload=u, details=rdetails, host=host, account='1441925'
        )
        rp1.save()
        self.assertEqual(u.currentreport_set.count(), 1)
        self.assertEqual(Upload.objects.filter(host_id=host.inventory_id, current=True).count(), 1)
        self.assertEqual(CurrentReport.objects.filter(details=rdetails).count(), 1)

        # Now delete the upload and the report should be deleted.
        u.delete()
        self.assertEqual(Upload.objects.filter(host_id=host.inventory_id, current=True).count(), 0)
        self.assertEqual(CurrentReport.objects.filter(details=rdetails).count(), 0)
        # but not the host
        self.assertEqual(Host.objects.filter(inventory_id=host.inventory_id).count(), 1)

    def test_current_upload_flag_correctness(self):
        """
        We must ensure in the test data that only the most recent upload for
        each upload source has its 'current' flag set.
        """
        for sys_uuid in Upload.objects.order_by(
            'host_id'
        ).distinct('host_id').values_list('host_id', flat=True):
            # Store the latest upload for each source; only that upload
            # should have its current flag set.
            latest_for_source = {}
            for upload in Upload.objects.filter(
                host_id=sys_uuid
            ).order_by('-checked_on'):
                if upload.source not in latest_for_source:
                    latest_for_source[upload.source] = upload
                    self.assertTrue(
                        upload.current,
                        f'Latest upload id {upload.id} for source '
                        f'{upload.source.name}, system {sys_uuid} does not '
                        f'have current flag set'
                    )
                else:
                    self.assertFalse(
                        upload.current,
                        f'Upload id {upload.id} for source '
                        f'{upload.source.name}, system {sys_uuid} is not '
                        f'latest but has current flag set'
                    )

    def test_upload_host_id_account_invariant(self):
        """
        Each system should stay consistently within one account.
        """
        for sys_uuid in Upload.objects.order_by(
            'host_id'
        ).distinct('host_id').values_list('host_id', flat=True):
            self.assertEqual(
                Upload.objects.filter(
                    host_id=sys_uuid
                ).values('account').order_by('account').distinct('account').count(),
                1,
                f'System {sys_uuid} has more than one account'
            )

    def test_upload_has_same_account_as_host(self):
        """
        Each upload should have the same account as its host.
        """
        for upload in Upload.objects.all():
            self.assertEqual(
                upload.account, upload.host.account,
                "Upload {u.host_id} has account {u.account}, host is account {u.host.account}".format(
                    u=upload
                )
            )
