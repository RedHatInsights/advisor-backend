# Copyright 2016-2024 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.
#
# Insights Advisor is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# Insights Advisor is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with Insights Advisor. If not, see <https://www.gnu.org/licenses/>.

import json
import os
import responses
from copy import deepcopy

from django.conf import settings
from django.test import TestCase, override_settings
from django.utils import timezone

from api.management.commands.advisor_inventory_service import (
    handle_engine_results, handle_rule_hits
)
from api.models import Ack, CurrentReport, Host, Rule, SystemType, Tag, Upload
from api.tests import constants


# Test constants
MOCK_WEBHOOK_URL = 'http://localhost:8000/api/webhooks/v1/notifications'


class AdvisorServiceEngineRuleHitsTestCase(TestCase):
    """
    Test engine results and rule hits processing for the Advisor Service.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'advisor_service_inventoryhost', 'service_test_data',
        'sample_report_rules'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Load sample data files
        test_dir = os.path.dirname(os.path.realpath(__file__))

        with open(os.path.join(test_dir, 'sample_engine_results.json')) as f:
            cls.sample_engine_results = json.load(f)

        with open(os.path.join(test_dir, 'sample_satellite_engine_results.json')) as f:
            cls.sample_satellite_engine_results = json.load(f)

        with open(os.path.join(test_dir, 'sample_rhel6_engine_results.json')) as f:
            cls.sample_rhel6_engine_results = json.load(f)

        with open(os.path.join(test_dir, 'sample_rule_hits.json')) as f:
            cls.sample_rule_hits = json.load(f)

    @responses.activate
    def test_similar_uploads(self):
        """Test that similar uploads update the same upload record."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        # Push first upload
        handle_engine_results('topic', self.sample_engine_results)
        uuid = self.sample_engine_results['input']['host']['id']
        error_key = self.sample_engine_results['results']['reports'][0]['details']['error_key']

        first_report = CurrentReport.objects.filter(
            host=uuid,
            details__error_key=error_key
        ).first()
        first_upload = first_report.upload

        # Push second upload for same system with same rule hits
        handle_engine_results('topic', self.sample_engine_results)
        second_report = CurrentReport.objects.filter(
            host=uuid,
            details__error_key=error_key
        ).first()
        second_upload = second_report.upload

        # Test the upload ids are the same but the upload times are different
        self.assertEqual(first_upload.id, second_upload.id,
                       "New upload should have same id as previous upload")
        self.assertNotEqual(first_upload.checked_on, second_upload.checked_on,
                          "New upload time should be different to previous upload time")
        # Test the report ids and impacted dates are the same
        self.assertEqual(first_report.id, second_report.id, "Report IDs should be the same")
        self.assertEqual(first_report.impacted_date, second_report.impacted_date,
                       "Report impacted_dates should be the same")
        # The second upload should be the current one
        self.assertTrue(second_upload.current)
        self.assertNotEqual(second_report.details, {}, "Details on new report shouldn't be empty")

    @responses.activate
    def test_impacted_date(self):
        """Test that impacted_date is preserved across uploads and reset when report is resolved."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        account = '477931'
        org_id = '5882103'
        host_id = '57c4c38b-a8c6-4289-9897-223681fd804d'
        other_linux_system_rule = Rule.objects.get(rule_id='other_linux_system|OTHER_LINUX_SYSTEM')

        # First upload
        handle_engine_results('topic', self.sample_engine_results)

        # Confirm a report has been generated
        cr = CurrentReport.objects.filter(
            rule=other_linux_system_rule, account=account, org_id=org_id, host_id=host_id)
        self.assertTrue(cr.exists())
        # Check its impacted date isn't None and that it's recent
        first_impacted_date = cr[0].impacted_date
        self.assertIsNotNone(first_impacted_date)
        self.assertGreater(first_impacted_date, timezone.now() - timezone.timedelta(minutes=1))

        # Second upload - impacted date should stay the same
        handle_engine_results('topic', self.sample_engine_results)
        cr = CurrentReport.objects.filter(
            rule=other_linux_system_rule, account=account, org_id=org_id, host_id=host_id)
        self.assertEqual(first_impacted_date, cr[0].impacted_date)

        # Upload with different rule - should delete the other_linux_system report
        different_engine_results = json.loads(
            json.dumps(self.sample_engine_results)
                .replace('other_linux_system', 'hardening_gpg_pubkey')
                .replace('OTHER_LINUX_SYSTEM', 'REDHAT_GPGKEY_NOT_INSTALLED')
        )
        handle_engine_results('topic', different_engine_results)
        # Confirm the other_linux_system report is gone
        self.assertFalse(CurrentReport.objects.filter(
            rule=other_linux_system_rule, account=account, org_id=org_id, host_id=host_id
        ).exists())

        # Upload the original report again - should get a new impacted date
        handle_engine_results('topic', self.sample_engine_results)
        cr = CurrentReport.objects.filter(
            rule=other_linux_system_rule, account=account, host_id=host_id)
        second_impacted_date = cr[0].impacted_date
        self.assertGreater(second_impacted_date, first_impacted_date)
        self.assertGreater(second_impacted_date, timezone.now() - timezone.timedelta(minutes=1))

    @responses.activate
    def test_autoacks_for_new_account(self):
        """Test that autoacks are created for new accounts and not for existing accounts."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        account = '477931'
        org_id = '5882103'
        other_linux_system = Rule.objects.get(rule_id='other_linux_system|OTHER_LINUX_SYSTEM')
        autoack_tag = Tag.objects.get(name=settings.AUTOACK['TAG'])
        other_linux_system.tags.add(autoack_tag)

        # Confirm account doesn't exist yet
        self.assertFalse(Upload.objects.filter(account=account, org_id=org_id).exists())
        self.assertFalse(Host.objects.filter(account=account, org_id=org_id).exists())
        self.assertFalse(Ack.objects.filter(account=account, org_id=org_id).exists())

        # Push an upload for new account - expect autoack to be created
        handle_engine_results('topic', self.sample_engine_results)
        self.assertTrue(Ack.objects.filter(
            rule=other_linux_system, account=account, org_id=org_id).exists())
        self.assertEqual(Ack.objects.get(
            rule=other_linux_system, account=account, org_id=org_id
        ).created_by, settings.AUTOACK['CREATED_BY'])

        # Remove the ack and re-upload - should NOT create autoack for existing account
        Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
        handle_engine_results('topic', self.sample_engine_results)
        self.assertFalse(Ack.objects.filter(
            rule=other_linux_system, account=account, org_id=org_id).exists())

        # Upload 2 archives for a new account - just one autoack should be created
        Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
        Host.objects.filter(account=account, org_id=org_id).delete()
        another_system = json.loads(
            json.dumps(self.sample_engine_results)
                .replace('RHIQE.d60db782-8462-410e-b0fc-f4ee97d985cb.test', 'another-system')
                .replace('57c4c38b-a8c6-4289-9897-223681fd804d',
                       '12345678-a8c6-4289-9897-223681fd804d')
        )
        handle_engine_results('topic', another_system)
        handle_engine_results('topic', self.sample_engine_results)
        self.assertEqual(Ack.objects.filter(
            rule=other_linux_system, account=account, org_id=org_id).count(), 1)
        self.assertEqual(Host.objects.filter(account=account, org_id=org_id).count(), 2)

        # Manual ack should not be replaced by autoack
        Host.objects.filter(account=account, org_id=org_id).delete()
        Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
        Ack(
            rule=other_linux_system, account=account, org_id=org_id,
            created_by="User", justification="Manual ack"
        ).save()
        handle_engine_results('topic', self.sample_engine_results)
        self.assertNotEqual(Ack.objects.get(
            rule=other_linux_system, account=account, org_id=org_id
        ).created_by, settings.AUTOACK['CREATED_BY'])

    @responses.activate
    def test_handle_engine_results(self):
        """Test basic engine results processing."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        handle_engine_results('topic', self.sample_engine_results)

        # Check host was created
        inventory_uuid = self.sample_engine_results['input']['host']['id']
        account = self.sample_engine_results['input']['host']['account']
        org_id = self.sample_engine_results['input']['platform_metadata']['org_id']
        self.assertTrue(Host.objects.filter(
            inventory_id=inventory_uuid, account=account, org_id=org_id).exists())

        # Check reports were created
        for report in self.sample_engine_results['results']['reports']:
            self.assertTrue(CurrentReport.objects.filter(
                host=inventory_uuid,
                rule__rule_id=report['rule_id']
            ).exists(), f"Report for rule hit '{report['rule_id']}' missing in DB")

        # No satellite IDs - Host should not have branch_id or satellite_id
        host = Host.objects.get(inventory_id="57c4c38b-a8c6-4289-9897-223681fd804d")
        self.assertIsNone(host.satellite_id)
        self.assertIsNone(host.branch_id)

    @responses.activate
    def test_handle_engine_results_two_sources(self):
        """Test that uploads from different sources for the same system work correctly."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        handle_engine_results('topic', self.sample_engine_results)

        # Set rule hits to same inventory ID
        rule_hits = deepcopy(self.sample_rule_hits)
        rule_hits['inventory_id'] = self.sample_engine_results['input']['host']['id']
        handle_rule_hits('topic', rule_hits)

        # Check host exists
        inventory_uuid = rule_hits['inventory_id']
        host = Host.objects.get(inventory_id=inventory_uuid)
        self.assertIsNone(host.satellite_id)
        self.assertIsNone(host.branch_id)

        # Should have two upload objects - one for each source
        client_upload = Upload.objects.get(source__name='insights-client', host_id=inventory_uuid)
        self.assertTrue(client_upload.current)
        self.assertEqual(client_upload.currentreport_set.count(), 4)

        aiops_upload = Upload.objects.get(source__name='aiops', host_id=inventory_uuid)
        self.assertTrue(aiops_upload.current)
        self.assertEqual(aiops_upload.currentreport_set.count(), 2)

    @responses.activate
    def test_satellite_handle_engine_results(self):
        """Test engine results from satellite-managed systems."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        handle_engine_results('topic', self.sample_satellite_engine_results)

        # Check host was created
        inventory_uuid = self.sample_satellite_engine_results['input']['host']['id']
        host = Host.objects.get(inventory_id=inventory_uuid)
        # Satellite system - Host should have branch_id and satellite_id
        self.assertEqual(str(host.satellite_id), "e80e58d1-d5ec-4a5a-bd37-3df104954125")
        self.assertEqual(str(host.branch_id), "bd1ddcc7-24a3-4591-bbad-30e9eae6d6ba")

    @responses.activate
    def test_handle_engine_results_bad_keys(self):
        """Test that engine results with missing keys are rejected."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        bad_input = deepcopy(self.sample_engine_results)
        bad_input['input'] = None
        self.assertFalse(handle_engine_results('topic', bad_input))

        bad_host = deepcopy(self.sample_engine_results)
        bad_host['input']['host'] = None
        self.assertFalse(handle_engine_results('topic', bad_host))

        bad_inventory = deepcopy(self.sample_engine_results)
        bad_inventory['input']['host']['id'] = None
        self.assertFalse(handle_engine_results('topic', bad_inventory))

        bad_org_id = deepcopy(self.sample_engine_results)
        bad_org_id['input']['platform_metadata']['org_id'] = None
        self.assertFalse(handle_engine_results('topic', bad_org_id))

        bad_engine_results = deepcopy(self.sample_engine_results)
        bad_engine_results['results'] = None
        self.assertFalse(handle_engine_results('topic', bad_engine_results))

        bad_engine_reports = deepcopy(self.sample_engine_results)
        bad_engine_reports['results']['reports'] = None
        self.assertFalse(handle_engine_results('topic', bad_engine_reports))

        bad_system_data = deepcopy(self.sample_engine_results)
        bad_system_data['results']['system'] = None
        self.assertFalse(handle_engine_results('topic', bad_system_data))

        bad_platform_data = deepcopy(self.sample_engine_results)
        bad_platform_data['input']['platform_metadata'] = None
        self.assertFalse(handle_engine_results('topic', bad_platform_data))

    @responses.activate
    def test_handle_rule_hits(self):
        """Test third-party rule hits processing."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        handle_rule_hits('topic', self.sample_rule_hits)

        # Check host was created
        system_id = self.sample_rule_hits['inventory_id']
        account = self.sample_rule_hits['account']
        org_id = self.sample_rule_hits['org_id']
        self.assertTrue(Host.objects.filter(
            inventory_id=system_id, account=account, org_id=org_id).exists())

        # Check reports were created
        for report in self.sample_rule_hits['hits']:
            self.assertTrue(CurrentReport.objects.filter(
                host=system_id,
                details__error_key=report['details']['error_key']
            ).exists(), f"Report for rule hit '{report['rule_id']}' missing in DB")

    def test_handle_rule_hits_missing_keys(self):
        """Test that rule hits with missing keys are rejected."""
        bad_json = {"some": "json"}
        self.assertFalse(handle_rule_hits('topic', bad_json))

    @responses.activate
    @override_settings(FILTER_OUT_NON_RHEL=False)
    def test_non_rhel_system_filtering(self):
        """Test that non-RHEL systems can be filtered."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        handle_engine_results('topic', self.sample_engine_results)

        # Check all reports were created (no filtering)
        inventory_uuid = self.sample_engine_results['input']['host']['id']
        for report in self.sample_engine_results['results']['reports']:
            self.assertTrue(CurrentReport.objects.filter(
                host=inventory_uuid,
                rule__rule_id=report['rule_id']
            ).exists())

    @responses.activate
    def test_rhel6_system_filtering(self):
        """Test that RHEL6 systems can be filtered to only show upgrade rules."""
        responses.add(responses.POST, MOCK_WEBHOOK_URL, status=200)

        # Assert there are 2 rule matches in the sample
        matched_rule_ids = [x['rule_id'] for x in self.sample_rhel6_engine_results['results']['reports']]
        self.assertEqual(len(matched_rule_ids), 2)
        self.assertIn("rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1", matched_rule_ids)
        self.assertIn("hardening_gpg_pubkey|REDHAT_GPGKEY_NOT_INSTALLED", matched_rule_ids)

        # Don't filter RHEL6 rules initially
        with override_settings(FILTER_OUT_RHEL6=False):
            handle_engine_results('topic', self.sample_rhel6_engine_results)

            host_id = self.sample_rhel6_engine_results['input']['host']['id']
            reports = CurrentReport.objects.filter(host=host_id)
            self.assertEqual(reports.count(), 2)
            self.assertTrue(reports.filter(
                rule__rule_id="rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1").exists())
            self.assertTrue(reports.filter(
                rule__rule_id="hardening_gpg_pubkey|REDHAT_GPGKEY_NOT_INSTALLED").exists())

        # Now filter for RHEL6 rules only
        with override_settings(FILTER_OUT_RHEL6=True):
            handle_engine_results('topic', self.sample_rhel6_engine_results)

            reports = CurrentReport.objects.filter(host=host_id)
            self.assertEqual(reports.count(), 1)
            self.assertTrue(reports.filter(
                rule__rule_id="rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1").exists())
            self.assertFalse(reports.filter(
                rule__rule_id="hardening_gpg_pubkey|REDHAT_GPGKEY_NOT_INSTALLED").exists())
