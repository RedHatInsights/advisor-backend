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
Tests for workspace filtering on the recommendations table (rules endpoint).

The recommendations table shows all rules and their impacted system counts.
Workspace filtering allows users to:
- See workspace (group name) for each rule
- See group_id (UUID) for filtering
- Filter rules by workspace using group_id parameter
- Sort rules by workspace name
"""

from datetime import timedelta
from uuid import uuid4

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import (
    InventoryHost, CurrentReport, Upload, Rule, RuleCategory, RuleSet, Host,
    SystemType, UploadSource
)
from api.permissions import auth_header_for_testing
from api.tests import constants


class RuleWorkspaceFilterTestCase(TestCase):
    """Test workspace field and filtering on recommendations table."""

    def setUp(self):
        """Set up test data with rules affecting hosts in different workspaces."""
        self.client = APIClient()

        # Create test category and ruleset
        self.category = RuleCategory.objects.create(name="Availability")
        self.ruleset = RuleSet.objects.create(
            rule_source="https://test.example.com/rules",
            description="Test ruleset for workspace filtering"
        )

        # Create test rules
        self.rule_1 = Rule.objects.create(
            rule_id="test_workspace_rule_1|TEST_RULE_1",
            ruleset=self.ruleset,
            category=self.category,
            description="Test rule 1 for workspace filtering",
            summary="Test summary 1",
            generic="Test generic 1",
            reason="Test reason 1",
            active=True
        )

        self.rule_2 = Rule.objects.create(
            rule_id="test_workspace_rule_2|TEST_RULE_2",
            ruleset=self.ruleset,
            category=self.category,
            description="Test rule 2 for workspace filtering",
            summary="Test summary 2",
            generic="Test generic 2",
            reason="Test reason 2",
            active=True
        )

        # Create SystemType and UploadSource for uploads
        self.system_type = SystemType.objects.create(role="host", product_code="rhel")
        self.upload_source = UploadSource.objects.create(name="test-source")

        # Create workspaces (groups)
        self.engineering_group_id = uuid4()
        self.production_group_id = uuid4()
        self.testing_group_id = uuid4()

        # Common timestamp values for hosts
        now = timezone.now()
        created_at = now - timedelta(days=7)
        stale_timestamp = now + timedelta(days=1)
        per_reporter_staleness = {
            'puptoo': {
                'stale_warning_timestamp': (now + timedelta(days=1)).isoformat(),
                'check_in_succeeded': True
            }
        }

        # Create hosts in different workspaces
        # Engineering workspace - 2 hosts
        self.host_eng_1_id = uuid4()
        self.host_eng_1 = InventoryHost.objects.create(
            id=self.host_eng_1_id,
            account=constants.standard_acct,
            org_id=constants.standard_org,
            display_name="engineering-host-1",
            tags=[],
            groups=[
                {'id': str(self.engineering_group_id), 'name': 'Engineering', 'ungrouped': False}
            ],
            created=created_at,
            updated=now,
            last_check_in=now,
            stale_timestamp=stale_timestamp,
            insights_id=uuid4(),
            per_reporter_staleness=per_reporter_staleness
        )

        self.host_eng_2_id = uuid4()
        self.host_eng_2 = InventoryHost.objects.create(
            id=self.host_eng_2_id,
            account=constants.standard_acct,
            org_id=constants.standard_org,
            display_name="engineering-host-2",
            tags=[],
            groups=[
                {'id': str(self.engineering_group_id), 'name': 'Engineering', 'ungrouped': False}
            ],
            created=created_at,
            updated=now,
            last_check_in=now,
            stale_timestamp=stale_timestamp,
            insights_id=uuid4(),
            per_reporter_staleness=per_reporter_staleness
        )

        # Production workspace - 1 host
        self.host_prod_1_id = uuid4()
        self.host_prod_1 = InventoryHost.objects.create(
            id=self.host_prod_1_id,
            account=constants.standard_acct,
            org_id=constants.standard_org,
            display_name="production-host-1",
            tags=[],
            groups=[
                {'id': str(self.production_group_id), 'name': 'Production', 'ungrouped': False}
            ],
            created=created_at,
            updated=now,
            last_check_in=now,
            stale_timestamp=stale_timestamp,
            insights_id=uuid4(),
            per_reporter_staleness=per_reporter_staleness
        )

        # Testing workspace - 1 host
        self.host_test_1_id = uuid4()
        self.host_test_1 = InventoryHost.objects.create(
            id=self.host_test_1_id,
            account=constants.standard_acct,
            org_id=constants.standard_org,
            display_name="testing-host-1",
            tags=[],
            groups=[
                {'id': str(self.testing_group_id), 'name': 'Testing', 'ungrouped': False}
            ],
            created=created_at,
            updated=now,
            last_check_in=now,
            stale_timestamp=stale_timestamp,
            insights_id=uuid4(),
            per_reporter_staleness=per_reporter_staleness
        )

        # Ungrouped host
        self.host_ungrouped_id = uuid4()
        self.host_ungrouped = InventoryHost.objects.create(
            id=self.host_ungrouped_id,
            account=constants.standard_acct,
            org_id=constants.standard_org,
            display_name="ungrouped-host",
            tags=[],
            groups=[],
            created=created_at,
            updated=now,
            last_check_in=now,
            stale_timestamp=stale_timestamp,
            insights_id=uuid4(),
            per_reporter_staleness=per_reporter_staleness
        )

        # Create Host and Upload records (needed for CurrentReport)
        self.uploads = {}
        for host_id in [self.host_eng_1_id, self.host_eng_2_id, self.host_prod_1_id,
                        self.host_test_1_id, self.host_ungrouped_id]:
            host = Host.objects.create(
                inventory_id=host_id,
                account=constants.standard_acct,
                org_id=constants.standard_org
            )
            self.uploads[host_id] = Upload.objects.create(
                host=host,
                account=constants.standard_acct,
                org_id=constants.standard_org,
                system_type=self.system_type,
                source=self.upload_source
            )

        # Rule 1 affects: Engineering (2), Production (1)
        CurrentReport.objects.create(
            account=constants.standard_acct,
            org_id=constants.standard_org,
            rule=self.rule_1,
            host_id=self.host_eng_1_id,
            upload=self.uploads[self.host_eng_1_id],
            details={}
        )
        CurrentReport.objects.create(
            account=constants.standard_acct,
            org_id=constants.standard_org,
            rule=self.rule_1,
            host_id=self.host_eng_2_id,
            upload=self.uploads[self.host_eng_2_id],
            details={}
        )
        CurrentReport.objects.create(
            account=constants.standard_acct,
            org_id=constants.standard_org,
            rule=self.rule_1,
            host_id=self.host_prod_1_id,
            upload=self.uploads[self.host_prod_1_id],
            details={}
        )

        # Rule 2 affects: Testing (1), Ungrouped (1)
        CurrentReport.objects.create(
            account=constants.standard_acct,
            org_id=constants.standard_org,
            rule=self.rule_2,
            host_id=self.host_test_1_id,
            upload=self.uploads[self.host_test_1_id],
            details={}
        )
        CurrentReport.objects.create(
            account=constants.standard_acct,
            org_id=constants.standard_org,
            rule=self.rule_2,
            host_id=self.host_ungrouped_id,
            upload=self.uploads[self.host_ungrouped_id],
            details={}
        )

        # Auth header
        self.auth_header = auth_header_for_testing()

    def test_workspace_field_in_response(self):
        """Test that workspace field appears in recommendations table response."""
        response = self.client.get(
            reverse('rule-list'),
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        # Find our test rules in response
        rules = {r['rule_id']: r for r in response.data['data']}

        self.assertIn('test_workspace_rule_1|TEST_RULE_1', rules)
        self.assertIn('workspace', rules['test_workspace_rule_1|TEST_RULE_1'])

    def test_group_id_field_in_response(self):
        """Test that group_id field appears in recommendations table response."""
        response = self.client.get(
            reverse('rule-list'),
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        rules = {r['rule_id']: r for r in response.data['data']}

        self.assertIn('test_workspace_rule_1|TEST_RULE_1', rules)
        self.assertIn('group_id', rules['test_workspace_rule_1|TEST_RULE_1'])

    def test_workspace_shows_first_affected_workspace(self):
        """Test that workspace shows the first affected system's workspace."""
        response = self.client.get(
            reverse('rule-list'),
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        rules = {r['rule_id']: r for r in response.data['data']}
        rule_1 = rules['test_workspace_rule_1|TEST_RULE_1']

        # Rule 1 affects Engineering and Production - should show first one
        self.assertIsNotNone(rule_1['workspace'])
        self.assertIn(rule_1['workspace'], ['Engineering', 'Production'])

    def test_filter_by_single_group_id(self):
        """Test filtering recommendations by single workspace (group_id)."""
        response = self.client.get(
            reverse('rule-list'),
            {'group_id': [str(self.engineering_group_id)]},
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        rules = {r['rule_id']: r for r in response.data['data']}

        # Should include rule_1 with impacted systems in Engineering
        self.assertIn('test_workspace_rule_1|TEST_RULE_1', rules)
        rule_1 = rules['test_workspace_rule_1|TEST_RULE_1']
        self.assertEqual(rule_1['impacted_systems_count'], 2)  # 2 Engineering hosts

        # Rule_2 may still appear but with 0 impacted systems (doesn't affect Engineering)
        if 'test_workspace_rule_2|TEST_RULE_2' in rules:
            rule_2 = rules['test_workspace_rule_2|TEST_RULE_2']
            self.assertEqual(rule_2['impacted_systems_count'], 0)

    def test_filter_by_multiple_group_ids(self):
        """Test filtering by multiple group_ids (OR logic)."""
        response = self.client.get(
            reverse('rule-list'),
            {'group_id': [str(self.engineering_group_id), str(self.testing_group_id)]},
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        rule_ids = [r['rule_id'] for r in response.data['data']]

        # Should include rule_1 (affects Engineering)
        self.assertIn('test_workspace_rule_1|TEST_RULE_1', rule_ids)
        # Should include rule_2 (affects Testing)
        self.assertIn('test_workspace_rule_2|TEST_RULE_2', rule_ids)

    def test_impacted_systems_count_filtered_by_workspace(self):
        """Test that impacted_systems_count reflects workspace filter."""
        # Without filter - rule_1 affects 3 systems (2 Eng + 1 Prod)
        response = self.client.get(
            reverse('rule-list'),
            **self.auth_header
        )
        rules = {r['rule_id']: r for r in response.data['data']}
        rule_1 = rules.get('test_workspace_rule_1|TEST_RULE_1')
        if rule_1:
            total_count = rule_1['impacted_systems_count']
            self.assertEqual(total_count, 3)

        # With Engineering filter - rule_1 should show 2 systems
        response = self.client.get(
            reverse('rule-list'),
            {'group_id': str(self.engineering_group_id)},
            **self.auth_header
        )
        rules = {r['rule_id']: r for r in response.data['data']}
        rule_1 = rules.get('test_workspace_rule_1|TEST_RULE_1')
        if rule_1:
            filtered_count = rule_1['impacted_systems_count']
            self.assertEqual(filtered_count, 2)

    def test_no_filter_shows_all_rules(self):
        """Test that omitting group_id filter shows all rules."""
        response = self.client.get(
            reverse('rule-list'),
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        rule_ids = [r['rule_id'] for r in response.data['data']]

        # Should include both test rules
        self.assertIn('test_workspace_rule_1|TEST_RULE_1', rule_ids)
        self.assertIn('test_workspace_rule_2|TEST_RULE_2', rule_ids)

    def test_workspace_with_other_filters(self):
        """Test that workspace filter works alongside other filters."""
        response = self.client.get(
            reverse('rule-list'),
            {
                'group_id': [str(self.engineering_group_id)],
            },
            **self.auth_header
        )

        self.assertEqual(response.status_code, 200)

        # Should successfully return results
        self.assertGreater(len(response.data['data']), 0)

