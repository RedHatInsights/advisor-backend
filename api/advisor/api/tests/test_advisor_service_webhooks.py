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

from django.db.models import Exists, OuterRef
from django.test import TestCase

import reports
from api.models import CurrentReport, InventoryHost, Rule


class AdvisorServiceWebhooksTestCase(TestCase):
    """
    Test webhook and report event generation for the Advisor Service.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'advisor_service_inventoryhost', 'service_test_data',
        'sample_report_rules'
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Load sample data
        test_dir = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(test_dir, 'sample_report.json')) as f:
            cls.sample_report_data = json.load(f)

    def setUp(self):
        """Clear DummyProducer state before each test."""
        super().setUp()
        if reports._producer:
            reports._producer.reset_calls()

    def test_generate_webhook_msgs_new_report(self):
        """Test that webhook messages are correctly generated for new reports."""
        inventory_uuid = "00112233-4455-6677-8899-012345678901"

        # Get new report rules
        new_report_rule_ids = ['test|Active_rule', 'test|Second_rule',
                               'test|Inactive_rule', 'test|Acked_rule']
        new_report_rules = Rule.objects.filter(rule_id__in=new_report_rule_ids).values(
            'id', 'rule_id', 'active', 'total_risk', 'description',
            'publish_date', 'reboot_required'
        ).annotate(
            has_incident=Exists(Rule.objects.filter(id=OuterRef('id'), tags__name='incident'))
        )

        # Get existing report (Second_rule)
        report_models = CurrentReport.objects.filter(rule__rule_id='test|Second_rule').values(
            'id', 'rule_id', 'rule__total_risk', 'rule__description', 'rule__publish_date',
            'rule__rule_id', 'rule__active', 'rule__reboot_required', 'rule__id'
        ).annotate(
            has_incident=Exists(Rule.objects.filter(id=OuterRef('rule'), tags__name='incident'))
        )
        cur_reports = [report_models.first()]
        host_obj = InventoryHost.objects.get(id=inventory_uuid)

        # Call trigger_report_hooks - reports._producer is already DummyProducer in tests
        reports.trigger_report_hooks(host_obj, new_report_rules, cur_reports)

        # Check poll and flush were called - both webhook and remediation events should be sent
        self.assertEqual(reports._producer.poll_calls, 2)
        self.assertEqual(reports._producer.flush_calls, 2)

        # Count the different event types
        new = 0
        resolved = 0
        remediations = 0

        for call in reports._producer.produce_calls:
            msg_obj = json.loads(call['message'].decode('utf-8'))

            if 'event_type' in msg_obj:
                if msg_obj['event_type'] == reports.NEW_REPORT_EVENT:
                    # Should be only one NEW event
                    new += 1
                    self.assertIn('account_id', msg_obj)
                    self.assertEqual(msg_obj['account_id'], '1234567')
                    self.assertIn('org_id', msg_obj)
                    self.assertEqual(msg_obj['org_id'], '9876543')
                    self.assertIn('context', msg_obj)

                    # Kafka values are strings, so decode context
                    context = json.loads(msg_obj['context'])
                    self.assertIsInstance(context, dict)
                    self.assertIn('tags', context)
                    self.assertEqual(context['tags'], [])

                    self.assertIn('events', msg_obj)
                    self.assertIsInstance(msg_obj['events'], list)
                    self.assertIsInstance(msg_obj['events'][0], dict)
                    self.assertIn('payload', msg_obj['events'][0])

                    payload = json.loads(msg_obj['events'][0]['payload'])
                    self.assertIsInstance(payload, dict)
                    self.assertIn('rule_id', payload)
                    self.assertIn('reboot_required', payload)
                    self.assertIn('has_incident', payload)
                elif msg_obj['event_type'] == reports.RESOLVED_REPORT_EVENT:
                    resolved += 1
            elif 'host_id' in msg_obj and 'issues' in msg_obj:
                # This is a remediations message
                if msg_obj['host_id'] == inventory_uuid and len(msg_obj['issues']) > 0:
                    remediations += 1

        # Assertions
        self.assertEqual(new, 1)
        self.assertEqual(resolved, 0)
        self.assertEqual(remediations, 1)

    def test_generate_webhook_msgs_resolved_report(self):
        """Test that webhook messages are correctly generated for resolved reports."""
        inventory_uuid = "00112233-4455-6677-8899-012345678901"

        # Get rules
        active_rule = Rule.objects.filter(rule_id="test|Active_rule").annotate(
            has_incident=Exists(Rule.objects.filter(id=OuterRef('id'), tags__name='incident'))
        ).first()
        inactive_rule = Rule.objects.filter(rule_id="test|Inactive_rule").annotate(
            has_incident=Exists(Rule.objects.filter(id=OuterRef('id'), tags__name='incident'))
        ).first()
        acked_rule = Rule.objects.filter(rule_id="test|Acked_rule").annotate(
            has_incident=Exists(Rule.objects.filter(id=OuterRef('id'), tags__name='incident'))
        ).first()

        # No new rules - Active_rule has been resolved
        new_rule_objs = []

        # Build current reports list
        cur_reports = [
            CurrentReport.objects.filter(rule=active_rule).values(
                'id', 'rule_id', 'rule__total_risk', 'rule__description', 'rule__publish_date',
                'rule__rule_id', 'rule__active', 'rule__reboot_required', 'rule__id', 'rule__tags'
            ).annotate(
                has_incident=Exists(Rule.objects.filter(id=OuterRef('rule'), tags__name='incident'))
            ).first(),
            # Make up dict structure for inactive and acked rules
            {
                'rule_id': inactive_rule.id,
                'rule__total_risk': inactive_rule.total_risk,
                'rule__description': inactive_rule.description,
                'rule__publish_date': inactive_rule.publish_date,
                'rule__rule_id': inactive_rule.rule_id,
                'rule__active': inactive_rule.active,
                'rule__reboot_required': inactive_rule.reboot_required,
                'rule__tags': inactive_rule.tags,
                'has_incident': inactive_rule.has_incident,
            },
            {
                'rule_id': acked_rule.id,
                'rule__total_risk': acked_rule.total_risk,
                'rule__description': acked_rule.description,
                'rule__publish_date': acked_rule.publish_date,
                'rule__rule_id': acked_rule.rule_id,
                'rule__active': acked_rule.active,
                'rule__reboot_required': acked_rule.reboot_required,
                'rule__tags': acked_rule.tags,
                'has_incident': acked_rule.has_incident,
            },
        ]
        host_obj = InventoryHost.objects.get(id=inventory_uuid)

        # Call trigger_report_hooks - reports._producer is already DummyProducer in tests
        reports.trigger_report_hooks(host_obj, new_rule_objs, cur_reports)

        # Check poll and flush were called
        self.assertEqual(reports._producer.poll_calls, 1)
        self.assertEqual(reports._producer.flush_calls, 1)

        # Count the different event types
        new = 0
        resolved = 0
        remediations = 0

        for call in reports._producer.produce_calls:
            msg_obj = json.loads(call['message'].decode('utf-8'))

            if 'event_type' in msg_obj:
                if msg_obj['event_type'] == reports.NEW_REPORT_EVENT:
                    new += 1
                elif msg_obj['event_type'] == reports.RESOLVED_REPORT_EVENT:
                    resolved += 1
                    self.assertIn('account_id', msg_obj)
                    self.assertEqual(msg_obj['account_id'], '1234567')
                    self.assertIn('org_id', msg_obj)
                    self.assertEqual(msg_obj['org_id'], '9876543')
                    self.assertIn('context', msg_obj)

                    # Kafka values are strings, so decode context
                    context = json.loads(msg_obj['context'])
                    self.assertIsInstance(context, dict)
                    self.assertIn('tags', context)
                    self.assertEqual(context['tags'], [])

                    self.assertIn('events', msg_obj)
                    self.assertIsInstance(msg_obj['events'], list)
                    self.assertIsInstance(msg_obj['events'][0], dict)
                    self.assertIn('payload', msg_obj['events'][0])

                    payload = json.loads(msg_obj['events'][0]['payload'])
                    self.assertIsInstance(payload, dict)
                    self.assertIn('rule_id', payload)
                    self.assertIn('reboot_required', payload)
                    self.assertIn('has_incident', payload)
            elif 'host_id' in msg_obj and 'issues' in msg_obj:
                # This is a remediations message
                if msg_obj['host_id'] == inventory_uuid and len(msg_obj['issues']) > 0:
                    remediations += 1

        # Assertions
        self.assertEqual(new, 0)
        self.assertEqual(resolved, 1)
        self.assertEqual(remediations, 0)
