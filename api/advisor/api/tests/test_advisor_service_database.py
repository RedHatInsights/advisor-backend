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

from unittest.mock import Mock, patch

from django.test import TestCase

from api.management.commands.advisor_inventory_service import create_db_reports
from api.models import SystemType, UploadSource


class AdvisorServiceDatabaseTestCase(TestCase):
    """
    Test database operations and error handling for the Advisor Service.

    Note: Database retry logic is handled by Django's built-in connection
    management, so we don't need to test manual retry loops.
    """
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'advisor_service_inventoryhost', 'service_test_data',
        'sample_report_rules'
    ]

    def test_db_reports_bad_upload(self):
        """Test that database failures in upload operations are handled gracefully."""
        # Get a valid system type
        system_type = SystemType.objects.first()

        # Mock UploadSource to return a valid source
        with patch.object(UploadSource.objects, 'get_or_create',
                         return_value=(Mock(name='test-source'), None)):
            # Mock Upload.objects.filter to raise an exception
            with patch('api.models.Upload.objects.filter', side_effect=Exception("AAAHHHHHHH")):
                result = create_db_reports(
                    [], '57c4c38b-a8c6-4289-9897-223681fd804d',
                    '477931', '1234567', system_type, 'blah'
                )
                self.assertFalse(result)

    def test_db_reports_bad_upload_source(self):
        """Test that None upload source is handled correctly."""
        # Get a valid system type
        system_type = SystemType.objects.first()

        # Mock get_or_create to return None, None
        with patch.object(UploadSource.objects, 'get_or_create',
                         return_value=(None, None)):
            result = create_db_reports(
                [], '57c4c38b-a8c6-4289-9897-223681fd804d',
                '477931', '1234567', system_type, 'blah'
            )
            self.assertFalse(result)

    def test_db_reports_upload_source_exception(self):
        """Test that exceptions in upload source operations are handled."""
        # Get a valid system type
        system_type = SystemType.objects.first()

        # Mock get_or_create to raise an exception
        with patch.object(UploadSource.objects, 'get_or_create',
                         side_effect=Exception("AAAHHHHHHH")):
            result = create_db_reports(
                [], '57c4c38b-a8c6-4289-9897-223681fd804d',
                '477931', '1234567', system_type, 'blah'
            )
            self.assertFalse(result)
