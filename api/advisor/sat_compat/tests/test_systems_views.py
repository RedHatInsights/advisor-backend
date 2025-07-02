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

from datetime import timedelta
import responses
from uuid import UUID

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from rest_framework.serializers import CharField

from api.models import Host, InventoryHost
from api.tests import constants, update_stale_dates
from api.permissions import auth_header_for_testing
from sat_compat.serializers import LabelSerializer
from sat_compat.views.systems import sort_fields

INVENTORY_SERVER_URL = 'http://localhost:8090'
non_interp_warning = "Warning: this content is not able to be interpolated"


class SystemViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data',
    ]
    systems_data = [{
        'toString': constants.host_01_name,
        'isCheckingIn': True,
        'system_id': constants.host_01_inid,
        'display_name': constants.host_01_name,
        'account_number': '1234567',
        'org_id': '9876543',
        'hostname': constants.host_01_name,
        'last_check_in': '2018-12-04T05:15:38Z',
        'created_at': '2020-01-01T06:00:00Z',
        'system_type_id': 105,
        'role': 'host',
        'product_code': 'rhel',
        'report_count': 1,
        'remote_branch': constants.remote_branch_lc,
        'remote_leaf': constants.host_01_said,
    }, {
        'toString': constants.host_03_name,
        'isCheckingIn': True,
        'system_id': constants.host_03_inid,
        'display_name': constants.host_03_name,
        'account_number': '1234567',
        'org_id': '9876543',
        'hostname': constants.host_03_name,
        'last_check_in': '2018-09-22T02:00:51Z',
        'created_at': '2020-01-01T06:00:00Z',
        'system_type_id': 105,
        'role': 'host',
        'product_code': 'rhel',
        'report_count': 2,
        'remote_branch': constants.remote_branch_lc,
        'remote_leaf': constants.host_03_said,
    }, {
        'toString': constants.host_04_name,
        'isCheckingIn': True,
        'system_id': constants.host_04_inid,
        'display_name': constants.host_04_name,
        'account_number': '1234567',
        'org_id': '9876543',
        'hostname': constants.host_04_name,
        'last_check_in': '2018-12-10T23:32:13Z',
        'created_at': '2020-01-01T06:00:00Z',
        'system_type_id': 89,
        'role': 'manager',
        'product_code': 'rhev',
        'report_count': 2,
        'remote_branch': None,
        'remote_leaf': None,
    }, {
        'toString': constants.host_05_name,
        'isCheckingIn': True,
        'system_id': constants.host_05_inid,
        'display_name': constants.host_05_name,
        'account_number': '1234567',
        'org_id': '9876543',
        'hostname': constants.host_05_name,
        'last_check_in': '2018-12-10T23:32:15Z',
        'created_at': '2020-01-01T06:00:00Z',
        'system_type_id': 105,
        'role': 'host',
        'product_code': 'rhel',
        'report_count': 0,
        'remote_branch': constants.remote_branch_lc,
        'remote_leaf': constants.host_05_said,
    }, {
        'toString': constants.host_06_name,
        'isCheckingIn': False,
        'system_id': constants.host_06_inid,
        'display_name': constants.host_06_name,
        'account_number': '1234567',
        'org_id': '9876543',
        'hostname': constants.host_06_name,
        'last_check_in': '2019-04-05T14:30:00Z',
        'created_at': '2020-01-01T06:00:00Z',
        'system_type_id': 105,
        'role': 'host',
        'product_code': 'rhel',
        'report_count': 1,
        'remote_branch': None,
        'remote_leaf': None,
    }]
    # Note: data has no `updated_at` because it's changed by update_stale_dates
    # - everything else should be stable enough to compare.
    fields_to_check = sorted(systems_data[0].keys())

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _response_is_good(self, response):
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertIn('resources', json)
        self.assertIsInstance(json['resources'], list)
        self.assertIn('total', json)
        self.assertIsInstance(json['total'], int)
        for system in json['resources']:
            self.assertIn('isCheckingIn', system)
            self.assertIn('isCheckingIn', system)
            self.assertIsInstance(system['isCheckingIn'], bool)
            self.assertIn('display_name', system)
            self.assertEqual(
                system['isCheckingIn'],
                not ('stale' in system['display_name'] or 'culled' in system['display_name'])
            )
        return json['resources']

    def _compare_rows(self, systems_view, row_order):
        """
        Compare the rows returned by the view with the rows of data we
        expect to see, in a given order.  The row number, starting from zero,
        of each row in the expected data is listed in `row_order`.
        """
        self.assertEqual(
            len(systems_view), len(row_order),
            f"Systems list should have {len(row_order)} rows, not {len(systems_view)}"
        )
        for view_row, data_row in enumerate(row_order):
            for field in self.fields_to_check:
                self.assertEqual(
                    systems_view[view_row][field], self.systems_data[data_row][field],
                    f"Field '{field}' in for {systems_view[view_row]['display_name']} view row {view_row} / data row {data_row} did not match"
                )

    def test_list_systems(self):
        response = self.client.get(
            reverse('sat-compat-systems-list'), **auth_header_for_testing()
        )
        systems = self._response_is_good(response)

        self.assertIsInstance(systems, list)
        # Systems in display name order
        self._compare_rows(systems, (4, 0, 1, 2, 3))

        # Test sorting field - default direction
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'sort_by': 'system_id'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in UUID order
        self._compare_rows(systems, (0, 1, 2, 3, 4))

        # Test sorting - reverse direction
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'sort_dir': 'DESC'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in reverse name order
        self._compare_rows(systems, (3, 2, 1, 0, 4))

        # Test sorting - field and direction
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'sort_by': 'report_count', 'sort_dir': 'DESC'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in descending hits order
        self._compare_rows(systems, (1, 2, 0, 4, 3))

        # Test pagination (from zero)
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'page': '0', 'page_size': '2'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display name order
        self._compare_rows(systems, (4, 0))
        # Non-zero pages
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'page': '1', 'page_size': '2'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display name order
        self._compare_rows(systems, (1, 2, ))

        # Test query of branch ID
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Satellite systems 1, 3, 5:
        self._compare_rows(systems, (0, 1, 3))

    def test_list_bad_branch_id(self):
        # Test query of branch ID
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'branch_id': constants.host_01_name},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 400, response.content.decode())

    def test_list_systems_sort_options(self):
        for sort_field in sort_fields:
            params = {'sort_by': sort_field}
            for sort_dir in ('ASC', 'DESC', None):
                if sort_dir:
                    params['sort_dir'] = sort_dir
                response = self.client.get(
                    reverse('sat-compat-systems-list'), data=params,
                    **auth_header_for_testing()
                )
                systems = self._response_is_good(response)
                self.assertIsInstance(systems, list)

    def test_list_systems_offline_filter(self):
        # All the stale systems aren't owned by a Satellite, so we need to
        # change one so it is...
        Host.objects.filter(
            inventory_id__in=(
                constants.host_06_uuid, constants.host_08_uuid,
                constants.host_0a_uuid
            ),
        ).update(
            satellite_id="AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE06",
            branch_id=constants.remote_branch_uc,
        )

        # Systems that aren't reporting in:
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'offline': 'true'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Not a system we cover in our normal test data...
        self.assertEqual(systems[0]['toString'], constants.host_06_name)
        self.assertEqual(systems[0]['isCheckingIn'], False)
        self.assertEqual(systems[0]['unregistered_at'], None)  # Not unregistered yet

        # Systems that are reporting in:
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'offline': 'false'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display_name order by default
        self._compare_rows(systems, (0, 1, 2, 3))

    def test_list_systems_unregistered_at(self):
        # All the stale systems aren't owned by a Satellite, so we need to
        # change one so it is...
        Host.objects.filter(
            inventory_id=constants.host_06_uuid
        ).update(
            satellite_id="AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE06",
            branch_id=constants.remote_branch_uc,
        )
        # And make this show up as 'culled' and give it a culled date (since
        # this happens after update_stale_dates()
        stale_host = InventoryHost.objects.get(id=constants.host_06_uuid)
        stale_host.display_name = 'culled.example.com'
        prs = stale_host.per_reporter_staleness
        # Have to modify the per-reporter staleness structure and then put it
        # back, we can't modify it in situ using an update.
        prs['puptoo']['stale_timestamp'] = str(timezone.now() - timedelta(days=24))
        prs['puptoo']['stale_warning_timestamp'] = str(timezone.now() - timedelta(days=17))
        prs['puptoo']['culled_timestamp'] = str(timezone.now() - timedelta(days=3))
        stale_host.per_reporter_staleness = prs
        stale_host.save()

        # Since that system is now being hidden, we don't see it
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'search_term': 'culled'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertEqual(systems, [])

    def test_list_systems_report_count_filter(self):
        # Systems that aren't reporting in:
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'report_count': 'gt0'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display_name order by default
        self._compare_rows(systems, (4, 0, 1, 2))

        # Systems that are reporting in:
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'report_count': 'lt1'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display_name order by default
        self._compare_rows(systems, (3, ))

    def test_list_systems_name_filter(self):
        # Systems filtered by name
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'search_term': '01'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        self._compare_rows(systems, (0, ))
        # Name matching but stale - not included
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'search_term': 'stale'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        self._compare_rows(systems, (4, ))

    def test_list_systems_cert_auth(self):
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display name order
        self._compare_rows(systems, (0, 1, 3))

    def test_list_systems_for_rule(self):
        # Systems impacted by a rule
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'rule': constants.active_rule},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Systems in display_name order by default
        self._compare_rows(systems, (4, 0, 1, 2))

        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'rule': constants.acked_rule, 'sort_by': 'report_count'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        # Acked rules don't show their reports, so systems are in UUID order
        self._compare_rows(systems, (0, ))

        # Nonexistent rule simply shows no systems affected
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'rule': 'nonexistent_rule'},
            **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        self.assertEqual(systems, [])

    def test_systems_detail(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json['toString'], constants.host_01_name)
        self.assertEqual(json['isCheckingIn'], True)
        self.assertEqual(json['system_id'], constants.host_01_inid)
        self.assertEqual(json['display_name'], constants.host_01_name)
        self.assertEqual(json['account_number'], '1234567')
        self.assertEqual(json['org_id'], '9876543')
        self.assertEqual(json['hostname'], constants.host_01_name)
        self.assertEqual(json['last_check_in'], '2018-12-04T05:15:38Z')
        self.assertEqual(json['system_type_id'], 105)
        self.assertEqual(json['role'], 'host')
        self.assertEqual(json['product_code'], 'rhel')
        self.assertEqual(json['report_count'], 1)
        self.assertIn('acks', json)
        # Now simplified
        self.assertEqual(json['acks'], [])

        # Request with branch ID should work
        response = self.client.get(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': constants.host_01_inid},
            ),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json['toString'], constants.host_01_name)
        self.assertEqual(json['isCheckingIn'], True)
        self.assertEqual(json['system_id'], constants.host_01_inid)
        self.assertEqual(json['display_name'], constants.host_01_name)
        self.assertEqual(json['account_number'], '1234567')
        self.assertEqual(json['org_id'], '9876543')
        self.assertEqual(json['hostname'], constants.host_01_name)
        self.assertEqual(json['last_check_in'], '2018-12-04T05:15:38Z')
        self.assertEqual(json['system_type_id'], 105)
        self.assertEqual(json['role'], 'host')
        self.assertEqual(json['product_code'], 'rhel')
        self.assertEqual(json['report_count'], 1)
        self.assertIn('acks', json)
        # Now simplified
        self.assertEqual(json['acks'], [])

        # Request with different branch ID should get a 404
        response = self.client.get(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': constants.host_01_inid},
            ),
            data={'branch_id': constants.missing_branch},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    def test_systems_groups(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-groups',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json, [])

        # Host not in this account gets a 404
        response = self.client.get(
            reverse(
                'sat-compat-systems-groups',
                kwargs={'uuid': constants.host_02_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404, response.content.decode())

        # Cert auth for a Satellite requesting another host gets the host
        response = self.client.get(
            reverse(
                'sat-compat-systems-groups',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing(system_opts=constants.host_03_system_data)
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json, [])

    def test_systems_reports(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-reports',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json['toString'], constants.host_01_name)
        self.assertEqual(json['isCheckingIn'], True)
        self.assertEqual(json['system_id'], constants.host_01_inid)
        self.assertEqual(json['display_name'], constants.host_01_name)
        self.assertEqual(json['account_number'], constants.standard_acct)
        self.assertEqual(json['org_id'], constants.standard_org)
        self.assertEqual(json['hostname'], constants.host_01_name)
        self.assertEqual(json['last_check_in'], '2018-12-04T05:15:38Z')
        self.assertEqual(json['system_type_id'], 105)
        self.assertEqual(json['role'], 'host')
        self.assertEqual(json['product_code'], 'rhel')
        self.assertIsInstance(json['reports'], list)
        self.assertEqual(len(json['reports']), 1)
        report = json['reports'][0]
        self.assertIsInstance(report, dict)
        self.assertIn('details', report)
        self.assertIsInstance(report['details'], dict)
        self.assertIn('id', report)
        self.assertEqual(report['id'], 8)
        self.assertIn('rule_id', report)
        self.assertEqual(report['rule_id'], constants.active_rule)
        self.assertIn('system_id', report)
        self.assertEqual(report['system_id'], constants.host_01_inid)
        self.assertIn('account_number', report)
        self.assertEqual(report['account_number'], constants.standard_acct)
        self.assertIn('org_id', report)
        self.assertEqual(report['org_id'], constants.standard_org)
        self.assertIn('date', report)
        self.assertEqual(report['date'], '2018-12-04T05:10:36Z')
        self.assertIn('rule', report)
        self.assertIsInstance(report['rule'], dict)
        self.assertIn('reason', report['rule'])
        self.assertEqual(report['rule']['generic'], non_interp_warning)
        self.assertEqual(report['rule']['reason'], non_interp_warning)
        self.assertEqual(report['rule']['resolution'], non_interp_warning)
        self.assertEqual(report['rule']['more_info'], non_interp_warning)

        # Check a system with two reports, to check ordering
        response = self.client.get(
            reverse(
                'sat-compat-systems-reports',
                kwargs={'uuid': constants.host_03_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json['toString'], constants.host_03_name)
        self.assertEqual(json['isCheckingIn'], True)
        self.assertEqual(json['system_id'], constants.host_03_inid)
        self.assertEqual(json['display_name'], constants.host_03_name)
        self.assertEqual(json['account_number'], '1234567')
        self.assertEqual(json['org_id'], '9876543')
        self.assertEqual(json['hostname'], constants.host_03_name)
        self.assertEqual(json['last_check_in'], '2018-09-22T02:00:51Z')
        self.assertEqual(json['system_type_id'], 105)
        self.assertEqual(json['role'], 'host')
        self.assertEqual(json['product_code'], 'rhel')
        self.assertIsInstance(json['reports'], list)
        self.assertEqual(len(json['reports']), 2)
        report = json['reports'][0]
        self.assertIsInstance(report, dict)
        self.assertIn('details', report)
        self.assertIsInstance(report['details'], dict)
        self.assertIn('id', report)
        self.assertEqual(report['id'], 17)
        self.assertIn('rule_id', report)
        self.assertEqual(report['rule_id'], constants.active_rule)
        self.assertIn('system_id', report)
        self.assertEqual(report['system_id'], constants.host_03_inid)
        self.assertIn('account_number', report)
        self.assertEqual(report['account_number'], constants.standard_acct)
        self.assertIn('org_id', report)
        self.assertEqual(report['org_id'], constants.standard_org)
        self.assertIn('date', report)
        self.assertEqual(report['date'], '2018-09-22T02:00:51Z')
        self.assertIn('rule', report)
        self.assertIsInstance(report['rule'], dict)
        self.assertEqual(report['rule']['reason'], non_interp_warning)
        self.assertEqual(report['rule']['resolution'], non_interp_warning)
        self.assertEqual(report['rule']['more_info'], non_interp_warning)
        report = json['reports'][1]
        self.assertIsInstance(report, dict)
        self.assertIn('details', report)
        self.assertIsInstance(report['details'], dict)
        self.assertIn('id', report)
        self.assertEqual(report['id'], 7)
        self.assertIn('rule_id', report)
        self.assertEqual(report['rule_id'], constants.second_rule)
        self.assertIn('system_id', report)
        self.assertEqual(report['system_id'], constants.host_03_inid)
        self.assertIn('account_number', report)
        self.assertEqual(report['account_number'], constants.standard_acct)
        self.assertIn('org_id', report)
        self.assertEqual(report['org_id'], constants.standard_org)
        self.assertIn('date', report)
        self.assertEqual(report['date'], '2018-09-22T02:00:51Z')
        self.assertIn('rule', report)
        self.assertIsInstance(report['rule'], dict)
        self.assertEqual(report['rule']['reason'], non_interp_warning)
        self.assertEqual(report['rule']['resolution'], non_interp_warning)
        self.assertEqual(report['rule']['more_info'], non_interp_warning)

        # Request with branch ID should work
        response = self.client.get(
            reverse(
                'sat-compat-systems-reports',
                kwargs={'uuid': constants.host_01_inid},
            ),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        self.assertEqual(json['toString'], constants.host_01_name)
        self.assertEqual(json['isCheckingIn'], True)
        self.assertEqual(json['system_id'], constants.host_01_inid)
        self.assertEqual(json['display_name'], constants.host_01_name)
        self.assertEqual(json['account_number'], '1234567')
        self.assertEqual(json['org_id'], '9876543')
        self.assertEqual(json['hostname'], constants.host_01_name)
        self.assertEqual(json['last_check_in'], '2018-12-04T05:15:38Z')
        self.assertEqual(json['system_type_id'], 105)
        self.assertEqual(json['role'], 'host')
        self.assertEqual(json['product_code'], 'rhel')
        self.assertIsInstance(json['reports'], list)
        self.assertEqual(len(json['reports']), 1)
        for report in json['reports']:
            self.assertIsInstance(report, dict)
            self.assertIn('details', report)
            self.assertIsInstance(report['details'], dict)
            self.assertIn('id', report)
            self.assertIsInstance(report['id'], int)
            self.assertIn('rule_id', report)
            self.assertIsInstance(report['rule_id'], str)
            self.assertIn('system_id', report)
            self.assertIsInstance(report['system_id'], str)
            self.assertIn('account_number', report)
            self.assertIsInstance(report['account_number'], str)
            self.assertIn('org_id', report)
            self.assertIsInstance(report['org_id'], str)
            self.assertIn('date', report)
            self.assertIsInstance(report['date'], str)
            self.assertIn('rule', report)
            self.assertIsInstance(report['rule'], dict)

        # Request with different branch ID should get a 404
        response = self.client.get(
            reverse(
                'sat-compat-systems-reports',
                kwargs={'uuid': constants.host_01_inid},
            ),
            data={'branch_id': constants.missing_branch},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    def test_systems_metadata(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-metadata',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        # Physical machine data
        self.assertEqual(json['release'], 'Red Hat Enterprise Linux release 7.5 (Maipo)')
        self.assertEqual(json['rhel_version'], '7.5')
        self.assertEqual(json['system_information.family'], 'Red Hat Enterprise Linux')
        self.assertNotIn('system_information.virtual_machine', json)
        self.assertEqual(json['bios_information.release_date'], '13/06/2017')
        self.assertEqual(json['bios_information.vendor'], 'Dell Inc.')
        self.assertEqual(json['bios_information.version'], '2.8.0')

        # Request with branch ID should work
        response = self.client.get(
            reverse(
                'sat-compat-systems-metadata',
                kwargs={'uuid': constants.host_03_inid},
            ),
            data={'branch_id': constants.remote_branch_uc},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        json = response.json()
        # Virtual machine data
        self.assertEqual(json['release'], 'Red Hat Enterprise Linux release 7.5 (Maipo)')
        self.assertEqual(json['rhel_version'], '7.5')
        self.assertEqual(json['system_information.family'], 'Red Hat Enterprise Linux')
        self.assertEqual(json['system_information.virtual_machine'], '1')
        self.assertEqual(json['bios_information.release_date'], '01/01/2011')
        self.assertEqual(json['bios_information.vendor'], 'innotek Gmbh')
        self.assertEqual(json['bios_information.version'], 'Virtualbox')

        # Request with different branch ID should get a 404
        response = self.client.get(
            reverse(
                'sat-compat-systems-metadata',
                kwargs={'uuid': constants.host_01_inid},
            ),
            data={'branch_id': constants.missing_branch},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    def test_bad_labelserializer(self):
        """
        Tests for completeness of the LabelSerializer class, including how
        it handles null values.
        """
        class TestNoLabelField(LabelSerializer):
            unlabeled = CharField(required=False, allow_null=True)

        # Test outgoing serialization:
        # No data at all
        serdata = TestNoLabelField({})
        self.assertEqual(serdata.data, dict())
        # No data for the 'unlabeled' field
        serdata = TestNoLabelField({'labeled': 'Very yes'})
        self.assertEqual(serdata.data, dict())
        # A field explicitly with the value None
        serdata = TestNoLabelField({'unlabeled': None})
        self.assertEqual(serdata.data, dict())
        # A field with any other value, including 'None'
        serdata = TestNoLabelField({'unlabeled': 'None'})
        self.assertEqual(serdata.data, {'Unlabeled': 'None'})

        # Test incoming serializations:
        # No data at all
        serdata = TestNoLabelField(data={})
        serdata.is_valid(raise_exception=True)
        self.assertEqual(serdata.validated_data, dict())
        # No data for the 'unlabeled field'
        serdata = TestNoLabelField(data={'labeled': 'Very yes'})
        serdata.is_valid(raise_exception=True)
        self.assertEqual(serdata.validated_data, dict())
        # None as the value for the field
        serdata = TestNoLabelField(data={'unlabeled': None})
        serdata.is_valid(raise_exception=True)
        # Note field name here, not label
        self.assertEqual(serdata.validated_data, {'unlabeled': None})
        # 'None' as the value for the field
        serdata = TestNoLabelField(data={'unlabeled': 'None'})
        serdata.is_valid(raise_exception=True)
        self.assertEqual(serdata.validated_data, {'unlabeled': 'None'})

    def test_systems_links(self):
        # Links give an empty list
        response = self.client.get(
            reverse(
                'sat-compat-systems-links',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200)
        json = response.json()
        self.assertEqual(json, {'total': 0, 'resources': []})

        # But we still get a 404 for a nonexistent system
        response = self.client.get(
            reverse(
                'sat-compat-systems-links',
                kwargs={'uuid': constants.host_ht_01_uuid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)
        # Or a system not in our account
        response = self.client.get(
            reverse(
                'sat-compat-systems-links',
                kwargs={'uuid': constants.host_02_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    def test_systems_register(self):
        # Register an existing system that hasn't previously registered as a
        # Satellite managed host.
        response = self.client.post(
            reverse('sat-compat-v1-systems-list'),
            data={
                'machine_id': constants.host_04_inid,
                'remote_branch': constants.remote_branch_lc,
                'remote_leaf': "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE04",
                'hostname': constants.host_04_name,
            },
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 201, response.content.decode())
        reg_data = response.json()
        # Data returned is same as given
        self.assertIn('hostname', reg_data)
        self.assertEqual(reg_data['hostname'], constants.host_04_name)
        self.assertIn('machine_id', reg_data)
        self.assertEqual(reg_data['machine_id'], constants.host_04_inid)
        self.assertIn('remote_branch', reg_data)
        self.assertEqual(reg_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('remote_leaf', reg_data)
        self.assertEqual(reg_data['remote_leaf'], "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE04")

        # Register a brand new system, with branch_id parameter (different
        # case to check comparison modes).
        response = self.client.post(
            reverse('sat-compat-v1-systems-list') + '?branch_id=' + constants.remote_branch_uc,
            data={
                'machine_id': '00112233-4455-6677-8899-01234567890B',
                'remote_branch': constants.remote_branch_lc,
                'remote_leaf': "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE0B",
                'hostname': 'system11.example.com',
            },
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 201, response.content.decode())
        reg_data = response.json()
        # Data returned is same as given
        self.assertIn('hostname', reg_data)
        self.assertEqual(reg_data['hostname'], 'system11.example.com')
        self.assertIn('machine_id', reg_data)
        self.assertEqual(reg_data['machine_id'], '00112233-4455-6677-8899-01234567890B')
        self.assertIn('remote_branch', reg_data)
        self.assertEqual(reg_data['remote_branch'], constants.remote_branch_lc)
        self.assertIn('remote_leaf', reg_data)
        self.assertEqual(reg_data['remote_leaf'], "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE0B")

        # However, these hosts should NOT show up in the hosts list, because
        # they only exist when they process an upload.
        response = self.client.get(
            reverse('sat-compat-systems-list'), **auth_header_for_testing()
        )
        systems = self._response_is_good(response)
        self.assertIsInstance(systems, list)
        self._compare_rows(systems, (4, 0, 1, 2, 3))

        # Failure mode - not supported in v3
        response = self.client.post(
            reverse('sat-compat-systems-list'),
            data={
                'machine_id': constants.host_04_inid,
                'remote_branch': constants.remote_branch_lc,
                'remote_leaf': "AABBCCDD-EEFF-FFEE-DDCC-AABBCCDDEE04",
                'hostname': constants.host_04_name,
            },
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 405, response.content.decode())

        # Apparently '-1' is used as a valid branch and leaf
        response = self.client.post(
            reverse('sat-compat-v1-systems-list'),
            data={
                'machine_id': constants.host_04_inid,
                'remote_branch': '-1',
                'remote_leaf': -1,
                'hostname': constants.host_04_name,
            },
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 201, response.content.decode())
        reg_data = response.json()
        # Data returned is same as given
        self.assertIn('hostname', reg_data)
        self.assertEqual(reg_data['hostname'], constants.host_04_name)
        self.assertIn('machine_id', reg_data)
        self.assertEqual(reg_data['machine_id'], constants.host_04_inid)
        self.assertIn('remote_branch', reg_data)
        self.assertEqual(reg_data['remote_branch'], '-1')
        self.assertIn('remote_leaf', reg_data)
        self.assertEqual(reg_data['remote_leaf'], '-1')

    def test_systems_unregister(self):
        response = self.client.delete(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 204, response.content.decode())
        # And now the system shouldn't be in the list
        response = self.client.get(
            reverse('sat-compat-systems-list'), **auth_header_for_testing()
        )
        systems = self._response_is_good(response)

        self.assertIsInstance(systems, list)
        # Systems in display name order
        self._compare_rows(systems, (4, 1, 2, 3))

        # Unknown host
        response = self.client.delete(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': '00112233-4455-6677-8899-0123456789FF'},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 404)

    @override_settings(INVENTORY_SERVER_URL=INVENTORY_SERVER_URL)
    @responses.activate
    def test_systems_delete(self):
        responses.add(
            responses.DELETE, INVENTORY_SERVER_URL + '/hosts/' + constants.host_01_uuid,
            status=204
        )

        response = self.client.delete(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid}
            ),
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 204)

    @override_settings(INVENTORY_SERVER_URL=INVENTORY_SERVER_URL)
    @responses.activate
    def test_systems_rename(self):
        # Remember that these methods are the ones the view code uses to
        # make the request of the inventory, not the ones we make of the view.
        # And remember, these Inventory responses are for the Inventory UUIDs,
        # NOT the Insights IDs.
        responses.add(
            responses.PATCH, INVENTORY_SERVER_URL + '/hosts/' + constants.host_01_uuid,
            body='{"display_name": "foo.bar.baz"}',
            status=200
        )
        responses.add(
            responses.PATCH, INVENTORY_SERVER_URL + '/hosts/00112233-4455-6677-8899-0123456789FF',
            status=404
        )

        # Clients can rename themselves
        response = self.client.put(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid}  # Insights ID
            ),
            data={
                'display_name': 'foo.bar.baz',
            },
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 200, response.content.decode())

        # Unknown client gets a 200
        response = self.client.put(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': '00112233-4455-6677-8899-0123456789FF'}
            ),
            data={
                'display_name': 'foo.bar.baz',
            },
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 200, response.content.decode())

        # Check form validation still 200s
        response = self.client.put(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid}
            ),
            data={
                'hostname': 'foo.bar.baz',
            },
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 200, response.content.decode())

    def test_systems_rename_no_inventory_server(self):
        # If the INVENTORY_SERVER setting isn't set, then we get a 500.
        response = self.client.put(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid}
            ),
            data={
                'display_name': 'foo.bar.baz',
            },
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 500, response.content.decode())


class SystemDupInsightsIDViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'sat_dup_insights_id_host',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_systems_available(self):
        # Bit of a sanity check here.
        self.assertEqual(constants.host_01_inid, constants.host_11_inid)
        systems = InventoryHost.objects.filter(
            insights_id=constants.host_01_inid
        ).values('id', 'insights_id', 'display_name').order_by('id')
        self.assertEqual(systems[0]['id'], UUID(constants.host_01_uuid))
        self.assertEqual(systems[0]['insights_id'], UUID(constants.host_01_inid))
        self.assertEqual(systems[0]['display_name'], constants.host_01_name)
        self.assertEqual(systems[1]['id'], UUID(constants.host_11_uuid))
        self.assertEqual(systems[1]['insights_id'], UUID(constants.host_11_inid))
        self.assertEqual(systems[1]['display_name'], constants.host_11_name)

    def test_list_systems_name_filter(self):
        # Systems filtered by name
        response = self.client.get(
            reverse('sat-compat-systems-list'),
            data={'search_term': '1'},
            **auth_header_for_testing()
        )
        # Should see two rows
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        page = response.json()
        self.assertIn('resources', page)
        self.assertIsInstance(page['resources'], list)
        # Systems in UUID order
        systems = page['resources']
        self.assertIn('display_name', systems[0])
        self.assertEqual(systems[0]['display_name'], constants.host_01_name)
        self.assertEqual(systems[1]['display_name'], constants.host_11_name)
        self.assertEqual(len(systems), 2)

    def test_retrieve(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        system = response.json()
        self.assertIn('display_name', system)
        self.assertIn(system['display_name'],
                      (constants.host_01_name, constants.host_11_name))

    def test_groups(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-groups',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        self.assertEqual(response.json(), [])

    def test_reports(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-reports',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_metadata(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-metadata',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_links(self):
        response = self.client.get(
            reverse(
                'sat-compat-systems-links',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_destroy(self):
        response = self.client.delete(
            reverse(
                'sat-compat-systems-detail',
                kwargs={'uuid': constants.host_01_inid}
            ),
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        # Just deletes the current reports; no Inventory involvement
        self.assertEqual(response.status_code, 204, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)


class SystemV1ViewTestCase(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def test_v1_retrieve(self):
        response = self.client.get(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid},
            ),
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        system = response.json()
        self.assertIn('display_name', system)
        self.assertIn(system['display_name'],
                      (constants.host_01_name, constants.host_11_name))
        # Systems can throw any branch_id at us and we ignore it
        response = self.client.get(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_04_inid},
            ),
            data={'branch_id': '-1'},
            **auth_header_for_testing()
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)
        system = response.json()
        self.assertIn('display_name', system)
        self.assertIn(system['display_name'], constants.host_04_name)

    @override_settings(INVENTORY_SERVER_URL=INVENTORY_SERVER_URL)
    @responses.activate
    def test_systems_v1_rename(self):
        responses.add(
            responses.PATCH, INVENTORY_SERVER_URL + '/hosts/' + constants.host_01_uuid,
            body='{"display_name": "foo.bar.baz"}',
            status=200
        )
        responses.add(
            responses.PATCH, INVENTORY_SERVER_URL + '/hosts/00112233-4455-6677-8899-0123456789FF',
            status=404
        )

        # Clients can rename themselves
        response = self.client.put(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid}  # Insights ID
            ),
            data={'display_name': 'foo.bar.baz'},
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    @override_settings(INVENTORY_SERVER_URL=INVENTORY_SERVER_URL)
    @responses.activate
    def test_systems_v1_delete(self):
        responses.add(
            responses.DELETE, INVENTORY_SERVER_URL + '/hosts/' + constants.host_01_uuid,
            status=204
        )

        response = self.client.delete(
            reverse(
                'sat-compat-v1-systems-detail',
                kwargs={'uuid': constants.host_01_inid}
            ),
            content_type=constants.json_mime,
            **auth_header_for_testing(),
        )
        self.assertEqual(response.status_code, 204)
