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

import responses
from requests.exceptions import Timeout

from django.test import TestCase, override_settings
from django.urls import reverse

from api.permissions import (
    auth_header_for_testing, request_object_for_testing,
    has_rbac_permission
)
from api import permissions  # for rbac_perm_cache
from api.kessel import add_kessel_response
from api.tests import constants, update_stale_dates, rbac_data

TEST_RBAC_URL = 'http://rbac.svc/'


class RBACTestCase(TestCase):

    # Now that we're checking whether we can ack rules, we need fixtures!
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data'
    ]

    no_auth_views = {
        'rulecategory-list', 'systemtype-list', 'kcs-list',
    }
    std_auth_views = {
        'ack-list', 'hostack-list', 'rule-list',
        'rulerating-list', 'settings-list', 'stats-list', 'system-list',
        'ruletopic-list', 'user-preferences-list',
        'weeklyreportsubscription-list',
    }
    acks_views = {
        'ack-list', 'hostack-list',
    }
    exports_views = {
        'export-hits-list',
    }
    preferences_views = {
        'settings-list',
    }
    weekly_report_views = {
        'weeklyreportsubscription-list', 'user-preferences-list',
    }
    results_views = {
        'rulerating-list', 'rule-list', 'stats-list', 'system-list',
        'ruletopic-list',
    }
    internal_views = {
        'ackcount-list', 'rulerating-all-ratings',
        'rulerating-stats', 'rule-stats', 'rule-justifications',
    }

    view_kwargs = {
        'rule-ack-hosts': {'rule_id': constants.acked_rule},
        'rule-unack-hosts': {'rule_id': constants.acked_rule},
        'rule-stats': {'rule_id': constants.active_rule},
        'rule-justifications': {'rule_id': constants.active_rule},
    }
    view_post_data = {
        'ack-list': {'rule_id': constants.acked_rule, 'justification': 'baz!'},
        'hostack-list': {
            'rule': constants.acked_rule, 'justification': 'foo!',
            'system_uuid': constants.host_06_uuid,
        },
        'rule-ack-hosts': {
            'systems': [constants.host_06_uuid],
            'justification': 'bah!',
        },
        'rule-unack-hosts': {
            'systems': [constants.host_06_uuid],
        },
        'weeklyreportsubscription-create': {
            'is_subscribed': True
        }
    }

    granular_rbac_data = {
        'disable-recommendations': {
            'resource views': acks_views,
            'non resource views': exports_views | preferences_views | results_views,
            'post views': ('ack-list', 'hostack-list', 'rule-ack-hosts', 'rule-unack-hosts'),
        },
        'exports': {
            'resource views': exports_views,
            'non resource views': acks_views | preferences_views | results_views,
        },
        'preferences': {
            'resource views': preferences_views,
            'non resource views': exports_views | acks_views | results_views,
        },
        'recommendation-results': {
            'resource views': results_views,
            'non resource views': acks_views | exports_views | preferences_views,
        },
        'weekly-report': {
            'resource views': weekly_report_views,
            'non resource views': exports_views | acks_views | results_views,
        },
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    def _get_view(self, view_name, auth=True, auth_args={}):
        return self.client.get(
            reverse(
                view_name,
                kwargs=self.view_kwargs[view_name] if view_name in self.view_kwargs else {}
            ),
            **(auth_header_for_testing(user_opts=auth_args) if auth else {})
        )

    def test_no_auth_header(self):
        """
        Some views should bypass rbac if auth headers are not present
        """
        for view_name in self.no_auth_views:
            response = self._get_view(view_name, auth=False)
            self.assertEqual(
                response.status_code, 200,
                f"view {view_name} should be visible with no auth header"
            )
        # Other views should be denied
        for view_name in self.std_auth_views | self.internal_views:
            response = self._get_view(view_name, auth=False)
            self.assertEqual(
                response.status_code, 403,
                f"view {view_name} should not be visible with no auth header"
            )

    def test_rbac_disabled(self):
        """
        If RBAC is disabled, all views should be available; even internal
        views.  RBAC here is separate from RH identity authentication.
        """
        for view_name in self.no_auth_views | self.std_auth_views | self.internal_views:
            response = self._get_view(view_name, auth_args={'is_internal': True})
            self.assertEqual(
                response.status_code, 200,
                f"view {view_name} should be visible with RBAC disabled"
            )

    @responses.activate
    def test_rbac_enabled_bad_rbac_response(self):
        """
        View should return a 403 with RBAC enabled and a bad response from RBAC
        """
        responses.add(
            responses.GET, TEST_RBAC_URL, status=500
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.std_auth_views | self.internal_views:
                response = self._get_view(view_name)
                # 500 error in RBAC -> permission denied
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should not be visible with RBAC returning 500"
                )
            for view_name in self.no_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible even with RBAC returning 500"
                )

    @responses.activate
    def test_rbac_enabled_and_access_denied(self):
        """
        View should return a 403 with RBAC enabled and denying us access to it
        """
        responses.add(
            responses.GET, TEST_RBAC_URL, status=403
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.std_auth_views | self.internal_views:
                response = self._get_view(view_name)
                # 403 error in RBAC -> permission denied
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should not be visible with RBAC returning 403"
                )
            for view_name in self.no_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible even with RBAC returning 403"
                )

    @responses.activate
    def test_rbac_enabled_rbac_raises_exception(self):
        """
        View should return a 403 with RBAC enabled and connection failure from RBAC
        """
        responses.add(
            responses.GET, TEST_RBAC_URL, body=ConnectionError("Test raises an exception")
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.std_auth_views | self.internal_views:
                response = self._get_view(view_name)
                # 500 error in RBAC -> permission denied
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should not be visible with RBAC raising a ConnectionError"
                )
            for view_name in self.no_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible even with RBAC raising a ConnectionError"
                )

    @responses.activate
    def test_rbac_enabled_rbac_timed_out(self):
        """
        View should return a 403 with RBAC enabled and no timely response from RBAC
        """
        responses.add(
            responses.GET, TEST_RBAC_URL, body=Timeout()
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.std_auth_views | self.internal_views:
                response = self._get_view(view_name)
                # 500 error in RBAC -> permission denied
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} looks like rbac timed out guys"
                )
            for view_name in self.no_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible even with RBAC raising a ConnectionError"
                )

    @responses.activate
    def test_rbac_enabled_good_rbac_response_no_data(self):
        """
        View should return 403 with RBAC enabled and bad permissions
        """
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json={'nonsense': 'complete'}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.no_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should still be visible with RBAC not providing a 'data' object"
                )
            for view_name in self.internal_views | self.std_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should not be visible with RBAC not providing a 'data' object"
                )

    @responses.activate
    def test_rbac_enabled_good_rbac_response_no_permissions(self):
        """
        View should return 403 with RBAC enabled and bad permissions
        """
        responses.add(
            responses.GET, TEST_RBAC_URL, json={'data': []}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.no_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should still be visible with RBAC denying all"
                )
            for view_name in self.internal_views | self.std_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should not be visible with RBAC denying all"
                )

    @responses.activate
    def test_rbac_enabled_good_rbac_response_good_permissions(self):
        """
        View should return 200 with RBAC enabled and good permissions
        """
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json=rbac_data(), status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.no_auth_views | self.std_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible with RBAC allowing all"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should be denied to non-internal users even with RBAC allowing all"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name, auth_args={'is_internal': True})
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible to internal users with RBAC allowing all"
                )

    @responses.activate
    def test_rbac_enabled_good_rbac_response_good_and_bad_permissions(self):
        """
        View should return 200 with RBAC enabled and providing good and malformed permissions
        """
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json={'data': [
                {'permission': 'abject failure'},
                {'no permission': 'do dogs even understand this?'},
                {'permission': 'advisor:*:*'},
            ]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.no_auth_views | self.std_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible with RBAC allowing all"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should be denied to non-internal users even with RBAC allowing all"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name, auth_args={'is_internal': True})
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible to internal users with RBAC allowing all"
                )

    @responses.activate
    def test_rbac_enabled_good_rbac_response_read_permissions(self):
        """
        View should return 200 with RBAC enabled and read-only permissions
        """
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json=rbac_data('advisor:*:read'), status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.no_auth_views | self.std_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible for user with read only RBAC permissions"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should be denied to non-internal users with read only RBAC permissions"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name, auth_args={'is_internal': True})
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible to internal users with read only RBAC permissions"
                )
            # Adding an ack should be denied when we only have read permission
            response = self.client.post(
                reverse('ack-list'), data={'rule_id': constants.acked_rule},
                **auth_header_for_testing()
            )
            self.assertEqual(
                response.status_code, 403,
                "view ack-list should not be allowed for a user with read only RBAC permissions"
            )

    @responses.activate
    def test_rbac_enabled_good_rbac_response_read_permissions_other(self):
        """
        View should return 200 with RBAC enabled and read-only permissions
        """
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json={'data': [
                {'permission': 'advisor:recommendation-results:read'},
                {'permission': 'advisor:*:read'},
                {'permission': 'vulnerability:*:*'}, {'permission': 'inventory:*:*'},
            ]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for view_name in self.no_auth_views | self.std_auth_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible for user with read only plus other RBAC permissions"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name)
                self.assertEqual(
                    response.status_code, 403,
                    f"view {view_name} should be denied to non-internal users with read only plus other RBAC permissions"
                )
            for view_name in self.internal_views:
                response = self._get_view(view_name, auth_args={'is_internal': True})
                self.assertEqual(
                    response.status_code, 200,
                    f"view {view_name} should be visible to internal users with read only plus other RBAC permissions"
                )
            # Adding an ack should be denied when we only have read permission
            response = self.client.post(
                reverse('ack-list'), data={'rule_id': constants.acked_rule},
                **auth_header_for_testing()
            )
            self.assertEqual(
                response.status_code, 403,
                "view ack-list should not be allowed for a user with read only plus other RBAC permissions"
            )

    @responses.activate
    def _test_rbac_granular_rbac_resource(self, resource_name, resource_test_info, action='*'):
        """
        Test to see that everything functions as expected in resource_test_info
        when RBAC is given 'advisor:resource_name:*' as a permission.

        This is a helper function because we can't use responses to override
        the RBAC response more than once in the same function.
        """
        test_desc = f"with RBAC allowing {resource_name} only"
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json=rbac_data('advisor:' + resource_name + ':' + action),
            status=200
        )
        for view_name in self.no_auth_views:
            response = self._get_view(view_name)
            self.assertEqual(
                response.status_code, 200,
                f"view {view_name} should be visible {test_desc}"
            )
        for view_name in resource_test_info['resource views']:
            response = self._get_view(view_name)
            self.assertEqual(
                response.status_code, 200,
                f"view {view_name} should be visible {test_desc}"
            )
        for view_name in resource_test_info['non resource views']:
            response = self._get_view(view_name)
            self.assertEqual(
                response.status_code, 403,
                f"view {view_name} should be denied {test_desc}"
            )
        for view_name in resource_test_info.get('post views', []):
            response = self.client.post(
                reverse(
                    view_name,
                    kwargs=self.view_kwargs[view_name] if view_name in self.view_kwargs else {}
                ),
                data=self.view_post_data[view_name],
                **auth_header_for_testing()
            )
            self.assertIn(
                response.status_code, (200, 201),
                f"view {view_name} (with kwargs "
                f"{self.view_kwargs[view_name] if view_name in self.view_kwargs else {}} "
                f"and data {self.view_post_data[view_name]} should be "
                f"allowed {test_desc} (gave {response.status_code} "
                f"{response.reason_phrase} - {response.content.decode()})"
            )
        for view_name in self.internal_views:
            response = self._get_view(view_name)
            self.assertEqual(
                response.status_code, 403,
                f"view {view_name} should be denied to non-internal users even {test_desc}"
            )
        for view_name in self.internal_views:
            response = self._get_view(view_name, auth_args={'is_internal': True})
            self.assertEqual(
                response.status_code, 200,
                f"view {view_name} should be visible to internal users {test_desc}"
            )

    def test_rbac_granular_rbac_resources(self):
        """
        RBAC granular permissions for a specific resource only, everything
        else denied.  We use this instead of lots of copy and paste.
        """
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            for resource_name, resource_test_info in self.granular_rbac_data.items():
                self._test_rbac_granular_rbac_resource(resource_name, resource_test_info)

    def test_rbac_granular_rbac_resources_read(self):
        """
        RBAC granular permissions for a specific resource that is read only.
        """
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            self._test_rbac_granular_rbac_resource(
                'recommendation-results',
                self.granular_rbac_data['recommendation-results'],
                action='read',
            )

    def test_rbac_bad_req_permissions(self):
        """
        has_rbac_permission should raise an exception if not given a
        permission in app:resource:action format.
        """
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            with self.assertRaises(ValueError):
                has_rbac_permission('username', 'org_id', 'fabulous clean!')

    @responses.activate
    def test_rbac_permission_request_caching(self):
        """
        Check that has_rbac_permission actually caches the data from RBAC if
        given a semi-valid request object.
        """
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json={'data': [{'permission': 'advisor:*:*'}]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            permissions.rbac_perm_cache = dict()  # activate cache for this
            rq = request_object_for_testing()
            accepted, elapsed = has_rbac_permission(
                'username', 'org_id', 'advisor:recommendations:*', rq, 'account'
            )
            self.assertTrue(accepted)
            self.assertGreater(elapsed, 0.0)  # Should take at least some milliseconds.
            # Request again should use the cache
            accepted, elapsed = has_rbac_permission(
                'username', 'org_id', 'advisor:recommendations:*', rq, 'account'
            )
            self.assertTrue(accepted)
            self.assertEqual(elapsed, 0.0)  # Cache sets elapsed to 0.0
            permissions.rbac_perm_cache = None  # deactivate again just in case


class KesselTestCase(TestCase):
    """
    Specific tests of the kessel functions and classes failure modes.
    """
    @override_settings(RBAC_ENABLED=False)
    def test_kessel_allowed_if_rbac_not_enabled(self):
        kessel_response, time = permissions.has_kessel_permission(
            permissions.ResourceScope.ORG,
            permissions.RBACPermission('advisor:recommendation-results:*'),
            'identity', host_id=None
        )
        self.assertTrue(kessel_response)
        self.assertEqual(time, 0.0)

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True)
    def test_kessel_host_none_in_resourcescope_host(self):
        # The ValueError raised is caught by the try/except in there,
        # generates a log message and returns False, 0.0
        kessel_response, time = permissions.has_kessel_permission(
            permissions.ResourceScope.HOST,
            permissions.RBACPermission('advisor:recommendation-results:*'),
            'identity', host_id=None
        )
        self.assertFalse(kessel_response)
        self.assertEqual(time, 0.0)

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True)
    def test_kessel_host_check_ok(self):
        with add_kessel_response(
            permission_checks=constants.kessel_zedrsp_allow_host_01_read
        ):
            kessel_response, time = permissions.has_kessel_permission(
                permissions.ResourceScope.HOST,
                permissions.RBACPermission('advisor:recommendation-results:read'),
                constants.kessel_std_user_identity_dict,
                host_id=constants.host_01_uuid
            )
            self.assertTrue(kessel_response)
            self.assertGreater(time, 0.0)
