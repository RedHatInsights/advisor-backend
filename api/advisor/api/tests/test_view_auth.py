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

from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.urls import reverse

from rest_framework.exceptions import AuthenticationFailed

from api.kessel import add_kessel_response
from api.models import InventoryHost
from api.permissions import (
    AssociatePermission, BaseAssociatePermission, BaseRedHatUserPermission,
    CertAuthPermission, InsightsRBACPermission, IsRedHatInternalUser,
    RBACPermission, RHIdentityAuthentication, ResourceScope, OrgPermission,
    TurnpikeIdentityAuthentication, auth_header_for_testing, auth_header_key,
    auth_to_request, request_object_for_testing, request_to_username,
    turnpike_auth_header_for_testing, make_rbac_url, get_workspace_id,
)
from api.tests import constants

import base64


def b64s(s):
    return base64.b64encode(s.encode())


TEST_RBAC_URL = 'http://rbac.svc'
TEST_RBAC_V2_WKSPC = make_rbac_url(
    "workspaces/?type=default",
    version=2, rbac_base=TEST_RBAC_URL
)

turnpike_defaults = {
    'Role': [], 'email': 'testuser@redhat.com', 'givenName': 'Test',
    'surname': 'User', 'rhatUUID': "01234567-89ab-cdef-0123-456789abcdef"
}


def fake_auth_check(request, auth_class):
    # The Viewset infrastructure sets the `auth` and `user` properties
    # of requests when it finds an auth class that authenticates.
    # Because we don't go through that here, we have to fake setting these
    # attributes in order to check that the permissions classes work.
    auth_tuple = auth_class().authenticate(request)
    if auth_tuple is not None:
        setattr(request, 'user', auth_tuple[0])
        setattr(request, 'auth', auth_tuple[1])
    return auth_tuple


class FakeView(object):
    # Needs to supply get_view_name method for has_permission check
    view_name = 'List'

    def get_view_name(self):
        return self.view_name


class AuthFailTestCase(TestCase):
    fixtures = ['rulesets']

    def test_non_auth_view_with_no_auth(self):
        """
        A view that doesn't require authentication should work without
        authentication headers.
        """
        response = self.client.get(reverse('systemtype-list'))
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_non_auth_view_with_auth(self):
        """
        A view that doesn't require authentication should work even if we do
        supply valid authentication headers.
        """
        response = self.client.get(reverse('systemtype-list'), **auth_header_for_testing())
        self.assertEqual(response.status_code, 200)

        # Test standard return type is JSON
        self.assertEqual(response.accepted_media_type, constants.json_mime)

    def test_auth_req_view_with_no_auth(self):
        """
        A view that requires authentication should return a 403 if no
        authentication header is supplied.
        """
        response = self.client.get(reverse('rule-list'))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'detail': 'No identity information'})

    def test_auth_req_view_with_no_base64(self):
        """
        A view that requires authentication should return a 403 if the
        authentication header supplied isn't Base64 encoded.
        """
        headers = {
            auth_header_key: 'org_id = 9876543'
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        # For unknown reasons, the Base64 decoding failure simply returns an
        # empty string to the JSON decoding, which then decodes as a blank
        # structure, which is invalid for a different reason.  So we don't
        # get the Base64 decoding error here.
        self.assertIn('Unparseable', response.content.decode())

    def test_auth_req_view_with_no_json_in_auth(self):
        """
        A view that requires authentication should return a 403 if the
        Base64 authentication header supplied contains no JSON.
        """
        headers = {
            auth_header_key: b64s('org_id = 9876543')
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn('Unparseable', response.content.decode())

    def test_auth_req_view_with_bad_json_in_auth(self):
        """
        A view that requires authentication should return a 403 if the
        Base64 authentication header supplied contains incomplete JSON.
        """
        headers = {
            auth_header_key: b64s('{"identity": {"org_id')
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn('Unparseable', response.content.decode())

    def test_auth_req_view_with_json_not_a_struct(self):
        """
        A view that requires authentication should return a 403 if the
        Base64 authentication header supplied contains just a string.
        """
        headers = {
            auth_header_key: b64s('["identity", "9876543"]')
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn('is not a structure', response.content.decode())

    def test_auth_req_view_with_json_no_identity(self):
        """
        A view that requires authentication should return a 403 if the
        Base64 authentication header supplied contains no identity section.
        """
        headers = {
            auth_header_key: b64s('{"org_id": "9876543"}')
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn("'identity' section not found in", response.content.decode())

    def test_auth_req_view_with_json_identity_not_a_struct(self):
        """
        A view that requires authentication should return a 403 if the
        Base64 authentication header supplied contains no identity structure.
        """
        headers = {
            auth_header_key: b64s('{"identity": "9876543"}')
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn('identity field is not a structure', response.content.decode())

    def test_auth_req_view_with_json_org_id_not_in_identity(self):
        """
        A view that requires authentication should return a 403 if the
        Base64 authentication header supplied contains no org_id
        in the identity section.
        """
        headers = {
            auth_header_key: b64s('{"identity": {"id": 9988776}}')
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn(
            "'org_id' property not found in 'identity' section of HTTP_X_RH_IDENTITY",
            response.content.decode()
        )

    def test_auth_req_view_with_json_org_id_too_long(self):
        """
        A view that requires authentication should return a 403 if the
        authentication header supplied contains an over-long org_id.
        """
        headers = {
            auth_header_key: b64s(
                '{"identity": {"org_id": "123456789012345678901234567890123456789012345678901"'
                ', "user": {"username": "test"}}}'
            )
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn(
            "Org ID '123456789012345678901234567890123456789012345678901' "
            "greater than 50 characters",
            response.content.decode()
        )

    def test_auth_req_view_with_json_org_id_alpha_characters(self):
        """
        A view that requires authentication should return a 200 if the
        authentication header supplied contains org_id with non number characters.
        """
        headers = {
            auth_header_key: b64s(
                '{"identity": {"org_id": "abc", "type": "User", "user": '
                '{"username": "test"}}}'
            )
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 200)

    def test_auth_req_view_with_org_id_as_int(self):
        """
        A view that requires authentication should gracefully handle an
        integer for the org_id.  We also need to supply at least the
        username or service account.
        """
        # Note that tests that pass have to have the correct auth type.
        headers = {
            auth_header_key: b64s(
                '{"identity": {"org_id": 1234567, "type": "User",'
                '"user": {"username": "test"}, "auth_type": "jwt"}}'
            )
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 200, response.content.decode())

        # Check it still works with a service account type identity header
        headers = {
            auth_header_key: b64s(
                '{"identity": {"org_id": 1234567, "type": "ServiceAccount",'
                '"service_account": {"username": "sa123"}, "auth_type": "jwt"}}'
            )
        }
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 200, response.content.decode())


class RHIdentityAuthFailTestCase(TestCase):
    fixtures = [
        'rule_categories', 'rulesets', 'system_types', 'upload_sources',
        'basic_test_data',
    ]

    def test_user_subsection_must_be_object(self):
        """
        A view that requires the 'is_internal' flag needs to have a user
        field that is an object.
        """
        headers = {auth_header_key: b64s(
            '{"identity": {"org_id": 9876543, "type": "User", "user": "khoes", '
            '"auth_type": "jwt"}}'
        )}
        response = self.client.post(
            reverse('ruletopic-list'), data={
                'name': 'New topic',
                'slug': 'New',
                'description': 'A new topic created through the API',
            },
            **headers
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn(
            "You do not have permission to perform this action",
            response.content.decode()
        )

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True)
    def test_kessel_enabled_requires_user_id(self):
        """
        When KESSEL_ENABLED is set, the user identity must have a 'user_id'
        property (because that is how we identify the user to RBACv2).  Test
        that we fail early on that.
        """
        headers = auth_header_for_testing(user_id=None)
        response = self.client.get(reverse('rule-list'), **headers)
        self.assertEqual(response.status_code, 403)
        # For some reason the custom instance message doesn't come through?
        # self.assertIn(
        #     "'user_id' property not found in 'user' section of identity",
        #     response.content.decode()
        # )


class BadUseOfRBACPermission(TestCase):
    def test_permission_not_string(self):
        with self.assertRaisesMessage(
            ValueError, 'permission given is not a string'
        ):
            RBACPermission(42)


class BadUseOfCertAuthPermission(TestCase):
    def test_permission_not_string(self):
        # request object must have gone through authentication.
        cap = CertAuthPermission()
        request = request_object_for_testing()
        result = cap.has_permission(request, 'view')
        self.assertFalse(result)
        self.assertEqual(request.rbac_failure_message, 'not authenticated')

        # Failures in identity property of request.auth
        request = request_object_for_testing(auth_by=RHIdentityAuthentication)
        view = FakeView()
        # System property not a dict
        request.auth = {
            'org_id': constants.standard_org, 'type': 'System',
            'system': constants.host_01_uuid
        }
        result = cap.has_permission(request, view)
        self.assertFalse(result)
        self.assertEqual(
            request.rbac_failure_message,
            "'system' property is not an object in 'identity' section of HTTP_X_RH_IDENTITY in Cert authentication check"
        )
        # system dict has no 'cn'
        request.auth = {
            'org_id': constants.standard_org, 'type': 'System',
            'system': {'id': constants.host_01_uuid}
        }
        result = cap.has_permission(request, view)
        self.assertFalse(result)
        self.assertEqual(
            request.rbac_failure_message,
            "'cn' property not found in 'identity.system' section of HTTP_X_RH_IDENTITY in Cert authentication check"
        )
        # system dict 'cn' value not a string
        request.auth = {
            'org_id': constants.standard_org, 'type': 'System',
            'system': {'cn': 123}
        }
        result = cap.has_permission(request, view)
        self.assertFalse(result)
        self.assertEqual(
            request.rbac_failure_message,
            "'identity.system.cn' is not a string in Cert authentication check"
        )
        # system dict 'cn' value not a UUID
        request.auth = {
            'org_id': constants.standard_org, 'type': 'System',
            'system': {'cn': constants.host_01_name}
        }
        result = cap.has_permission(request, view)
        self.assertFalse(result)
        self.assertEqual(
            request.rbac_failure_message,
            "'identity.system.cn' is not a UUID in Cert authentication check"
        )

        # Finally we should be able to validate with a valid identity
        request.auth = {
            'org_id': constants.standard_org, 'type': 'System',
            'system': {'cn': constants.host_01_uuid, 'cert_type': 'system'}
        }
        result = cap.has_permission(request, view)
        self.assertTrue(result)
        self.assertEqual(
            request.rbac_failure_message, 'CertAuthPermission OK'
        )
        # Check attributes now set on request
        self.assertTrue(hasattr(request, 'auth_system_type'))
        self.assertEqual(request.auth_system_type, 'system')
        self.assertTrue(hasattr(request, 'auth_system'))
        self.assertEqual(request.auth_system, constants.host_01_uuid)
        self.assertTrue(hasattr(request, 'username'))
        self.assertEqual(request.username, 'Certified System')


class RequestToUserNameTestCase(TestCase):
    def test_missing_fields(self):
        # First - no username and no auth done yet.
        request = HttpRequest()
        self.assertFalse(hasattr(request, 'username'))
        self.assertFalse(hasattr(request, 'auth'))
        with self.assertRaises(AuthenticationFailed):
            request_to_username(request)
        # Then check handling of unknown identity type
        request = HttpRequest()
        request.META = {
            auth_header_key: b64s(
                '{"identity": {"org_id": 9876543, "type": "Certificate", '
                '"user": {"is_internal": false}}}'
            ),
            'REMOTE_ADDR': 'test'
        }
        fake_auth_check(request, RHIdentityAuthentication)
        self.assertFalse(hasattr(request, 'username'))
        self.assertTrue(hasattr(request, 'auth'))
        with self.assertRaises(AuthenticationFailed):
            request_to_username(request)
        # Then check handling when the type key is not in the identity
        request = HttpRequest()
        request.META = {
            auth_header_key: b64s(
                '{"identity": {"org_id": 9876543, "type": "User", '
                '"certificate": {"is_internal": false}}}'
            ),
            'REMOTE_ADDR': 'test'
        }
        fake_auth_check(request, RHIdentityAuthentication)
        self.assertFalse(hasattr(request, 'username'))
        with self.assertRaises(AuthenticationFailed):
            request_to_username(request)


class IsRedHatInternalUserTestCase(TestCase):
    fixtures = ['rulesets']

    def test_has_is_internal_permission(self):
        request = HttpRequest()
        request.META = {
            auth_header_key: b64s(
                '{"identity": {"org_id": 9876543, "type": "User", "user": '
                '{"username": "test", "is_internal": true}}}'
            ),
            'REMOTE_ADDR': 'test'
        }
        request.method = 'GET'

        # First have to go through standard identity authentication
        self.assertEqual(fake_auth_check(request, RHIdentityAuthentication), (
            '9876543',
            {"org_id": 9876543, "type": "User", "user": {
                "username": "test", "is_internal": True
            }}
        ))
        # Then check that the user can be detected as internal
        irhu = IsRedHatInternalUser()
        irhu.allowed_views = ['List']
        view = FakeView()
        self.assertTrue(irhu.has_permission(request, view))

    def test_has_is_internal_permission_false(self):
        request = HttpRequest()
        request.META = {
            auth_header_key: b64s(
                '{"identity": {"org_id": 9876543, "type": "User", "user": '
                '{"username": "test", "is_internal": false}}}'
            ),
            'REMOTE_ADDR': 'test'
        }
        request.method = 'GET'

        # First have to go through standard identity authentication
        rhia = RHIdentityAuthentication()
        self.assertEqual(rhia.authenticate(request), (
            '9876543',
            {"org_id": 9876543, "type": "User", "user": {
                "username": "test", "is_internal": False
            }}
        ))
        irhu = IsRedHatInternalUser()
        irhu.allowed_views = ['List']
        view = FakeView()
        self.assertFalse(irhu.has_permission(request, view))


class BaseRedHatUserTestCase(TestCase):
    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            x = BaseRedHatUserPermission()
            x.has_red_hat_permission('request', 'view', 'user_data')


class OrgPermissionTestCase(TestCase):
    def test_basic_has_permission_steps(self):
        orgperm = OrgPermission()
        view = FakeView()
        # Firstly, if no auth then false
        rq = request_object_for_testing()
        self.assertFalse(hasattr(rq, 'user'))
        self.assertFalse(orgperm.has_permission(rq, view))
        # Now for the second stage of the identity check
        rq = request_object_for_testing(auth_by=RHIdentityAuthentication)
        self.assertTrue(hasattr(rq, 'user'))
        self.assertTrue(hasattr(rq, 'auth'))
        self.assertIsInstance(rq.auth, dict)
        # Temporarily remove that...
        auth_dict = rq.auth
        rq.auth = None
        self.assertFalse(orgperm.has_permission(rq, view))
        # Now put it back and check that we get True if 'org_id' is present.
        rq.auth = auth_dict
        self.assertIn('org_id', rq.auth)
        self.assertTrue(orgperm.has_permission(rq, view))


class BadUsesOfAuthHeaderTestCase(TestCase):
    def test_get_unencode_value(self):
        self.assertEqual(auth_header_for_testing(unencoded=True), {'identity': {
            'account_number': constants.standard_acct,
            'auth_type': 'jwt-auth',
            'org_id': constants.standard_org,
            'type': 'User',
            'user': {'user_id': constants.test_user_id, 'username': constants.test_username}
        }})

    def test_system_and_user_auth(self):
        with self.assertRaises(AuthenticationFailed):
            auth_header_for_testing(user_opts={'foo': 1}, system_opts={'bar': 2})


class GetWorkspaceIdTestCase(TestCase):
    @responses.activate
    @override_settings(RBAC_URL=TEST_RBAC_URL)
    def test_get_workspace_id_failures(self):
        request = request_object_for_testing(auth_by=RHIdentityAuthentication)
        # Have to not use the workspace_for_org cache in this test
        from api import permissions
        permissions.workspace_for_org = None  # prevents cache use
        with self.assertLogs(logger='advisor-log') as logs:
            # Non-200 response
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                status=404,
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)  # This reflects the actual request.
            self.assertIn(
                "ERROR:advisor-log:Error: Got status 404 from RBAC: ''",
                logs.output
            )
            # Not a dict
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                json='Foo!',
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)
            self.assertIn(
                "ERROR:advisor-log:Error: Response from RBAC is not a dictionary: 'Foo!'",
                logs.output
            )
            # No 'data' item in dict
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                json={'foo': 'bar'},
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)
            self.assertIn(
                "ERROR:advisor-log:Error: Response from RBAC is missing 'data' "
                "key: '{'foo': 'bar'}'",
                logs.output
            )
            # Data not a list
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                json={'data': 'bar'},
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)
            self.assertIn(
                "ERROR:advisor-log:Error: Response from RBAC is not a list: "
                "'bar'",
                logs.output
            )
            # Data list empty
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                json={'data': []},
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)
            self.assertIn(
                "ERROR:advisor-log:Error: Data from RBAC is empty: "
                "'[]'",
                logs.output
            )
            # Data list does not contain a dictionary
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                json={'data': ['Foo part 2: Return of Foo']},
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)
            self.assertIn(
                "ERROR:advisor-log:Error: First data item from RBAC is not a "
                "dictionary: 'Foo part 2: Return of Foo'",
                logs.output
            )
            # Data list dictionary does not contain an 'id' element
            responses.add(
                responses.GET, TEST_RBAC_V2_WKSPC,
                json={'data': [{'foo': 'bar'}]},
            )
            workspace_id, elapsed = get_workspace_id(request)
            self.assertFalse(workspace_id)
            self.assertGreater(elapsed, 0.0)
            self.assertIn(
                "ERROR:advisor-log:Error: First data item from RBAC is missing "
                "'id' key: '{'foo': 'bar'}'",
                logs.output
            )

    @responses.activate
    @override_settings(RBAC_URL=TEST_RBAC_URL)
    def test_workspace_id_cached(self):
        request = request_object_for_testing(auth_by=RHIdentityAuthentication)
        # Make the first request to cache the workspace ID
        responses.add(
            responses.GET, TEST_RBAC_V2_WKSPC,
            json={'data': [{'id': constants.kessel_std_workspace_id}]}
        )
        # Grab the cache dict to manipulate it in testing.
        from api import permissions
        permissions.workspace_for_org = dict()
        workspace_id, elapsed = get_workspace_id(request)
        self.assertEqual(workspace_id, constants.kessel_std_workspace_id)
        self.assertGreater(elapsed, 0.0)
        # Make a second request to verify the workspace ID is cached
        workspace_id, elapsed = get_workspace_id(request)
        # Only one request made.
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(workspace_id, constants.kessel_std_workspace_id)
        self.assertEqual(elapsed, 0.0)
        self.assertEqual(len(permissions.workspace_for_org), 1)


class TestInsightsRBACPermissionKessel(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data',
    ]

    def test_request_has_user_auth(self):
        # Can't use the permission class before authentication has been done
        request = request_object_for_testing()
        view = FakeView()
        irbp = InsightsRBACPermission()
        result = irbp.has_permission(request, view)
        self.assertFalse(result)

    def test_view_has_no_scope(self):
        rhia = RHIdentityAuthentication()
        request = request_object_for_testing()
        user_id, _ = rhia.authenticate(request)
        self.assertEqual(user_id, constants.standard_org)

        view = FakeView()
        # This by default should not have a 'resource_scope' attribute
        self.assertFalse(hasattr(view, 'resource_scope'))
        # specifically set the attribute to None so _get_resource doesn't
        # default to ResourceScope.WORKSPACE.  This is basically setting the
        # view to always deny access, like 'denied' for the resource_name.
        setattr(view, 'resource_scope', None)
        # So therefore the RBAC permission should deny access.
        irbp = InsightsRBACPermission()
        result = irbp.has_permission(request, view)
        self.assertFalse(result)

    def test_identity_object_property_fails(self):
        rhia = RHIdentityAuthentication()
        request = request_object_for_testing()
        user_id, _ = rhia.authenticate(request)
        self.assertEqual(user_id, constants.standard_org)
        # Not sure yet why this isn't set but has_permission needs it.
        self.assertFalse(hasattr(request, 'user'))
        setattr(request, 'user', user_id)
        self.assertTrue(hasattr(request, 'auth'))
        view = FakeView()
        irbp = InsightsRBACPermission()

        # Manipulate the auth property to run through error checking
        # Not a dict
        request.auth = 'foo'
        self.assertFalse(irbp.has_permission(request, view))
        # No 'org_id'
        request.auth = {'foo': 'bar'}
        self.assertFalse(irbp.has_permission(request, view))
        # No 'type'
        request.auth = {'org_id': constants.standard_org}
        self.assertFalse(irbp.has_permission(request, view))
        # Identity has no 'username'
        request.auth = {
            'org_id': constants.standard_org, 'type': 'User',
            'user': {'id': constants.test_user_id}
        }
        self.assertFalse(irbp.has_permission(request, view))
        # Identity 'username' key is not a string
        request.auth = {
            'org_id': constants.standard_org, 'type': 'User',
            'user': {'username': ['Barry', 'Jones']}
        }
        self.assertFalse(irbp.has_permission(request, view))

    @override_settings(RBAC_ENABLED=True, KESSEL_ENABLED=True, RBAC_URL=TEST_RBAC_URL)
    @add_kessel_response(
        permission_checks=constants.kessel_allow_disable_recom_rw,
        resource_lookups=constants.kessel_user_in_workspace_host_group_1
    )
    @responses.activate
    def test_kessel_resourcescope_host_object_permissions(self):
        responses.add(
            responses.GET, TEST_RBAC_V2_WKSPC,
            json={'data': [{'id': constants.kessel_std_workspace_id}]}
        )
        # Set up the various permissions objects
        request = request_object_for_testing(auth_by=RHIdentityAuthentication)
        self.assertTrue(hasattr(request, 'user'))
        self.assertTrue(hasattr(request, 'auth'))
        view = FakeView()
        setattr(view, 'resource_name', 'recommendation-results')
        setattr(view, 'resource_scope', ResourceScope.HOST)
        irbp = InsightsRBACPermission()

        # HOST resources get allowed at view level, relying on
        # has_object_permission to handle specific host queries
        self.assertTrue(irbp.has_permission(request, view))

        # And then they would call has_object_permission, so let's exercise
        # that.
        host = InventoryHost.objects.get(id=constants.host_01_uuid)
        # If Kessel is not enabled this should always return True
        with self.settings(KESSEL_ENABLED=False):
            self.assertTrue(irbp.has_object_permission(request, view, host))
        # If called but resource scope is not HOST, returns True
        view.resource_scope = ResourceScope.WORKSPACE
        self.assertTrue(irbp.has_object_permission(request, view, host))
        view.resource_scope = ResourceScope.HOST
        # Object passed in has no 'id' attribute:
        self.assertFalse(hasattr(irbp, 'id'))
        self.assertFalse(irbp.has_object_permission(request, view, irbp))
        self.assertEqual(
            request.rbac_failure_message,
            "Permission scope is 'Host' but object has no 'id' attribute"
        )
        # Finally we actually get to do a has_kessel_permission check
        with add_kessel_response(
            permission_checks=constants.kessel_allow_host_01_read
        ):
            self.assertTrue(irbp.has_object_permission(request, view, host))


class TestTurnpikeAuthentication(TestCase):
    TIAClass = TurnpikeIdentityAuthentication()

    def test_identity_fails(self):
        # Basic failure - no need to re-test `get_identity_header()`
        rq = auth_to_request({auth_header_key: 'org_id = 9876543'})
        with self.assertRaisesRegex(AuthenticationFailed, 'Unparseable HTTP_X_RH_IDENTITY data'):
            self.TIAClass.authenticate(rq)

        # Standard auth identity fails
        rq = auth_to_request(auth_header_for_testing())
        with self.assertRaisesRegex(
            AuthenticationFailed, "identity.auth_type is not 'saml-auth'"
        ):
            self.TIAClass.authenticate(rq)

        # No auth header key in request seems to be the only way of returning
        # `None` from `get_identity_header()`...
        rq = auth_to_request({'foo': 'bar'})
        # That then returns None here:
        with self.assertRaisesRegex(
            AuthenticationFailed, "could not decode identity header"
        ):
            self.TIAClass.authenticate(rq)

    def test_header_property_fails(self):
        # Specific property failures
        # no auth_type property
        rq = auth_to_request({
            auth_header_key: b64s('{"identity": {"type": "Associate"}}')
        })
        with self.assertRaisesRegex(
            AuthenticationFailed, "'auth_type' not found in identity header"
        ):
            self.TIAClass.authenticate(rq)
        # auth_type not a string
        rq = auth_to_request({
            auth_header_key: b64s('{"identity": {"auth_type": 47}}')
        })
        with self.assertRaisesRegex(
            AuthenticationFailed, "identity.auth_type is not a string"
        ):
            self.TIAClass.authenticate(rq)
        # auth type doesn't match
        rq = auth_to_request({
            auth_header_key: b64s('{"identity": {"auth_type": "Associate"}}')
        })
        # non-matching auth_type is OK, just fails out
        with self.assertRaisesRegex(
            AuthenticationFailed, "identity.auth_type is not 'saml-auth'"
        ):
            self.TIAClass.authenticate(rq)

        # no type property
        rq = auth_to_request({
            auth_header_key: b64s('{"identity": {"auth_type": "saml-auth"}}')
        })
        with self.assertRaisesRegex(
            AuthenticationFailed, "'type' not found in identity header"
        ):
            self.TIAClass.authenticate(rq)
        # type property not a string
        rq = auth_to_request({auth_header_key: b64s(
            '{"identity": {"auth_type": "saml-auth", "type": 2}}'
        )})
        with self.assertRaisesRegex(
            AuthenticationFailed, "identity.type is not a string"
        ):
            self.TIAClass.authenticate(rq)
        # type property doesn't match
        rq = auth_to_request({auth_header_key: b64s(
            '{"identity": {"auth_type": "saml-auth", "type": "Manager"}}'
        )})
        # type not 'Associate'
        with self.assertRaisesRegex(
            AuthenticationFailed, "identity.type is not 'Associate'"
        ):
            self.TIAClass.authenticate(rq)

        # no associate property
        rq = auth_to_request({auth_header_key: b64s(
            '{"identity": {"auth_type": "saml-auth", "type": "Associate"}}'
        )})
        with self.assertRaisesRegex(
            AuthenticationFailed, "'associate' not found in identity header"
        ):
            self.TIAClass.authenticate(rq)
        # associate property not a dict
        rq = auth_to_request({auth_header_key: b64s(
            '{"identity": {"auth_type": "saml-auth", "type": "Associate"'
            ', "associate": "very yes"}}'
        )})
        with self.assertRaisesRegex(
            AuthenticationFailed, "identity.associate is not an object"
        ):
            self.TIAClass.authenticate(rq)

    def test_authenticate_success(self):
        # Completely minimal associate header
        rq = auth_to_request({auth_header_key: b64s(
            '{"identity": {"auth_type": "saml-auth", "type": "Associate"'
            ', "associate": {}}}'
        )})
        # Returns a tuple
        self.assertEqual(self.TIAClass.authenticate(rq), ({}, {
            "auth_type": "saml-auth", "type": "Associate", "associate": {}
        }))

        # Hopefully same thing
        rq2 = auth_to_request(turnpike_auth_header_for_testing())
        # Default data provided by turnpike_auth_header_for_testing
        self.assertEqual(
            self.TIAClass.authenticate(rq2), (turnpike_defaults, {
                "associate": turnpike_defaults, 'auth_type': 'saml-auth',
                "type": "Associate",
            })
        )


class TestBaseAssociatePermission(TestCase):
    BAPClass = BaseAssociatePermission()

    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.BAPClass.has_associate_permission('request', 'view', 'user_data')

    def test_has_permission_no_identity(self):
        rhia = RHIdentityAuthentication()
        request = request_object_for_testing()
        user_id, _ = rhia.authenticate(request)
        # If 'auth' property is None, it should fail
        request.user = 'username'
        request.auth = None
        self.assertFalse(self.BAPClass.has_permission(request, 'view'))

    def test_has_permission_allowed_views(self):
        local_bap = BaseAssociatePermission()
        # For ease of testing we mangle the has_associate_permission call
        local_bap.has_associate_permission = lambda r, v, i: True
        local_bap.allowed_views = ['List']
        rhia = RHIdentityAuthentication()
        request = request_object_for_testing()
        user_id, _ = rhia.authenticate(request)
        request.user = user_id
        # Check the handling of allowed_views in has_permission
        view = FakeView()
        # Normal handling should allow list view access
        self.assertTrue(local_bap.has_permission(request, view))
        # This should have set the 'allowed_view_methods' property
        self.assertTrue(hasattr(local_bap, 'allowed_view_methods'))
        # Now if this view is not in that dict, then it should return False
        view.view_name = 'Detail'
        self.assertFalse(local_bap.has_permission(request, view))
        # Or if the request method is not allowed it returns false.
        view.view_name = 'List'
        request.method = 'POST'
        self.assertFalse(local_bap.has_permission(request, view))


class TestAssociatePermission(TestCase):
    APClass = AssociatePermission()
    view = FakeView()

    def test_associate_needed(self):
        ext_rq = auth_to_request(auth_header_for_testing())
        with self.assertRaises(AuthenticationFailed):
            fake_auth_check(ext_rq, TurnpikeIdentityAuthentication)
        int_rq = auth_to_request(turnpike_auth_header_for_testing())
        fake_auth_check(int_rq, TurnpikeIdentityAuthentication)
        self.assertTrue(self.APClass.has_permission(int_rq, self.view))
