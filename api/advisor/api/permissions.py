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

import base64
from enum import Enum
import json
import uuid

from django.conf import settings
from django.http import HttpRequest
from django.utils.datastructures import MultiValueDict

from rest_framework.authentication import BaseAuthentication
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.exceptions import AuthenticationFailed

from advisor_logging import logger

import api.kessel as kessel

http_auth_header_key = 'x-rh-identity'
auth_header_key = 'HTTP_X_RH_IDENTITY'
TP_ASSOCIATE = 'tp_associate'

host_group_attr = 'host_groups'
user_details_key = {
    'User': 'user',
    'ServiceAccount': 'service_account'
}


##############################################################################
# Kessel resource scope definition
##############################################################################

class ResourceScope(Enum):
    """
    ORG scope indicates the resource is "org wide" or not.

    An "org wide" resource is one which is scoped to the entire organization,
    and effectively an operation on the organization itself.  This equates to
    the 'root workspace'.

    For example, ack-ing a Rule is org_wide.  Host-acks, however, are scoped
    to a specific host.

    Between the two, a 'workspace' scope at this stage is just used for host
    groups.
    """
    ORG = 1
    WORKSPACE = 2
    HOST = 3


##############################################################################
# Authentication and header parsing
##############################################################################


def error_and_deny(msg, extra=''):
    logger.error(msg + (' ' + extra if extra else ''))
    raise AuthenticationFailed(msg)


# In normal operation, and in certain tests, we don't really want to cache
# the permissions returned for a particular username and account, because
# the permissions might change while this instance is alive.  However, when
# the schema is being generated, drf-spectacular makes up a new request object
# for each view it tests, which caused our previous cache (which was attached
# to the request object) to fail.  So we have a cache, of sorts, that can be
# turned on when the schema view is requested and then turned off immediately
# afterward.
rbac_perm_cache = None


class RBACPermission(object):
    """
    A handy container object for handling RBAC permissions in the form
    app:resource:method.

    This object provides the properties:
    * 'string' - the original permissions string
    * 'app' - the app from the original permission
    * 'resource' - the resource from the original permission
    * 'method' - the method from the original permission

    This object provides the following operator handling:

    * Equality - `this == that`.
      - True if the two permissions are exactly the same.
    * Contains than - `this in that`.
      - True if the two permissions are the same, or the first permission
        'includes' the second permission.  A permission includes another if
        all of the following are true:
            * the apps match, or the second app == '*'.
            * the resources match, or the second resource == '*'.
            * the methods match, or the second method == '*', or the first
              method is 'read' and the second method is 'write'.

    The equality and contains operators are used to test when a sought
    permission is included in an RBAC permission
    """

    def __init__(self, permission_str):
        if not isinstance(permission_str, str):
            raise ValueError('permission given is not a string')
        self.string = permission_str
        if not permission_str.count(':') == 2:
            raise ValueError("permission given does not contain exactly two ':' characters")
        (self.app, self.resource, self.method) = permission_str.split(':')

    def __eq__(self, other):
        return self.string == other.string

    def __contains__(self, other):
        # Note that the sense of 'contains' is opposite to the sense of 'in':
        # A is in B if B contains A.
        if self.string == other.string:
            return True
        if not (self.app == other.app or self.app == '*'):
            return False
        if not (self.resource == other.resource or self.resource == '*'):
            return False
        return (self.method == other.method or self.method == '*' or (other.method == 'read' and self.method == 'write'))

    def __repr__(self):
        return self.string

    def as_kessel_permission(self):
        # Note that neither the resource nor method will be '*' here, because
        # we are converting a specific permission to a relation, not a 'general
        # scope' permission.  This saves us doing two full replaces on the
        # entire rendered string.
        return f"{self.app}_{self.resource.replace('-', '_')}_{self.method}"


def find_host_groups(role_list, request):
    """
    We now also have to store the host group information we get from inventory.
    This comes in the resource definition within the RBAC response:

    {
      "resourceDefinitions": [
        {
          "attributeFilter": {
            "key": "group.id",
            "value": [
              "11111111-1111-1111-1111-111111111111",
              "11111111-1111-1111-1111-222222222222"
            ],
            "operation": "in"
          }
        }
      ],
      "permission": "inventory:hosts:read"
    }

    If the permission is 'inventory:hosts:read', we find one of the resource
    definitions that has an attribute filter key of 'inventory.groups', and
    we get the list of inventory groups from its value. We currently ignore
    the operation value.

    However, if any matching inventory:hosts permission includes no resource
    definitions, according to ESSNTL-4816 this allows access to all hosts -
    which is enabled by exiting out of this function early and not setting the
    'host_group_attr' on the request object.
    """
    if request is None:
        return  # we can't store any host groups on None
    host_groups = []
    sought_permission = RBACPermission('inventory:hosts:read')
    for role in role_list:
        if 'permission' not in role:
            continue
        try:
            role_permission = RBACPermission(role['permission'])
        except ValueError:
            continue
        if sought_permission not in role_permission:
            continue
        # ignore the failure modes, try moving on to other roles that
        # also match this permission
        if 'resourceDefinitions' not in role:
            # This should not be possible, something is wrong, ignore
            continue
        if not isinstance(role['resourceDefinitions'], list):
            # Error in construction?
            continue
        if len(role['resourceDefinitions']) == 0:
            # No resource definitions == full access.  If we don't add the
            # attribute to the request object, it doesn't filter...
            return
        for rscdef in role['resourceDefinitions']:
            if not isinstance(rscdef, dict):
                continue
            if 'attributeFilter' not in rscdef:
                continue
            attrfilter = rscdef['attributeFilter']
            if not isinstance(attrfilter, dict):
                continue
            if 'key' not in attrfilter and 'value' not in attrfilter:
                continue
            if attrfilter['key'] != 'group.id':
                continue
            value = attrfilter['value']
            # Early versions of the spec say the value is a list; later
            # versions say it's a string with a JSON-encoded list.  Let's try
            # to cope with the latter by converting it into the former.
            if isinstance(value, str) and value[0] == '[' and value[-1] == ']':
                value = json.loads(value)
            if not isinstance(value, list):
                continue
            # Finally, we have the right key: add them to our list
            host_groups.extend(value)

    # If we found any host groups at the end of that, store them
    if host_groups:
        setattr(request, host_group_attr, host_groups)
        logger.info(f"User has host groups {host_groups}")


def has_rbac_permission(
    username, org_id, permission='advisor:*:*', request=None, account=None, is_org_admin=False
):
    """
    Check if this user in this account has the required permission.

    1. If RBAC is not enabled, this returns True
    2. If RBAC is enabled but no RBAC URL is specified, an exception is raised.
    3. The user's access information is requested from RBAC and compared with
       the given permission:
      a. The app must match, or the RBAC app must be '*'.
      b. The resource must match, or the RBAC resource must be '*'.
      c. The action must match, or the RBAC action must be '*', or the RBAC
        action is 'write' and the request's expected action is 'read' (i.e.
        if you have write access, you also have read access).

    This will attempt to cache the results from the RBAC so only one RBAC
    request is made per API request, even if this function is called more
    than once on the same request.

    Host group information is also found and stored in the request object.
    """
    if not settings.RBAC_ENABLED:
        return (True, 0.0)
    if not settings.RBAC_URL:
        raise Exception("RBAC enabled but no URL specified.")

    try:
        request_permission = RBACPermission(permission)
    except ValueError:
        raise ValueError(f"Permission '{permission}' needs to be in app:resource:access format")

    # BTW, annoyingly, Spectacular schema generation builds a new mock request
    # object for each request it makes.  So this request caching doesn't work
    # for schema generation; instead we just use a local cache dict.  The
    # only values RBAC cares about are the username and account, so that's the
    # key we use.
    auth_tuple = (username, org_id)
    if rbac_perm_cache is not None and auth_tuple in rbac_perm_cache:
        response = rbac_perm_cache[auth_tuple]
        elapsed = 0.0
    else:
        # Use PSK if it's defined, otherwise fallback to crafting an identity header for username
        separator = '&' if '?' in settings.RBAC_URL else '?'
        rbac_url = settings.RBAC_URL + separator + 'limit=1000'
        if settings.RBAC_PSK:
            rbac_header = {"x-rh-rbac-client-id": settings.RBAC_CLIENT_ID,
                           "x-rh-rbac-psk": settings.RBAC_PSK,
                           "x-rh-rbac-org-id": org_id,
                           "x-rh-rbac-account": account}
            rbac_url += "&username=" + username
        else:
            # Supply the full x-rh-identity header if we have it, because
            # that gives is_org_admin and other flags used by RBAC.
            if request and auth_header_key in request.META:
                # We don't want the other cruft in request.META...
                rbac_header = {
                    http_auth_header_key: request.META[auth_header_key]
                }
            else:
                rbac_header = auth_header_for_testing(
                    username=username, account=account, org_id=org_id,
                    supply_http_header=True, user_opts={'is_org_admin': is_org_admin},
                )

        # Do import here because of preloading of permissions classes - if
        # we do it in header then Django's test framework imports get confused.
        from api.utils import retry_request
        response, elapsed = retry_request('RBAC', rbac_url, headers=rbac_header, timeout=10)
        if (response is None) or response.status_code == 500:
            # Cannot reach RBAC at all, but should retry...
            return (False, elapsed)
        if rbac_perm_cache is not None:
            rbac_perm_cache[auth_tuple] = response

    if response.status_code == 200:
        data = response.json()
        if 'data' not in data:
            logger.warning(
                f"Warning: Response from RBAC did not contain a 'data' list: "
                f"'{response.content.decode()}'"
            )
            return (False, elapsed)
        tested_list = []
        # Find host group data
        find_host_groups(data['data'], request)
        # Find matching permission (ignoring resource definitions)
        for role_info in data['data']:
            if 'permission' not in role_info:
                continue
            try:
                rbac_permission = RBACPermission(role_info['permission'])
            except ValueError:
                logger.error(f"RBAC permission {role_info['permission']} could not be decoded correctly")
                continue
            tested_list.append(role_info['permission'])
            # Always OK on exact match
            if rbac_permission == request_permission:
                # Log and return exact match
                logger.info(f"RBAC permission '{rbac_permission}' exactly matched sought permission")
                return ({
                    'rbac_matched_permission': rbac_permission, 'rbac_match_type': 'exact'
                }, elapsed)

            if request_permission in rbac_permission:
                # Log and return inexact match
                logger.info(f"RBAC permission {rbac_permission} pattern matched sought permission {request_permission}")
                return ({
                    'rbac_matched_permission': rbac_permission, 'rbac_match_type': 'pattern'
                }, elapsed)
        logger.info(f"RBAC permissions list {tested_list} did not match sought permission {request_permission}")
        return (False, elapsed)
    else:
        logger.warning(f"Warning: Got status {response.status_code} from RBAC: '{response.content.decode()}'")
        return (False, elapsed)


def has_kessel_permission(
    scope: "ResourceScope", permission: RBACPermission, identity: dict,
    host_id: str | None = None
):
    """
    Check if this user in this account has the required permission.

    1. If Kessel is not enabled, this returns True
    2. If Kessel is enabled but no Kessel URL is specified, an exception is raised.
    3. The permission is checked against Kessel, depending on its scope.

    Host group information is also found and stored in the request object.
    """
    if not settings.RBAC_ENABLED:
        return (True, 0.0)

    # We don't use the RBAC cache here because the only time we cache RBAC
    # responses is during unit tests.

    try:
        # print(f"Checking {identity} has {permission} in {scope}...")
        logger.info("KESSEL: checking %s has %s in %s", identity, permission, scope)
        if scope == ResourceScope.ORG:
            # We actually translate this into the root workspace of that org.
            # print(f"... for org {identity['org_id']}")
            logger.info("KESSEL: checking access for org %s", identity['org_id'])
            # TODO: run check against org somehow (org itself, default, or root?)
            result, elapsed = kessel.client.check(
                kessel.Workspace(identity['org_id']).to_ref(),
                permission.as_kessel_permission(),
                kessel.identity_to_subject(identity))
        elif scope == ResourceScope.WORKSPACE:
            # print("... for workspace")
            logger.info("KESSEL: checking which workspaces this user has access to")
            # Lookup all the workspaces in which the permission is granted.
            result, elapsed = kessel.client.lookupResources(
                kessel.ObjectType("rbac", "workspace"),
                permission.as_kessel_permission(),
                kessel.identity_to_subject(identity))
        else:
            # Scope is a specific host.
            # Run a check against that host.
            if host_id is None:
                raise ValueError("TODO")

            # print(f"... for host {host_id}")
            logger.info("KESSEL: checking access to host %s", host_id)
            result, elapsed = kessel.client.check(
                kessel.HostId(str(host_id)).to_ref(),
                kessel.rbac_permission_to_relation(permission),
                kessel.identity_to_subject(identity)
            )

        # print(f"... returned {result} in {elapsed}s")
        logger.info("KESSEL: returned %s in %s", result, elapsed)
        return result, elapsed
    except Exception as e:
        # TODO elapsed time
        logger.warning(f"Warning: TODO error calling kessel for access check {e}'")
        return (False, 0.0)


def get_identity_header(request):
    """
    Get the identity structure from the request, `None` if no identity
    header was found in the request, or raise an error if decoding the
    identity structure failed somehow.
    """
    if auth_header_key not in request.META:
        return None
    # From here, if you have the header then you must get it correct.
    try:
        auth_header = json.loads(base64.b64decode(request.META[auth_header_key]))
    except Exception:
        error_and_deny(f"Unparseable {auth_header_key} data", str(request.META[auth_header_key]))
        return None  # noqa: mainly here to improve code analysis
    if not isinstance(auth_header, dict):
        error_and_deny(f"{auth_header_key} is not a structure", f"({auth_header})")

    if 'identity' not in auth_header:
        error_and_deny(f"'identity' section not found in {auth_header_key}")
    if not isinstance(auth_header['identity'], dict):
        error_and_deny(f"{auth_header_key} identity field is not a structure")
    setattr(request, 'rh_identity', auth_header['identity'])
    return auth_header['identity']


##############################################################################
# Authentication classes
##############################################################################


class RHIdentityAuthentication(BaseAuthentication):
    """
    Authenticate the user or service account in the X-RH-IDENTITY header information:

    * It should be a Base64-encoded JSON string
    * That should decode to a structure containing an 'identity' object
    * The identity object should have an 'org_id' property
    * The account number is no longer required, but will be present for the forseeable future

    Identity header for a User principal:
    "identity": {
        "account_number": "540155",
        "org_id": "1979710",
        "user": {
            "username": "rhn-support-pwayper",
            "is_internal": true,
            "is_org_admin": true,
            "first_name": "Paul",
            "last_name": "Wayper",
            "is_active": true,
            "locale": "en_US",
            "user_id": "7393748",
            "email": "paulway@redhat.com"
        },
        "auth_type": "jwt-auth",
        "internal": {
            "cross_access": false,
            "auth_time": 0,
            "org_id": "1979710"
        },
         "type": "User"
    },

    Identity header for a service account principal:
    "identity": {
        "auth_type": "jwt-auth",
        "internal": {
            "auth_time": 500,
            "cross_access": false,
            "org_id": "456"
        },
        "org_id": "456",
        "type": "ServiceAccount",
        "service_account": {
            "client_id": "b69eaf9e-e6a6-4f9e-805e-02987daddfbd",
            "username": "service-account-b69eaf9e-e6a6-4f9e-805e-02987daddfbd"
        }
    }

    This feeds data to the IsRedHatInternalUser and other permission
    classes, which actually give permission.  Other fields, such as user, service_account
    in the identity object are not checked for here.
    """
    message = 'Authentication failed'

    def authenticate(self, request):
        """
        If the user has an identity supplied in the X-RH-IDENTITY header
        (i.e. in {auth_header_key}), then they have authenticated with the
        3Scales and we trust them implicitly.
        """
        # If we have this cached, return the cached data.
        if hasattr(request, 'rh_identity') and hasattr(request, 'org_id'):
            return (request.org_id, request.rh_identity)

        identity = get_identity_header(request)
        if identity is None:
            # If we can't authenticate, then return nothing
            self.message = 'No identity information'
            return None

        if 'org_id' not in identity:
            self.message = f"'org_id' property not found in 'identity' section of {auth_header_key}"
            return None
        org_id = identity['org_id']

        if isinstance(org_id, int):
            org_id = str(org_id)
        if len(org_id) > 50:
            self.message = f"Org ID '{org_id}' greater than 50 characters"
            return None

        if settings.KESSEL_ENABLED:
            if 'user_id' not in identity['user']:
                self.message = "'user_id' property not found in 'user' section of identity"
                return None

        # Set the org_id
        setattr(request, 'org_id', org_id)

        # Although we only require org_id
        # We want to still retain account number information if possible
        # And still store/pass that along to other services
        # For potential backwards-compat issues for the foreseeable future
        account_number = identity['account_number'] if 'account_number' in identity else None
        setattr(request, 'account', account_number)

        # We're only concerned with the org id for most authentication,
        # not the username per se.  So we just hand the org id on as
        # the username.
        # This should really return user, identity...
        return (org_id, identity)


class TurnpikeIdentityAuthentication(BaseAuthentication):
    """
    Authenticate the user based on the X-RH-IDENTITY header information from
    Turnpike.  This takes the form of:

    {"identity": {
        "associate": {
            "email": "?", "givenName": "?", "surname": "?", "rhatUUID": "{uuid}",
            "Role": ["some-ldap-group", "another-ldap-group"]
        },
        "auth_type": "saml-auth",
        "type": "Associate"
    }}

    In particular we check

    * identity.auth_type == 'saml-auth'
    * identity.type == 'Associate'
    * identity.associate is a dict

    We don't at this point handle the X509 certificate identity from Turnpike.
    """
    def authenticate(self, request):
        """
        Check the identity header for basic compliance.
        """
        identity = get_identity_header(request)
        if identity is None:
            self.message = "could not decode identity header"
            return None

        # Check the properties we care about
        if "auth_type" not in identity:
            self.message = "'auth_type' not found in identity header"
            return None
        if not isinstance(identity['auth_type'], str):
            self.message = "identity.auth_type is not a string"
            return None
        if identity['auth_type'] != "saml-auth":
            return None
        if "type" not in identity:
            self.message = "'type' not found in identity header"
            return None
        if not isinstance(identity['type'], str):
            self.message = "identity.type is not a string"
            return None
        if identity['type'] != "Associate":
            return None
        if "associate" not in identity:
            self.message = "'associate' not found in identity header"
            return None
        if not isinstance(identity['associate'], dict):
            self.message = "identity.associate is not an object"
            return None

        # Save the associate identity in the request properties
        setattr(request, TP_ASSOCIATE, identity['associate'])
        return (identity['associate'], identity)


def set_resource(resource=None, scope: ResourceScope | None = None):
    # Return a decorator that sets the attribute on that function.
    def wrapper(fn):
        if resource is not None:
            setattr(fn, 'resource_name', resource)
        if scope is not None:
            setattr(fn, 'resource_scope', scope)
        return fn
    return wrapper


##############################################################################
# Permissions classes
##############################################################################


class ReadOnlyUser(BasePermission):
    """
    Authorise all users to use read-only methods.
    """
    message = 'Only read access is permitted'

    def has_permission(self, request, view):
        return request.method in SAFE_METHODS


class CertAuthPermission(BasePermission):
    """
    Authorise the access based on the system providing a certificate to
    authenticate itself.  In the `x-rh-identity` header this looks like:

    {
        "entitlements": {...stuff},
        "identity": {
            "account_number": "540155",
            "org_id": "1979710",
            "auth_type": "cert-auth",
            "system": {
                "cn": "0dd79821-a002-419a-90a6-29f8f1e7b0b1",
                "cert_type": "satellite"
            },
            "internal": {
                "cross_access": false,
                "auth_time": 0,
                "org_id": "1979710"
            },
            "type": "System"
        }
    }

    In particular we check:

    * The identity.type == 'System'
    * The identity.auth_type == 'cert-auth'
    * The identity.system is an object and has a 'cn' attribute.

    If these are true we allow the request, otherwise we deny it.

    We also set the `auth_system` attribute on the request, which allows
    queries to filter only on this system.
    """
    message = 'Red Hat Certificate Authentication has denied permission'

    def has_permission(self, request, view):
        if not (hasattr(request, 'user') and hasattr(request, 'auth')):
            self.message = 'not authenticated'
            return False
        identity = request.auth

        if identity is None:
            self.message = 'no identity'
            return False
        # This class only allows access for systems - see other classes such
        # as InsightsRBACPermission for allowing access to other types.
        if 'system' not in identity:
            self.message = "'system' property absent from identity object"
            return False

        # Failures in what we expect the system property to be:
        if not isinstance(identity['system'], dict):
            self.message = (
                f"'system' property is not an object in 'identity' section of "
                f"{auth_header_key} in Cert authentication check"
            )
            return False
        if 'cn' not in identity['system']:
            self.message = (
                f"'cn' property not found in 'identity.system' section of "
                f"{auth_header_key} in Cert authentication check"
            )
            return False
        if not isinstance(identity['system']['cn'], str):
            self.message = (
                "'identity.system.cn' is not a string in Cert authentication check"
            )
            return False
        try:
            uuid.UUID(identity['system']['cn'])
        except:
            self.message = (
                "'identity.system.cn' is not a UUID in Cert authentication check"
            )
            return False
        # Less important - remember what type of certificate this is:
        setattr(request, 'auth_system_type', identity['system'].get('cert_type', 'system'))

        # Save the system's UUID for later
        setattr(request, 'auth_system', identity['system']['cn'])
        # Set a username (for ack and hostack creation) - not really long enough for the CN...
        setattr(request, 'username', "Certified System")
        # We're a system, and we're allowed to access this view.
        return True


class InsightsRBACPermission(BasePermission):
    """
    Authorise the user based on their permissions from the Insights RBAC
    system.  If the RBAC_ENABLED setting is False, then everything is
    permitted (for testing, usually).  If it is True, then the function
    `has_rbac_permission` (above) is used to request the user's data from
    RBAC and compared with the permission required for this view.

    Permissions are made up of the app (set in the 'app' class property,
    defaulting to 'advisor'), the resource and the action as a
    colon-separated tuple, e.g. 'insights:results:read'. For both resource
    and action, '*' in the list of permissions returned by RBAC means 'all
    permitted'.

    The resource name is the first of:

    1. the 'resource_name' property set on the view method by the
       `set_resource()` decorator above.
    2. the 'resource_name' property of the viewset class.
    3. the base name of the viewset class, pluralised if singular.

    Actions are mapped by HTTP request type:

    * GET, HEAD and OPTIONS requests are 'read' actions.
    * All others - POST, PUT, PATCH, DELETE - are 'write' actions.

    Setting the resource name to 'denied' will deny access to that view by
    RBAC.  This is so that this class can be ORed with other permissions
    classes and one of them allows access; otherwise RBAC applies to every
    view in the viewset.
    """
    message = "Red Hat RBAC has denied you permission"
    app = 'advisor'

    def has_permission(self, request, view):
        # Returns true or false

        # Allow views to specify a specific resource name via its
        # 'resource_name' attribute, and if it doesn't have that default
        # to pluralising its basename.
        # The view's action property can be a name, or unset, or None - the
        # latter two we convert to 'list'.
        resource, scope = self._get_resource(view)
        if resource == 'denied':
            return False

        if scope is None:
            # TODO: error
            return False

        if not ((hasattr(request, 'user') or hasattr(request, 'service_account'))
                and hasattr(request, 'auth')):
            return False

        identity = request.auth
        # Do checks of the identity that we do have, in case some other class
        # allowed us:
        if identity is None:
            return False
        if not isinstance(identity, dict):
            return False
        if 'org_id' not in identity:
            return False
        if 'type' not in identity or identity['type'] not in user_details_key:
            return False
        type_key = user_details_key[identity['type']]
        if type_key not in identity or not isinstance(identity[type_key], dict):
            return False
        if 'username' not in identity[type_key]:
            return False
        if not isinstance(identity[type_key]['username'], str):
            return False
        username = identity[type_key]['username']
        is_org_admin = identity[type_key].get('is_org_admin', False)

        # Have to do this after the auth checks and view method check so that
        # views that deny access to RBAC can return False earlier than this.
        if not settings.RBAC_ENABLED:
            return True

        # Map the request and the view into the permission that the user
        # would need.  Permissions are of the form 'app:resource:action'.
        if request.method in SAFE_METHODS:
            action = 'read'
        else:
            action = 'write'

        permission = f'{self.app}:{resource}:{action}'
        # Probably can remove account number now...
        account_number = identity['account_number'] if 'account_number' in identity else None

        if not settings.KESSEL_ENABLED:
            result, elapsed = has_rbac_permission(
                username, identity['org_id'], permission, request._request,
                account=account_number, is_org_admin=is_org_admin
            )
        else:
            if scope == ResourceScope.HOST:
                # Let has_object_permission take care of it
                return True
            else:
                result, elapsed = has_kessel_permission(
                    scope, RBACPermission(permission), identity
                )
                # ORG level returns a single object, WORKSPACE level returns
                # a list.  We assume any list returned contains host group IDs.
                if isinstance(result, list):
                    setattr(request, host_group_attr, result)

        # Only record the non-cached response time
        if elapsed > 0.0:
            setattr(request._request, 'rbac_elapsed_time_millis', int(elapsed * 1000))
        # a rather ugly way of pushing the information about how this user
        # matched the needed RBAC permissions into the request object for
        # logging
        if isinstance(result, dict):
            for key, val in result.items():
                setattr(request._request, key, val)
        setattr(request._request, 'rbac_sought_permission', permission)
        return bool(result)

    def has_object_permission(self, request, view, obj):
        if not settings.KESSEL_ENABLED:
            return True

        resource, scope = self._get_resource(view)

        if scope != ResourceScope.HOST:
            return True

        # Map the request and the view into the permission that the user
        # would need.  Permissions are of the form 'app:resource:action'.
        if request.method in SAFE_METHODS:
            action = 'read'
        else:
            action = 'write'

        permission = f'{self.app}:{resource}:{action}'
        identity = request.auth

        # This is assumed to be used on a view that gets InventoryHost objects.
        if not hasattr(obj, "id"):
            raise ValueError("Permission scope is 'Host' but object has no 'id' attribute")

        result, elapsed = has_kessel_permission(
            scope, RBACPermission(permission), identity, host_id=obj.id
        )

        if elapsed > 0.0:
            setattr(request._request, 'rbac_elapsed_time_millis', int(elapsed * 1000))

        return result

    def _get_resource(self, view):
        """
        Returns the resource and its scope for a particular view.
        """

        view_name = getattr(view, 'action', None) or 'list'
        view_method = getattr(view, view_name, None)
        resource = getattr(view, 'resource_name', None)
        if resource is None and hasattr(view, 'basename'):
            resource = view.basename + ('' if view.basename[-1] == 's' else 's')
        if view_method is not None:
            resource = getattr(view_method, 'resource_name', resource)

        scope = getattr(view, 'resource_scope', ResourceScope.WORKSPACE)
        if view_method is not None:
            scope = getattr(view_method, 'resource_scope', scope)

        return resource, scope


class BaseAssociatePermission(BasePermission):
    """
    This is a base class for permissions that check the user data supplied in
    the `x-rh-identity` header by Turnpike.  This is internal Red Hat
    Associate data including name, email, and most importantly LDAP groups.

    If the list of allowed views is blank, then all views in the viewset that
    uses this permissions will check the associate's permission.  If one or
    more (capitalised) view names are given, then access to all other views
    is denied and only those given are allowed.  This makes sure that the
    permission can OR together with other permissions classes for the correct
    behaviour.
    """
    allowed_views = []
    message = "Access is restricted"

    def has_associate_permission(self, request, view, identity):
        """
        This method checks the associate's identity data supplied in the
        `x-rh-identity` header.  This must be overridden in derived classes.
        """
        raise NotImplementedError("Implement a check of Associate user data here")

    def has_permission(self, request, view):
        # Return OK if we're not restricting access, or we're viewing an
        # un-restricted view
        if not (hasattr(request, 'user') and hasattr(request, 'auth')):
            return False
        identity = request.auth
        if identity is None:
            return False

        # If allowed_views is set then we deny access to anything else and
        # check permissions on accesses to those views.  Otherwise we assume
        # that all access must be checked - i.e. that access to all views is
        # allowed as long as they've got this permission.
        if self.allowed_views:
            if not hasattr(self, 'allowed_view_methods'):
                self.allowed_view_methods = view_methods_dict(self.allowed_views)
            view_name = view.get_view_name()
            if view_name not in self.allowed_view_methods:
                return False
            if request.method not in self.allowed_view_methods[view_name]:
                return False

        return self.has_associate_permission(request, view, identity)


class AssociatePermission(BaseAssociatePermission):
    """
    Allow a user that's been authenticated with Turnpike.

    Hard coding LDAP groups or other permissions inside the DRF permissions
    system leads to conflicts with Turnpike when those permissions differ.
    For instance, if a new LDAP group is added to the list of groups allowed
    to access an endpoint, Turnpike will respond instantly but Advisor would
    need to be patched and re-released.  Therefore, we should only do those
    permissions checks within Turnpike.
    """

    def has_associate_permission(self, request, view, identity):
        # Basic 'associate' structure within the Turnpike identity.
        return 'associate' in identity


def view_methods_dict(allowed_views):
    """
    Construct the view methods dictionary for ease of reference later.
    Each view can occur more than once, as long as the associated method is
    unique.  I.e. you can have two 'GET' methods on different view names,
    and different methods on the same view name, but restricting the same
    view name and method twice has no further effect.
    """
    view_methods_dict = dict()
    for rv in allowed_views:
        if not isinstance(rv, tuple):
            rv = (rv, 'GET')
        (view, method) = rv
        if view not in view_methods_dict:
            view_methods_dict[view] = []
        view_methods_dict[view].append(method)
    return view_methods_dict


class BaseRedHatUserPermission(BasePermission):
    """
    This is a base class for permissions that check the user data supplied in
    the `x-rh-identity` header.  It is subclassed to provide specific checks
    on user data.

    Sometimes you only want a specific view method to be restricted and all
    others allowed.  If so, set the `allowed_views` property to a list of:

    * the view name, after DRF markup - e.g. 'Account Setting List', 'Stats'.
      The 'GET' method is assumed for these views
    * a tuple of (view name, method in upper case) - e.g. ('Account Settings
      List', 'POST').  This allows you to restrict methods that are normally
      named for their 'GET' method.

    If the `allowed_views` list is set, access to views that are not named
    will be denied.  This happens before the identity check.  If no allowed
    views are set, then access to all views must get permissions.  This is so
    that this class can be ORed together with other permissions classes and
    one of them will grant access.
    """
    allowed_views = []
    message = "Access is restricted"

    def has_red_hat_permission(self, request, view, user_data):
        """
        This method checks the user data supplied in the `x-rh-identity`
        header.  This must be overridden in derived classes.
        """
        raise NotImplementedError("Implement a check of Red Hat user data here")

    def has_permission(self, request, view):
        """
        Check if this user is allowed to view this view.

        The request must be authenticated using the RHIdentityAuthentication
        and the identity must include a 'user' key.

        If the 'allowed_views' property has been set (i.e. it's not an empty
        list) then the view's name (capitalised) is checked against the list.
        If this view is not in that list, or the combination of view and
        method are not in the list, then access is denied.  If no views are
        listed (i.e. the 'allowed_views' property is an empty list) then all
        views are assumed to be controlled by this permission check.

        The `has_red_hat_permission` method is then called to check if the
        user has the required permission or setting.  This is not implemented
        by default, so this class must be subclassed and that method
        implemented for this to work.
        """
        if not (hasattr(request, 'user') and hasattr(request, 'auth')):
            return False
        identity = request.auth
        if identity is None:
            return False
        if 'user' not in identity:
            return False

        # If allowed_views is set then we deny access to anything else and
        # check permissions on accesses to those views.  Otherwise we assume
        # that all access must be checked - i.e. that access to all views is
        # allowed as long as they've got this permission.
        if self.allowed_views:
            if not hasattr(self, 'allowed_view_methods'):
                self.allowed_view_methods = view_methods_dict(self.allowed_views)
            view_name = view.get_view_name()
            if view_name not in self.allowed_view_methods:
                self.message = f"{view_name} not in allowed views"
                return False
            if request.method not in self.allowed_view_methods[view_name]:
                self.message = f"{request.method} of {view_name} not allowed"
                return False

        return self.has_red_hat_permission(request, view, identity['user'])


class IsRedHatInternalUser(BaseRedHatUserPermission):
    """
    Authorise the user based on whether they have the 'is_internal' flag
    set in their user details.
    """
    message = "Access is restricted to Red Hat users"

    def has_red_hat_permission(self, request, view, user_data):
        return 'is_internal' in user_data and bool(user_data['is_internal'])


class OrgPermission(BasePermission):
    """
    Authorise any user with an `org_id` field in their identity.
    """
    message = "Permissions require an organisation ID"

    def has_permission(self, request, view):
        if not (hasattr(request, 'user') and hasattr(request, 'auth')):
            return False
        identity = request.auth
        if identity is None:
            return False
        return ('org_id' in identity)


##############################################################################
# Helper functions
##############################################################################


def request_to_username(request):
    """
    Get the user name from the current request, in the
    identity['user']['user_name'] field.
    """
    if hasattr(request, 'username') and request.username is not None:
        return request.username
    # Hack to use the decoder inside RHIdentityAuthentication
    rh = RHIdentityAuthentication()
    authentication = rh.authenticate(request)
    if authentication is None:
        return None
    org_id, identity = authentication
    # Because other systems besides the RBACPermission use this function, we
    # have to politely return nothing if we don't have a user section.
    if 'type' not in identity or identity['type'] not in user_details_key:
        return False
    type_key = user_details_key[identity['type']]
    if type_key not in identity:
        return None
    user_data = identity[type_key]
    if 'username' not in user_data:
        error_and_deny(
            f"'username' property not found in 'identity.user' section of "
            f"{auth_header_key}"
        )
    setattr(request, 'username', user_data['username'])
    return user_data['username']


def request_to_org(request):
    """
    Get the org id from the current request.  This is a string, even
    though the values are always whole numbers.

    If we cannot get the org id, for whatever reason, we raise a 403
    (Forbidden).  We don't want to send a WWW-Authenticate header, as this is
    not something the client can get by itself.
    """
    if request and hasattr(request, 'auth'):
        return request.auth['org_id'] if 'org_id' in request.auth else None
    # Otherwise decode and return it
    # Hack to use the decoder inside RHIdentityAuthentication
    rh = RHIdentityAuthentication()
    authentication = rh.authenticate(request)
    if authentication is None:
        return None
    org_id, identity = authentication
    if not org_id:
        return None
    return org_id


##############################################################################
# Authentication header generation
##############################################################################


def auth_header_for_testing(
    org_id=None, account=None, supply_http_header=False, username='testing',
    user_id='01234567-0123-0123-0123-0123456789ab', user_opts={},
    system_opts=None, unencoded=False, raw=None, service_account=None
) -> dict[str, str]:
    """
    Provide a JSON string which can be loaded into the 'x-rh-identity'
    header to provide access for testing.

    Returns:

        A dictionary with the header and its value.  This can then be added
        to for more complicated header declarations.

    Params:

        org_id: the organisation ID number (as a string), defaulting to
            '9876543'.  Set to '' to not supply an organisation ID.
        account: the account number (as a string), defaulting to '1234567'.
            Set to '' to not supply an account number.
        NOTE: you can't set both to ''.  That would cause the universe to
            implode.
        supply_http_header: if set to True, this sets the raw header type as
            opposed to one prefixed by 'HTTP_' and in upper case.  This is
            required if using auth_header_for_testing with `requests` (which
            adds the HTTP_ prefix) as opposed to using Django's test client
            (which doesn't).
        username: the username to supply if required (default: 'testing')
        user_id: the user id to supply if required (default: '123')
        user_opts: a dictionary with any extra parameters for the user options
            section.
        system_opts: a dictionary with system options.
        unencoded: supply the identity as a dict, rather than as a
            Base64-encoded JSON representation.
        raw: use whatever this is as the identity data and just return that.

    Notes:

    If `system_opts` is set, then the request is assumed to be from a system.
    In this case:
        * the `System` type is set
        * the `cert-auth` auth_type is set
        * user information is ignored.

    Output:

        With no parameters:

            {'HTTP_X_RH_IDENTITY': 'xxx'}

            'xxx' here is the Base64 encoding of the JSON encoding of:

            {'identity': {
                'account': '1234567', 'type': 'User', 'auth_type': 'jwt',
                'user': {'username': 'testing'}
            }}

    Usage:

        >>> # Get the '/api/rule/' URL with the standard auth header.
        >>> client.get('/api/rule/', **auth_header_for_testing())
        >>> # Get the '/api/rule/' URL with a different account number.
        >>> client.get('/api/rule/', **auth_header_for_testing('9876543'))
        >>> # Send a custom header as well as the auth headers.
        >>> headers = auth_header_for_testing()
        >>> headers['REMOTE_HOST'] = 'foo.example.com'
        >>> client.get('/api/rule/', **headers)

    THIS DOES NOT ATTEMPT TO CREATE THE FULL STRUCTURE OF THE IDENTITY.

    THIS DOES NOT ATTEMPT TO CREATE A RECORD THAT WILL PASS ALL FORMS OF
    AUTHENTICATION.  But it's pretty close...
    """
    my_auth_header_key = http_auth_header_key if supply_http_header else auth_header_key
    if raw:
        return {my_auth_header_key: raw}
    identity = {}
    # Set account/org_id to default if not supplied, or value if not ''
    if org_id:
        identity['org_id'] = org_id
    elif org_id is None:
        identity['org_id'] = '9876543'
    if account:
        identity['account_number'] = account
    elif account is None:
        identity['account_number'] = '1234567'
    if org_id in identity:
        # org_id also appears in the 'internal' section for some reason
        identity['internal'] = {
            'org_id': identity['org_id']
        }
    # In the future, when account is no longer
    # We need at least one of those two to be valid...
    if not identity:
        error_and_deny("both account and org_id cannot be empty")
    if system_opts and user_opts:
        error_and_deny("'system-opts' cannot be used with 'user_opts'")
    if system_opts:
        identity['system'] = system_opts
        identity['type'] = 'System'
    elif service_account:
        identity['service_account'] = service_account
        identity['type'] = 'ServiceAccount'
    else:
        user_section = dict(user_opts)
        if username is not None:
            user_section['username'] = username
        if user_id is not None:
            # Don't actually store the user_id as a UUID, just validate that
            # it is one.
            try:
                uuid.UUID(user_id)
            except ValueError:
                raise ValueError(
                    "'user_id' argument to auth_header_for_testing must be a "
                    "valid UUID"
                )
            user_section['user_id'] = user_id
        identity['user'] = user_section
        identity['type'] = 'User'
    auth_value = {'identity': identity}
    if unencoded:
        return auth_value
    return {my_auth_header_key: base64.b64encode(json.dumps(auth_value).encode())}


def turnpike_auth_header_for_testing(**kwargs):
    """
    Construct a dictionary that provides the Base64-encoded JSON string of a
    Turnpike authentication structure.  All arguments given are turned into
    a dictionary in the identity.associate property, overriding some basic
    test defaults (including having no LDAP roles).
    """
    associate_defs = {
        'Role': [], 'email': 'testuser@redhat.com', 'givenName': 'Test',
        'surname': 'User', 'rhatUUID': "01234567-89ab-cdef-0123-456789abcdef"
    }
    associate_defs.update(kwargs)  # doesn't return the dict...
    auth_dict = {'identity': {
        'associate': associate_defs,
        'auth_type': 'saml-auth', 'type': 'Associate'
    }}
    return {auth_header_key: base64.b64encode(json.dumps(auth_dict).encode())}


def auth_to_request(auth_dict):
    """
    Create a request object from a dictionary, given by either
    `auth_header_for_testing` or `turnpike_auth_header_for_testing`.
    """
    request = HttpRequest()
    request.META = auth_dict
    request.META['REMOTE_ADDR'] = 'test'
    request.method = 'GET'
    request.query_params = MultiValueDict()
    request.auth = {}
    return request


def request_object_for_testing(auth_by=None, *args, **kwargs):
    """
    Create a request object with the auth header constructed by
    `auth_header_for_testing` above.
    """
    rq = auth_to_request(auth_header_for_testing(*args, **kwargs))
    if auth_by:
        # auth_by is a class
        auth_tuple = auth_by().authenticate(rq)
        if auth_tuple is not None:
            setattr(rq, 'user', auth_tuple[0])
            setattr(rq, 'auth', auth_tuple[1])
    setattr(rq, '_request', HttpRequest())
    return rq


def request_header_data(request):
    """
    Reframe the request's authentication data in to a dict with the key that
    the 'requests' module can use.
    """
    return {http_auth_header_key: request.META[auth_header_key]}


##############################################################################
# Authentication schema definition
##############################################################################

class RHIdentityAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    This gets picked up automatically by drf_spectacular grovelling through
    every module in our API.  Wild.
    """
    target_class = 'api.permissions.RHIdentityAuthentication'
    name = http_auth_header_key

    def get_security_definition(self, auto_schema):
        # See https://spec.openapis.org/oas/v3.0.3#security-scheme-object
        # There's no way in that spec to describe what form the
        return {
            'type': 'apiKey', 'in': 'header', 'name': http_auth_header_key,
            # 'examples': [
            #     'Base 64 encoded JSON object with an "identity" key',
            # ],
        }
