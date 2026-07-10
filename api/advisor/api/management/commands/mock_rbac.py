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
A mock RBAC/Kessel server for local development.

Supports two modes:

1. RBAC v1 mode (default):
   Serves GET /api/rbac/v1/access/ with configurable permissions.
   Also serves /api/rbac/v2/workspaces/ for workspace ID lookups.

2. Kessel mode (--kessel-enabled):
   Additionally starts a gRPC server implementing KesselInventoryService
   (Check and StreamedListObjects RPCs).  The HTTP server serves both
   RBAC v1 access and RBAC v2 workspace endpoints.

Usage (command line):
    python api/advisor/manage.py mock_rbac
    python api/advisor/manage.py mock_rbac --rbac-readonly
    python api/advisor/manage.py mock_rbac --rbac-host-groups id1,id2
    python api/advisor/manage.py mock_rbac --kessel-enabled
    python api/advisor/manage.py mock_rbac --kessel-enabled --kessel-deny
    python api/advisor/manage.py mock_rbac --kessel-enabled --kessel-host-groups id1,id2

Usage (environment variables, e.g. in podman-compose):
    MOCK_RBAC_PORT=8111              HTTP port (default: 8111)
    MOCK_RBAC_READONLY=true          Read-only permissions (default: false)
    MOCK_RBAC_PERMISSIONS=...        Comma-separated permission strings
    MOCK_RBAC_HOST_GROUPS=id1,id2    Comma-separated host group UUIDs (RBAC v1)
    MOCK_KESSEL_ENABLED=true         Enable Kessel gRPC server
    MOCK_KESSEL_PORT=9000       gRPC port (default: 9000)
    MOCK_KESSEL_DENY=true            Deny all Kessel permission checks
    MOCK_KESSEL_HOST_GROUPS=id1,id2  Workspace IDs for StreamedListObjects
    MOCK_KESSEL_WORKSPACE_ID=...     Default workspace UUID

Command-line arguments take precedence over environment variables.

For RBAC v1 mode, set on the Advisor API:
    RBAC_ENABLED=true
    RBAC_URL=http://mock-rbac:8111

For Kessel mode, set on the Advisor API:
    KESSEL_ENABLED=true
    KESSEL_URL=mock-rbac:9000
    KESSEL_INSECURE=true
    RBAC_ENABLED=true
    RBAC_URL=http://mock-rbac:8111
"""

import base64
import json
import os
import threading
from concurrent import futures
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from django.core.management.base import BaseCommand
from advisor_logging import logger


# Full read-write permissions for all three applications that Advisor
# requests from RBAC (see permissions.py make_rbac_url call).
ALL_RW_PERMISSIONS = [
    'advisor:*:*',
    'tasks:*:*',
    'inventory:*:*',
]

ALL_RO_PERMISSIONS = [
    'advisor:*:read',
    'tasks:*:read',
    'inventory:*:read',
]

DEFAULT_WORKSPACE_ID = '00000000-0000-0000-0000-000000000000'


def string_to_bool(value):
    """Convert a string to a boolean, matching the project's convention."""
    return value.lower() in ('true', '1', 'yes') if value else False


def build_rbac_response(permissions, host_groups=None):
    """
    Build an RBAC v1 access response matching the format expected by
    has_rbac_permission() and find_host_groups() in permissions.py.
    """
    data = []
    for perm in permissions:
        # When host groups are specified, exclude inventory permissions with
        # empty resourceDefinitions.  find_host_groups() in permissions.py
        # returns early (granting full access) when it encounters any
        # inventory:hosts:read-matching permission with no resourceDefinitions,
        # so any such entry (e.g. inventory:*:*) would override the
        # group-filtered entry we add below.
        if host_groups is not None and perm.startswith('inventory:'):
            continue
        entry = {
            'permission': perm,
            'resourceDefinitions': [],
        }
        data.append(entry)

    # If host groups are specified, add an inventory:hosts:read entry
    # with resourceDefinitions containing group.id filters.  Without
    # this, the user has access to all hosts (no filtering).
    if host_groups is not None:
        data.append({
            'permission': 'inventory:hosts:read',
            'resourceDefinitions': [{
                'attributeFilter': {
                    'key': 'group.id',
                    'value': host_groups,
                    'operation': 'in',
                }
            }],
        })

    return {'data': data}


###############################################################################
# HTTP handler (serves both RBAC v1 and v2 endpoints)
###############################################################################


class RBACRequestHandler(BaseHTTPRequestHandler):
    """
    Handle GET requests to /api/rbac/v1/access/ and
    /api/rbac/v2/workspaces/.
    """

    def _username_from_identity(self):
        """Extract the username from the x-rh-identity header."""
        header = self.headers.get('x-rh-identity')
        if not header:
            return None
        try:
            decoded_header = base64.b64decode(header)
            identity_wrapper = json.loads(decoded_header)
        except Exception as exc:
            logger.debug("Failed to decode x-rh-identity header: %s", exc)
            return None

        identity = identity_wrapper.get('identity') or {}
        # Check user, then service_account (see user_details_key in permissions.py)
        for key in ('user', 'service_account'):
            username = identity.get(key, {}).get('username')
            if username:
                return username

        logger.debug("x-rh-identity header present but no username found in 'user' or 'service_account'")
        return None

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == '/api/rbac/v1/access/':
            applications = query.get('application', [''])[0].split(',')
            username = query.get('username', [None])[0]
            if username is None:
                username = self._username_from_identity()

            logger.info("RBAC v1 access request: applications=%s username=%s", applications, username)

            response_body = json.dumps(self.server.rbac_response).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            logger.info("RBAC v1 access response: %s", response_body)

        elif parsed.path == '/api/rbac/v2/workspaces/':
            workspace_type = query.get('type', ['default'])[0]
            logger.info("RBAC v2 workspace request: type=%s", workspace_type)
            workspace_response = {
                'data': [{
                    'id': self.server.workspace_id,
                    'name': workspace_type,
                    'type': workspace_type,
                    'description': f'{workspace_type} workspace',
                }]
            }
            response_body = json.dumps(workspace_response).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            logger.info("RBAC v2 workspace response: %s", response_body)

        else:
            logger.warning("Unknown path: %s", self.path)
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "not found"}')


###############################################################################
# Kessel gRPC servicer (only used when --kessel-enabled is set)
###############################################################################


def _get_kessel_imports():
    """Import Kessel gRPC modules on demand so the command works without
    them when Kessel mode is not enabled."""
    import grpc  # noqa: F811
    from kessel.inventory.v1beta2 import (
        allowed_pb2,
        check_response_pb2,
        inventory_service_pb2_grpc,
        resource_reference_pb2,
        reporter_reference_pb2,
        response_pagination_pb2,
        streamed_list_objects_response_pb2,
    )
    return {
        'grpc': grpc,
        'allowed_pb2': allowed_pb2,
        'check_response_pb2': check_response_pb2,
        'inventory_service_pb2_grpc': inventory_service_pb2_grpc,
        'resource_reference_pb2': resource_reference_pb2,
        'reporter_reference_pb2': reporter_reference_pb2,
        'response_pagination_pb2': response_pagination_pb2,
        'streamed_list_objects_response_pb2': streamed_list_objects_response_pb2,
    }


def _make_kessel_servicer(kessel_modules, allow_all, host_groups):
    """Create a MockKesselServicer that inherits from the gRPC base class.

    The base class is imported lazily, so we build the class dynamically
    to avoid importing gRPC/Kessel at module load time.
    """
    km = kessel_modules  # Renamed to km to save repeating the full variable name
    base = km['inventory_service_pb2_grpc'].KesselInventoryServiceServicer

    class MockKesselServicer(base):
        """
        A mock KesselInventoryService that responds to Check and
        StreamedListObjects.  All other RPCs return UNIMPLEMENTED
        (inherited from the base class).
        """

        def Check(self, request, context):
            """Permission check: does subject X have relation Y on object Z?"""
            allowed = (
                km['allowed_pb2'].ALLOWED_TRUE
                if allow_all
                else km['allowed_pb2'].ALLOWED_FALSE
            )
            result_str = 'ALLOWED' if allow_all else 'DENIED'
            context.set_code(km['grpc'].StatusCode.OK)
            logger.info(
                "Check: subject=%s relation=%s object=%s/%s -> %s",
                request.subject.resource.resource_id,
                request.relation,
                request.object.resource_type,
                request.object.resource_id,
                result_str,
            )
            return km['check_response_pb2'].CheckResponse(allowed=allowed)

        def StreamedListObjects(self, request, context):
            """
            List the workspaces (host groups) this subject has the given
            relation to.
            """
            subject_id = request.subject.resource.resource_id
            relation = request.relation
            object_type = request.object_type.resource_type
            logger.info(
                "StreamedListObjects request: subject=%s relation=%s object_type=%s -> %d workspace(s)",
                subject_id, relation, object_type, len(host_groups or []),
            )
            if not host_groups:
                logger.info("StreamedListObjects response: no host groups/workspaces configured, access will be denied")
                return
            for group_id in host_groups:
                response = km['streamed_list_objects_response_pb2'].StreamedListObjectsResponse(
                    object=km['resource_reference_pb2'].ResourceReference(
                        resource_id=group_id,
                        resource_type="workspace",
                        reporter=km['reporter_reference_pb2'].ReporterReference(
                            type="rbac"
                        ),
                    ),
                    pagination=km['response_pagination_pb2'].ResponsePagination(
                        continuation_token="",
                    ),
                )
                logger.info("StreamedListObjects response yielding: %s", response.object)
                yield response

    return MockKesselServicer()


###############################################################################
# Management command
###############################################################################


class Command(BaseCommand):
    help = (
        'Run a mock RBAC server for local development. '
        'Serves /api/rbac/v1/access/ and /api/rbac/v2/workspaces/. '
        'With --kessel-enabled, also runs a Kessel gRPC server for Check and '
        'StreamedListObjects RPCs. '
        'Options can also be set via environment variables.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--rbac-port', type=int, default=None,
            help='HTTP port to listen on (env: MOCK_RBAC_PORT, default: 8111)',
        )
        parser.add_argument(
            '--rbac-readonly', action='store_true', default=None,
            help='Grant read-only permissions instead of full read-write (env: MOCK_RBAC_READONLY)',
        )
        parser.add_argument(
            '--rbac-permissions', type=str, default=None,
            help=(
                'Comma-separated list of custom permission strings to return '
                '(e.g. "advisor:*:*,tasks:*:read"). '
                'Overrides --rbac-readonly. (env: MOCK_RBAC_PERMISSIONS)'
            ),
        )
        parser.add_argument(
            '--rbac-host-groups', type=str, default=None,
            help=(
                'Comma-separated list of host group UUIDs to restrict access to '
                '(RBAC v1 resourceDefinitions). '
                'Use "null" to include ungrouped hosts. '
                'If not set, the user has unrestricted access to all hosts. '
                '(env: MOCK_RBAC_HOST_GROUPS)'
            ),
        )
        # Kessel options
        parser.add_argument(
            '--kessel-enabled', action='store_true', default=None,
            help='Enable the Kessel gRPC server (env: MOCK_KESSEL_ENABLED)',
        )
        parser.add_argument(
            '--kessel-port', type=int, default=None,
            help='gRPC port for Kessel (env: MOCK_KESSEL_PORT, default: 9000)',
        )
        parser.add_argument(
            '--kessel-deny', action='store_true', default=None,
            help='Deny all Kessel permission checks (env: MOCK_KESSEL_DENY)',
        )
        parser.add_argument(
            '--kessel-host-groups', type=str, default=None,
            help=(
                'Comma-separated list of workspace/host group UUIDs returned '
                'by Kessel StreamedListObjects. REQUIRED for Kessel mode: '
                'the Advisor API denies access when no workspaces are returned. '
                'Use the default workspace ID for full access. (env: MOCK_KESSEL_HOST_GROUPS)'
            ),
        )
        parser.add_argument(
            '--kessel-workspace-id', type=str, default=None,
            help=(
                'The default workspace UUID returned by the RBAC v2 '
                'workspace endpoint. (env: MOCK_KESSEL_WORKSPACE_ID, '
                f'default: {DEFAULT_WORKSPACE_ID})'
            ),
        )

    def handle(self, *args, **options):
        # ----- Resolve RBAC v1 options -----
        port = options['rbac_port']
        if port is None:
            port = int(os.environ.get('MOCK_RBAC_PORT', '8111'))

        permissions_str = options['rbac_permissions']
        if permissions_str is None:
            permissions_str = os.environ.get('MOCK_RBAC_PERMISSIONS')

        readonly = options['rbac_readonly']
        if readonly is None:
            readonly = string_to_bool(os.environ.get('MOCK_RBAC_READONLY', ''))

        groups_str = options['rbac_host_groups']
        if groups_str is None:
            groups_str = os.environ.get('MOCK_RBAC_HOST_GROUPS')

        # Determine permissions
        if permissions_str:
            permissions = [p.strip() for p in permissions_str.split(',')]
        elif readonly:
            permissions = list(ALL_RO_PERMISSIONS)
        else:
            permissions = list(ALL_RW_PERMISSIONS)

        # Determine host groups (RBAC v1)
        # "null" is converted to None, which serializes as JSON null in the
        # RBAC response.  find_host_groups() in permissions.py passes this
        # through to get_host_group_filter() in models.py, which translates
        # None into a filter for hosts with an empty groups list (ungrouped).
        host_groups = None
        if groups_str:
            host_groups = [
                None if g.strip() == 'null' else g.strip()
                for g in groups_str.split(',')
            ]

        rbac_response = build_rbac_response(permissions, host_groups)

        # ----- Resolve Kessel options -----
        kessel_enabled = options['kessel_enabled']
        if kessel_enabled is None:
            kessel_enabled = string_to_bool(
                os.environ.get('MOCK_KESSEL_ENABLED', '')
            )

        grpc_port = options['kessel_port']
        if grpc_port is None:
            grpc_port = int(os.environ.get('MOCK_KESSEL_PORT', '9000'))

        deny = options['kessel_deny']
        if deny is None:
            deny = string_to_bool(os.environ.get('MOCK_KESSEL_DENY', ''))

        kessel_host_groups_str = options['kessel_host_groups']
        if kessel_host_groups_str is None:
            kessel_host_groups_str = os.environ.get('MOCK_KESSEL_HOST_GROUPS')

        workspace_id = options['kessel_workspace_id']
        if workspace_id is None:
            workspace_id = os.environ.get(
                'MOCK_KESSEL_WORKSPACE_ID', DEFAULT_WORKSPACE_ID
            )

        if kessel_host_groups_str:
            kessel_host_groups = [
                g.strip() for g in kessel_host_groups_str.split(',')
            ]
        else:
            kessel_host_groups = None

        # ----- Print configuration -----
        mode = 'Kessel + RBAC v1' if kessel_enabled else 'RBAC v1'
        logger.info('Mock RBAC server starting (%s mode)', mode)
        logger.info('  HTTP port: %s', port)
        logger.info('  Permissions (RBAC v1): %s', permissions)
        if host_groups:
            logger.info('  Host groups (RBAC v1): %s', host_groups)
        else:
            logger.info('  Host groups (RBAC v1): unrestricted (all hosts)')
        logger.info('  Workspace ID: %s', workspace_id)

        if kessel_enabled:
            allow_all = not deny
            check_str = 'ALLOW' if allow_all else 'DENY'
            logger.info('  gRPC port: %s', grpc_port)
            logger.info(
                '  Kessel Check RPC (--kessel-deny): %s',
                'ALLOW all' if allow_all else 'DENY all',
            )
            if kessel_host_groups:
                logger.info(
                    '  Kessel StreamedListObjects (--kessel-host-groups): %s',
                    kessel_host_groups,
                )
            else:
                logger.info(
                    '  Kessel StreamedListObjects (--kessel-host-groups): none'
                )
            # Show effective access per scope
            workspace_access = 'ALLOW' if kessel_host_groups else 'DENY'
            logger.info('  Effective access by scope:')
            logger.info('    ORG scope  (Check RPC):              %s', check_str)
            logger.info('    HOST scope (Check RPC):              %s', check_str)
            if kessel_host_groups:
                groups_str = ', '.join(kessel_host_groups)
                logger.info('    WORKSPACE scope (StreamedListObjects): %s [%s]', workspace_access, groups_str)
            else:
                logger.info('    WORKSPACE scope (StreamedListObjects): %s', workspace_access)
            if not kessel_host_groups:
                logger.warning(
                    '  Most endpoints use WORKSPACE scope and will '
                    'be denied. Use --kessel-host-groups with the default workspace '
                    'ID %s for full access.', workspace_id,
                )

        logger.info('RBAC v1 response payload:')
        logger.info(json.dumps(rbac_response, indent=2))

        # ----- Start Kessel gRPC server (if enabled) -----
        grpc_server = None
        if kessel_enabled:
            kessel_modules = _get_kessel_imports()
            allow_all = not deny
            servicer = _make_kessel_servicer(
                kessel_modules,
                allow_all=allow_all,
                host_groups=kessel_host_groups,
            )
            grpc_server = kessel_modules['grpc'].server(
                futures.ThreadPoolExecutor(max_workers=4)
            )
            kessel_modules['inventory_service_pb2_grpc'] \
                .add_KesselInventoryServiceServicer_to_server(
                    servicer, grpc_server
                )
            # Enable gRPC reflection so tools like grpcurl can discover services.
            from grpc_reflection.v1alpha import reflection
            from kessel.inventory.v1beta2 import inventory_service_pb2
            service_names = (
                inventory_service_pb2.DESCRIPTOR.services_by_name['KesselInventoryService'].full_name,
                reflection.SERVICE_NAME,
            )
            reflection.enable_server_reflection(service_names, grpc_server)
            grpc_server.add_insecure_port(f'0.0.0.0:{grpc_port}')
            grpc_server.start()
            logger.info('gRPC server listening on 0.0.0.0:%s', grpc_port)

        # ----- Start HTTP server -----
        server = HTTPServer(('0.0.0.0', port), RBACRequestHandler)
        server.allow_reuse_address = True
        server.rbac_response = rbac_response
        server.workspace_id = workspace_id

        logger.info('HTTP server listening on 0.0.0.0:%s', port)

        if grpc_server:
            # Run HTTP in a background thread, gRPC blocks on main thread
            http_thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            http_thread.start()
            try:
                grpc_server.wait_for_termination()
            except KeyboardInterrupt:
                logger.info('Shutting down mock RBAC + Kessel servers.')
                grpc_server.stop(grace=0)
                server.shutdown()
        else:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                logger.info('Shutting down mock RBAC server.')
                server.server_close()