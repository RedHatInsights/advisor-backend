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
A simple mock RBAC v1 HTTP server for local development.

Responds to GET /api/rbac/v1/access/ with a full set of advisor, tasks,
and inventory permissions so that all Advisor API endpoints are accessible.

Usage (command line):
    python api/advisor/manage.py mock_rbac
    python api/advisor/manage.py mock_rbac --port 8111
    python api/advisor/manage.py mock_rbac --readonly
    python api/advisor/manage.py mock_rbac --groups id1,id2

Usage (environment variables, e.g. in podman-compose):
    MOCK_RBAC_PORT=8111          Port to listen on (default: 8111)
    MOCK_RBAC_READONLY=true      Read-only permissions (default: false)
    MOCK_RBAC_PERMISSIONS=...    Comma-separated permission strings
    MOCK_RBAC_GROUPS=id1,id2     Comma-separated host group UUIDs

Command-line arguments take precedence over environment variables.

Then set RBAC_ENABLED=true and RBAC_URL=http://mock-rbac:8111 when running
the Advisor API.
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from django.core.management.base import BaseCommand


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


class RBACRequestHandler(BaseHTTPRequestHandler):
    """
    Handle GET requests to /api/rbac/v1/access/ and return mock RBAC
    permission data.
    """

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == '/api/rbac/v1/access/':
            applications = query.get('application', [''])[0].split(',')
            username = query.get('username', [None])[0]

            self.log_message(
                "RBAC access request: applications=%s username=%s",
                applications, username
            )

            response_body = json.dumps(self.server.rbac_response).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        elif parsed.path == '/api/rbac/v2/workspaces/':
            # Kessel uses this endpoint to look up the default workspace ID.
            # Provide a minimal response for local dev if needed.
            workspace_type = query.get('type', ['default'])[0]
            self.log_message(
                "RBAC v2 workspace request: type=%s", workspace_type
            )
            workspace_response = {
                'data': [{
                    'id': '00000000-0000-0000-0000-000000000000',
                    'name': workspace_type,
                    'type': workspace_type,
                }]
            }
            response_body = json.dumps(workspace_response).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        else:
            self.log_message("Unknown path: %s", self.path)
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "not found"}')


class Command(BaseCommand):
    help = (
        'Run a mock RBAC v1 HTTP server for local development. '
        'Responds to /api/rbac/v1/access/ with configurable permissions. '
        'Options can also be set via environment variables: '
        'MOCK_RBAC_PORT, MOCK_RBAC_READONLY, MOCK_RBAC_PERMISSIONS, MOCK_RBAC_GROUPS.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--port', type=int, default=None,
            help='Port to listen on (env: MOCK_RBAC_PORT, default: 8111)',
        )
        parser.add_argument(
            '--readonly', action='store_true', default=None,
            help='Grant read-only permissions instead of full read-write (env: MOCK_RBAC_READONLY)',
        )
        parser.add_argument(
            '--permissions', type=str, default=None,
            help=(
                'Comma-separated list of custom permission strings to return '
                '(e.g. "advisor:*:*,tasks:*:read"). '
                'Overrides --readonly. (env: MOCK_RBAC_PERMISSIONS)'
            ),
        )
        parser.add_argument(
            '--groups', type=str, default=None,
            help=(
                'Comma-separated list of host group UUIDs to restrict access to. '
                'If not set, the user has unrestricted access to all hosts. '
                '(env: MOCK_RBAC_GROUPS)'
            ),
        )

    def handle(self, *args, **options):
        # Resolve each option: command-line arg takes precedence, then env var,
        # then default.
        port = options['port']
        if port is None:
            port = int(os.environ.get('MOCK_RBAC_PORT', '8111'))

        permissions_str = options['permissions']
        if permissions_str is None:
            permissions_str = os.environ.get('MOCK_RBAC_PERMISSIONS')

        readonly = options['readonly']
        if readonly is None:
            readonly = string_to_bool(os.environ.get('MOCK_RBAC_READONLY', ''))

        groups_str = options['groups']
        if groups_str is None:
            groups_str = os.environ.get('MOCK_RBAC_GROUPS')

        # Determine permissions
        if permissions_str:
            permissions = [p.strip() for p in permissions_str.split(',')]
        elif readonly:
            permissions = list(ALL_RO_PERMISSIONS)
        else:
            permissions = list(ALL_RW_PERMISSIONS)

        # Determine host groups
        host_groups = None
        if groups_str:
            host_groups = [g.strip() for g in groups_str.split(',')]

        rbac_response = build_rbac_response(permissions, host_groups)

        self.stdout.write(self.style.SUCCESS(f'Mock RBAC server starting on port {port}'))
        self.stdout.write(f'  Permissions: {permissions}')
        if host_groups:
            self.stdout.write(f'  Host groups: {host_groups}')
        else:
            self.stdout.write('  Host groups: unrestricted (all hosts)')
        self.stdout.write('')
        self.stdout.write('Response payload:')
        self.stdout.write(json.dumps(rbac_response, indent=2))
        self.stdout.write('')

        server = HTTPServer(('0.0.0.0', port), RBACRequestHandler)
        server.allow_reuse_address = True
        server.rbac_response = rbac_response
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down mock RBAC server.'))
            server.server_close()