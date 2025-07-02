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

from collections import OrderedDict
import requests

from django.conf import settings
from django.db import connection

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.reverse import reverse

from api.permissions import auth_header_for_testing
from api.serializers import StatusReadySerializer

from drf_spectacular.utils import extend_schema


class StatusViewSet(viewsets.ViewSet):
    """
    Simple status information for readiness / liveness checks.
    """
    authentication_classes = []
    permission_classes = []
    # The 'list' is just a path list of the status views available.
    serializer_class = None

    def list(self, request, format=None):
        """
        Provide a simple list of URLs contained here.

        A list of statistics views.
        """
        urls = OrderedDict()
        for method in self.get_extra_actions():
            urls[method.url_name] = reverse(
                'status-' + method.url_name, request=request
            )
        return Response(urls)

    @action(detail=False)
    @extend_schema(
        responses={200: StatusReadySerializer(many=False)},
    )
    def ready(self, request, format=None):
        """
        Is the Advisor API ready to serve requests?

        This returns a dictionary with properties defining the status of the
        components Advisor relies on.

        * 'django' should always be True.  If Django isn't ready, you can't
          get this information :-)
        * 'database' is True when a database access returns successfully with
          valid information.
        * 'rbac' is True when we can make a request to the RBAC API and get
          a valid response.
        * 'advisor' is True if all of the above are True.
        """
        status = {
            'django': True, 'database': False, 'rbac': False,
            'environment': False, 'advisor': False,
        }
        errors = []
        # Database?
        try:
            cursor = connection.cursor()
            cursor.execute('''SELECT 1;''')
            cursor.fetchone()
            cursor.close()
            status['database'] = True
        except Exception as e:
            errors.append(f"Error connecting to database: {e}")
        # RBAC?
        try:
            if settings.RBAC_ENABLED:
                rbac_header = auth_header_for_testing(
                    username='test', account='540155', org_id='1979710', supply_http_header=True
                )
                # Use a basic timeout of 5 seconds here, no retries
                response = requests.get(
                    settings.RBAC_URL, headers=rbac_header, timeout=5
                )
                status['rbac'] = response.status_code == 200
                if response.status_code != 200:
                    errors.append(
                        f"Connection to RBAC returned {response.status_code}: "
                        f"{response.content.decode()}"
                    )
            else:
                status['rbac'] = True
        except Exception as e:
            errors.append(f"Error connecting to RBAC: {e}")
        # Environment?
        status['environment'] = True
        for var in (
            'RBAC_URL', 'MIDDLEWARE_HOST_URL', 'INVENTORY_SERVER_URL',
            'REMEDIATIONS_URL',
        ):
            # Quick hack for when RBAC isn't enabled
            if var == 'RBAC_URL' and not settings.RBAC_ENABLED:
                continue
            if not hasattr(settings, var):
                status['environment'] = False
                errors.append(f"Environment error: {var} not present in settings")
            elif not getattr(settings, var):
                status['environment'] = False
                errors.append(f"Environment error: {var} not set")

        # Therefore Advisor?
        status['advisor'] = all(
            status[part] for part in status.keys()
            if part != 'advisor'
        )
        status['errors'] = errors
        return Response(StatusReadySerializer(
            status, many=False, context={'request': request}
        ).data)

    @action(detail=False)
    @extend_schema(
        responses={200: StatusReadySerializer(many=False)},
    )
    def live(self, request, format=None):
        """
        Is the Advisor API live and serving requests?

        This returns a dictionary with properties defining the status of the
        components Advisor relies on.

        At the moment this is the same as the Readiness check (see `/ready/`).
        In the future it may include other checks if we need to, but the
        properties of `/ready/` will always be included.
        """
        return self.ready(request, format)
