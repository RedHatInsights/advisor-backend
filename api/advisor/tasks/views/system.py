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

from itertools import batched

from django.conf import settings
from django.db.models import Case, CharField, F, Value, When
from rest_framework.response import Response
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.viewsets import ReadOnlyModelViewSet

from advisor_logging import logger

from api.filters import (
    sort_params_to_fields, filter_multi_param,
    host_tags_query_param, value_of_param,
    display_name_query_param, filter_on_display_name,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    host_group_name_query_param, filter_on_host_tags,
)
from api.models import get_host_group_filter
from api.permissions import (
    OrgPermission, http_auth_header_key, auth_header_key,
    ResourceScope
)
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, retry_request,
)
from tasks.models import Host
from tasks.permissions import TasksRBACPermission
from tasks.serializers import HostSerializer
from tasks.utils import (
    os_version_query_param, filter_on_os_version, system_sort_query_param,
    os_name_query_param, filter_on_os_name, os_query_param, filter_on_os,
    apply_system_connected_filter, direct_connect_filter, satellite_rhc_filter,
    all_systems_query_param, playbook_dispatcher_connection_status_path,
)

# Have to have our own here because we operate on the Host model directly
os_name = 'system_profile__operating_system__name'
os_major = 'system_profile__operating_system__major'
os_minor = 'system_profile__operating_system__minor'
system_sort_field_map = {
    'os_version': [os_major, os_minor],
    'os_name': os_name,
    'os': [os_name, os_major, os_minor],
    'last_seen': 'updated',
    'group_name': 'groups__0__name',
}


# Cut down to remove duplication - just giving examples of Satellite-connected
# and Direct-connected hosts as well as connected, disconnected and not
# registered with RHC.
example_connection_status_response = """
[
  {
    "org_id": "6666666",
    "recipient": "beefface-c7a6-4cc3-89bc-9066ffda695e",
    "recipient_type": "satellite",
    "sat_id": "893f2788-c7a6-4cc3-89bc-9066ffda695e",
    "sat_org_id": "6",
    "status": "connected",
    "systems": [
      "2a708189-4b48-4642-9443-64bda5f38e5f",
      "36828b63-38f3-4b9a-ad08-0b7812e5df57",
      "6f6a889d-6bac-4d53-9bc1-ef75bc1a55ff",
      "938c5ce7-481f-4b82-815c-2973ca76a0ef"
    ]
  },
  {
    "org_id": "6666666",
    "recipient": null,
    "recipient_type": "satellite",
    "sat_id": "409dd231-6297-43a6-a726-5ce56923d624",
    "sat_org_id": "2",
    "status": "disconnected",
    "systems": [
      "a9b3af62-8404-4b2a-9084-9ed37da6baf1"
    ]
  },
  {
    "org_id": "6666666",
    "recipient": "0341e468-fbae-416c-b16f-5abb64d99834",
    "recipient_type": "directConnect",
    "sat_id": "",
    "sat_org_id": "",
    "status": "connected",
    "systems": [
      "0341e468-fbae-416c-b16f-5abb64d99834"
    ]
  },
  {
    "org_id": "6666666",
    "recipient": "",
    "recipient_type": "none",
    "sat_id": "",
    "sat_org_id": "",
    "status": "rhc_not_configured",
    "systems": [
      "35f36364-6007-4ecc-9666-c4f8d354be9f"
    ]
  }
]"""


def retrieve_pd_connected_systems(request, system_uuids):
    """
    Retrieve the connection status of systems via Playbook Dispatcher.  This
    allows it to work out Satellite-connected systems.
    """
    # If Playbook Dispatcher is not enabled here, just return nothing
    if not (settings.PLAYBOOK_DISPATCHER_URL and settings.PDAPI_PSK):
        logger.warn("Expected PLAYBOOK_DISPATCHER_URL and PDAPI_PSK to be set")
        return set()
    # /internal/v2/recipients/status takes an array of HostsWithOrgId
    # items, and returns a HighLevelRecipientStatus response.
    # HighLevelRecipientStatus is basically an array of RecipientWithConnectionInfo
    # items, each of which is of this form:
    """
    RecipientWithConnectionInfo:
      type: object
      properties:
        recipient: $ref: './public.openapi.yaml#/components/schemas/RunRecipient' (-> uuid, probably rhc_client_id)
        org_id: $ref: '#/components/schemas/OrgId'
        sat_id: $ref: '#/components/schemas/SatelliteId'
        sat_org_id: $ref: '#/components/schemas/SatelliteOrgId'
        recipient_type: $ref: '#/components/schemas/RecipientType'
        systems:
          type: array
          items: $ref: '#/components/schemas/HostId' (-> same ID that we fed in??)
        status:
          description: Indicates the current run status of the recipient
          type: string
          enum: [connected, disconnected, rhc_not_configured]
    """
    # So we have to
    # This is a HostsWithOrgID:
    dispatch_body = {
        'org_id': request.auth['org_id'],
        'hosts': [
            str(system_uuid)
            for system_uuid in system_uuids
        ]
    }
    url = settings.PLAYBOOK_DISPATCHER_URL + playbook_dispatcher_connection_status_path
    logger.info(
        "Requesting %s from %s%s", dispatch_body,
        settings.PLAYBOOK_DISPATCHER_URL, playbook_dispatcher_connection_status_path
    )
    (response, elapsed) = retry_request(
        'Playbook Dispatcher', url,
        max_retries=1, mode='POST',
        headers={
            "Authorization": f"PSK {settings.PDAPI_PSK}",
            http_auth_header_key: request.META[auth_header_key]
        },
        json=dispatch_body
    )
    if response.status_code != 200:
        logger.error(
            "Received non-200 response from playbook dispatcher %s: %s",
            url, response.content.decode()
        )
        return set()
    connection_status_list = response.json()
    if not isinstance(connection_status_list, list):
        logger.error(
            "HighLevelRecipientStatus is not an array from %s: %s",
            url, connection_status_list
        )
        return set()
    # Note that 'status' can be one of [connected, disconnected, rhc_not_configured]
    # but we already know if RHC is not configured we don't have an rhc_client_id
    # and so we already know that we can't execute the task on that system.
    logger.info(
        "Playbook Dispatcher connection status returned %s", connection_status_list
    )
    return set(
        system_uuid
        for connection_info in connection_status_list
        for system_uuid in connection_info['systems']
        if connection_info['status'] == 'connected'
    )


def annotate_rhc_status(request, systems_page):
    """
    Fetch the RHC connection status for a page of systems from Cloud
    Connector.  We check at this point - when we have the page, but before
    it's resolved into JSON - because we want it to be least effort.

    This fetches the complete (paginated) list of connected systems from
    Cloud Connector and indexes that by rhc_client_id.  Then we turn the
    page from a queryset into a list of objects, and annotate the status
    on that.
    """
    # Expected: a list of Host objects.
    logger.info("Annotating system RHC status on systems %s", str({
        str(system.id): system.display_name
        for system in systems_page
    }))
    # Waiting on RHIN-1702 for Remediations to fix the problem where they
    # just assume that you won't pass them more than 50 systems.
    available_systems = set()
    for batch in batched(systems_page, 50):  # list of Host objects
        available_systems |= retrieve_pd_connected_systems(
            request, [system.id for system in batch]
        )
    # available_systems = retrieve_pd_connected_systems(
    #     request, [system.id for system in systems_page]
    # )
    logger.info(
        "Playbook Dispatcher says this set of systems is available: %s",
        available_systems
    )
    for system in systems_page:
        system.connected = (str(system.id) in available_systems)
    return systems_page


class SystemViewSet(ReadOnlyModelViewSet, PaginateMixin):
    """
    List the systems that can execute tasks, or the task-related details for
    a single system.
    """
    lookup_field = 'id'
    pagination_class = CustomPageNumberPagination
    permission_classes = [OrgPermission, TasksRBACPermission]
    queryset = Host.objects.all()
    resource_name = 'task'
    resource_scope = ResourceScope.ORG
    serializer_class = HostSerializer

    def get_queryset(self):
        return self.queryset.filter(
            org_id=self.request.auth['org_id']
        ).filter(
            apply_system_connected_filter(self.request),
            filter_on_host_tags(self.request, field_name='id'),
            filter_multi_param(self.request, 'system_profile'),
            get_host_group_filter(self.request),
            per_reporter_staleness__puptoo__stale_warning_timestamp__gt=str(timezone.now()),
        ).annotate(
            connection_type=Case(
                When(direct_connect_filter, then=Value('direct')),
                When(satellite_rhc_filter, then=Value('satellite')),
                default=Value('none'),
                output_field=CharField()
            ),
            last_check_in=F('per_reporter_staleness__puptoo__last_check_in'),
        )

    @extend_schema(
        parameters=[
            system_sort_query_param, host_tags_query_param, display_name_query_param,
            os_version_query_param, os_name_query_param, os_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            host_group_name_query_param, all_systems_query_param,
        ],
    )
    def list(self, request, format=None):
        sort_fields = list(sort_params_to_fields(
            value_of_param(system_sort_query_param, request),
            system_sort_field_map,
            reverse_nulls_order=True
        )) + ['id']  # Enforce a repeatable ordering just in case
        systems = self.get_queryset().filter(
            filter_on_host_tags(request, field_name='id'),
            filter_on_display_name(request),
            filter_on_os_version(request), filter_on_os_name(request), filter_on_os(request)
        ).order_by(*sort_fields)
        return self._paginated_response(
            systems, request=request, page_annotator_fn=annotate_rhc_status
        )

    def retrieve(self, request, id, format=None):
        """
        Retrieve a single system by Inventory UUID.
        """
        host = self.get_object()
        connection_state = retrieve_pd_connected_systems(request, [host.id])
        host.connected = (str(host.id) in connection_state)
        return Response(HostSerializer(host).data)
