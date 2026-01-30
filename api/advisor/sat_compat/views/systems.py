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

from json import dumps

from django.conf import settings
from django.db import transaction
from django.db.models import (
    BooleanField, Case, DateTimeField, Exists, F, IntegerField,
    OuterRef, Prefetch, Q, Subquery, Value, When,
)
from django.utils import timezone

from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED, HTTP_204_NO_CONTENT, HTTP_200_OK
from rest_framework import viewsets

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema

from advisor_logging import logger
from api.filters import (
    value_of_param, filter_on_param, branch_id_param, required_branch_id_param,
    OpenApiParameter,
)
from api.models import (
    CurrentReport, Host, InventoryHost, Playbook,
    Resolution, Rule, convert_to_count_query, get_reports_subquery
)
from api.permissions import (
    http_auth_header_key, auth_header_key, request_to_org
)
from api.utils import (
    PaginateMixin, retry_request, store_post_data,
)

from sat_compat.models import SatMaintenanceAction
from sat_compat.serializers import (
    SatSystemsSerializer, SatSystemReportsSerializer,
    SatSystemMetadataSerializer, SatSystemNewSerializer,
    SatSystemEditSerializer, SatGroupSerializer,
)
from sat_compat.utils import ClassicPageNumberPagination
from sat_compat.views.rules import report_count_query_param, report_count_filter


name_search_param = OpenApiParameter(
    name='search_term', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description="Search for systems that include this term in their name"
)
offline_query_param = OpenApiParameter(
    name='offline', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.BOOL, required=False,
    description="Search for systems that are current (or stale)"
)
rule_search_param = OpenApiParameter(
    name='rule', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description="Search for systems impacted by a specific rule",
)
sort_fields = [
    'toString', 'system_id', 'display_name', 'hostname', 'last_check_in',
    'report_count', 'created_at',
]
# Fields based on InventoryHost
sort_map = {
    'toString': 'display_name',
    'system_id': 'id',
    'display_name': 'display_name',
    'hostname': 'display_name',
    'last_check_in': 'updated',
    'report_count': 'report_count',
    'created_at': 'created',
}
sort_field_param = OpenApiParameter(
    name='sort_by', location=OpenApiParameter.QUERY,
    type=OpenApiTypes.STR, required=False,
    description="Order by this field",
    enum=sort_fields,
    default='toString'
)
sort_dir_param = OpenApiParameter(
    name='sort_dir', location=OpenApiParameter.QUERY,
    description="Ordering direction",
    required=False,
    type=OpenApiTypes.STR,
    enum=['ASC', 'DESC'],
    default='ASC'
)


def filter_on_rule_id(request):
    org_id = request_to_org(request)
    rule_search_value = value_of_param(rule_search_param, request)
    if not rule_search_value:
        return Q()
    return Q(host__upload__in=Subquery(CurrentReport.objects.filter(
        rule__rule_id=rule_search_value, org_id=org_id
    ).order_by().values('upload_id')))


def filter_on_offline(request):
    offline = value_of_param(offline_query_param, request)
    if offline is None:
        return Q()
    # Use the isCheckingIn derived parameter
    return Q(isCheckingIn=(not offline))


def isCheckingIn_case(relation=''):
    """
    Return a Case clause that evaluates whether the system is checking in -
    i.e. is it not stale yet?

    The relation field, if set, defines the relation leading to the
    InventoryHost model.
    """
    field_comp = (relation + '__' if relation else '') + 'per_reporter_staleness__puptoo__stale_timestamp__gt'
    return Case(
        When(Q(**{field_comp: str(timezone.now())}), then=Value(True)),
        default=Value(False),
        output_field=BooleanField()
    )


def get_system_or_404(queryset, insights_id, org_id):
    '''
    Get 'a' system by insights_id for this account.  Due to client confusion,
    it's possible to have multiple systems with the same insights_id.  In
    that case, we simply return the first one, since there's no way of
    distinguishing in this request which one we want.  If a system with this
    insights_id is not found, raise a 404.
    '''
    try:
        return queryset.filter(insights_id=insights_id, org_id=org_id)[0]
    except IndexError:
        raise NotFound(f"System with insights_id {insights_id} not found")


class SystemViewSet(viewsets.ReadOnlyModelViewSet, PaginateMixin):
    """
    List systems, or retrieve a system by UUID.

    param: uuid: The Insights UUID of a host to retrieve.
    """
    queryset = InventoryHost.objects.all()
    # lookup_field not used as we override the views with code
    lookup_url_kwarg = 'uuid'
    pagination_class = ClassicPageNumberPagination
    serializer_class = SatSystemsSerializer

    def get_queryset(self):
        report_count_query = convert_to_count_query(get_reports_subquery(
            self.request, host_id=OuterRef('id'),
        ))

        return InventoryHost.objects.for_account(
            self.request
        ).filter(
            host__upload__current=True, host__upload__source_id=1,
        ).annotate(
            isCheckingIn=isCheckingIn_case(),
            # We tried making this dependent on the culled_timestamp, but it
            # makes no sense as we never show hosts that are culled or in
            # stale-hide mode.  Until there's a better definition, we're just
            # going to not give an unregistered_at time here.
            unregistered_at=Value(None, output_field=DateTimeField(null=True)),
            system_type_id=F('host__upload__system_type_id'),
            product_code=F('host__upload__system_type__product_code'),
            role=F('host__upload__system_type__role'),
            report_count=Subquery(
                report_count_query, output_field=IntegerField(),
            ),
            remote_branch=F('host__branch_id'),
            remote_leaf=F('host__satellite_id'),
        ).select_related('host')

    @extend_schema(
        parameters=[
            branch_id_param, offline_query_param, report_count_query_param,
            name_search_param, rule_search_param,
            sort_field_param, sort_dir_param
        ],
    )
    def list(self, request, format=None):
        """
        List the systems in this account.

        Only systems not yet past their stale warning date with current
        reports are shown.  List can be sorted and paginated.
        """
        sort_field = sort_map[value_of_param(sort_field_param, request)]
        if value_of_param(sort_dir_param, request) == 'DESC':
            sort_field = '-' + sort_field
        systems = (
            self.get_queryset()
            .filter(
                filter_on_param('display_name__contains', name_search_param, request),
                filter_on_offline(request),
                report_count_filter(request),
                filter_on_rule_id(request),
            )
            .order_by(sort_field, 'id')
        )
        return self._paginated_response(systems)

    @extend_schema(
        parameters=[required_branch_id_param],
        responses={200: SatSystemsSerializer(many=False)},
    )
    def retrieve(self, request, uuid, format=None):
        """
        Retrieve a single system in this account.

        Only systems that are still reporting and that have current reports
        are shown.
        """
        # Because of client problems, it's possible to have more than one
        # system with the given insights_id.  So here we just return the
        # first,
        org_id = request_to_org(request)
        system = get_system_or_404(
            self.get_queryset(), uuid, org_id
        )
        # Acks list is now a property of the system itself
        return Response(SatSystemsSerializer(system).data)

    @extend_schema(
        parameters=[branch_id_param],
        responses={200: SatGroupSerializer(many=True)},
    )
    @action(detail=True)
    def groups(self, request, uuid, format=None):
        """
        Retrieve the list of groups this system is in.

        Because we don't implement system groups, this is an empty list.
        """
        org_id = request_to_org(request)
        get_system_or_404(
            self.get_queryset(), uuid, org_id
        )
        # Then throw that away...
        return Response(SatGroupSerializer([], many=True).data)

    @extend_schema(
        parameters=[branch_id_param],
        responses={200: SatSystemReportsSerializer(many=False)},
    )
    @action(detail=True)
    def reports(self, request, uuid, format=None):
        """
        Retrieve the reports for a single system in this account.

        Only systems that are still reporting and that have current reports
        are shown.
        """
        org_id = request_to_org(request)
        system = get_system_or_404(
            self.get_queryset(), uuid, org_id
        )

        # OK, this is complicated here so buckle up.  We have two problems:
        # Firstly, we can't actually render the DoT fields in a queryset
        # because that basically can't be done in the database.  Here we're
        # calling out to Node but it'd be the same if this was a pure Python
        # function.
        # Secondly, the details are in the CurrentReport, and the template is
        # in the Rule or Resolution.  They need to be presented in the Rule
        # serializer, but the rule can't introspect back to 'the current
        # report that it's being presented in'.
        # So we actually have to translate this from a Queryset into an actual
        # structure, and annotate in the renderings of the template fields.
        # The easiest way to do this is with `values()` - which means we're
        # duplicating the list of fields needed in the serializer.  Caveat.

        system.reports = get_reports_subquery(
            request, host=system.host,
        ).annotate(
            insights_id=F('host__inventory__insights_id'),
            checked_on=F('upload__checked_on'),
        ).select_related('upload',).values(
            'details', 'id', 'rule_id', 'host_id', 'account', 'org_id', 'insights_id',
            'checked_on',
        ).order_by('rule_id')  # One report per rule for this system.
        # Now get the rules in these reports - no duplicates in upload
        playbook_subquery = Playbook.objects.filter(
            resolution__rule_id=OuterRef('id')
        ).values('id')
        # Get the rule information in one go, without the resolutions
        rules = {
            rule['id']: rule
            for rule in Rule.objects.filter(
                id__in=set(rpt['rule_id'] for rpt in system.reports),
            ).annotate(
                category_name=F('category__name'),  # Reduces serializer queries
                rec_impact=F('impact__impact'),  # Reduces serializer queries
                ansible=Exists(
                    playbook_subquery,
                    output_field=BooleanField()
                ),
                ansible_fix=Exists(
                    playbook_subquery.filter(type='fix'),
                    output_field=BooleanField()
                ),
                ansible_mitigation=Exists(
                    playbook_subquery.filter(type__in=('workaround', 'mitigate')),
                    output_field=BooleanField()
                ),
            ).values(
                'id', 'rule_id', 'active', 'node_id', 'reboot_required',
                'publish_date', 'description', 'summary', 'generic',
                'reason', 'more_info', 'total_risk', 'category_name',
                'rec_impact', 'likelihood', 'resolution__system_type_id',
                'ansible', 'ansible_fix', 'ansible_mitigation',
            ).order_by('rule_id', 'resolution__system_type_id')
        }
        # Find all the resolutions for that set of rules, and index them first
        # by rule ID number and then by system type, so we can find the
        # resolutions in a suitable system type order.
        risks = dict()
        for resolution in Resolution.objects.filter(
            rule_id__in=rules.keys()
        ).values(
            'rule_id', 'resolution_risk__risk'
        ):
            if resolution['rule_id'] not in risks:
                risks[resolution['rule_id']] = resolution['resolution_risk__risk']
        # Maintenance action query with prefetches
        maintenance_actions = SatMaintenanceAction.objects.filter(
            host_id=uuid
        ).prefetch_related(Prefetch(
            'host', queryset=Host.objects.filter(
                upload__current=True
            ).select_related('inventory').annotate(
                display_name=F('inventory__display_name'),
                isCheckingIn=isCheckingIn_case('inventory'),
                system_type_id=F('upload__system_type_id'),  # see filter above
                last_check_in=F('inventory__updated'),
            )
        ))
        # Map the rule onto each report, and get the Dot field outputs
        for rpt in system.reports:
            # Find the rule for this report.
            rule = rules[rpt['rule_id']]
            rpt['rule'] = rule
            # Rough hack to just get the first available resolution risk value.
            rpt['rule']['resolution_risk'] = risks[rpt['rule_id']]
            # Warn that this content is not interpolated.
            for field in ('summary', 'generic', 'reason', 'resolution', 'more_info'):
                rpt['rule'][field] = "Warning: this content is not able to be interpolated"
            # Add the maintenance actions as a subquery
            rpt['maintenance_actions'] = maintenance_actions.filter(
                rule_id=rule['id'],
            )
        # Now the system should be ready!
        return Response(SatSystemReportsSerializer(system).data)

    @extend_schema(
        parameters=[branch_id_param],
        responses={200: SatSystemMetadataSerializer(many=False)},
    )
    @action(detail=True)
    def metadata(self, request, uuid, format=None):
        """
        Retrieve the system metadata for a single system in this account.

        Only systems that are still reporting and that have current reports
        are shown.
        """
        org_id = request_to_org(request)
        system = get_system_or_404(
            self.get_queryset(), uuid, org_id
        )
        profile = system.system_profile
        virtual_machine = (profile.get('infrastructure_type', 'real') == 'virtual')
        # Nice lookups
        releases = {6: 'Santiago', 7: 'Maipo', 8: 'Ootpa', 9: 'Plow'}
        if 'release' in profile:
            os_release = profile['release']
        else:
            os_release = "Red Hat Enterprise Linux"
        if 'operating_system' in profile and 'major' in profile['operating_system']:
            os_release_suffix = " release {ver} ({release})".format(
                ver=system.rhel_version, release=releases.get(
                    profile['operating_system']['major'],
                    profile['operating_system']['major']
                )
            )
        else:
            os_release_suffix = ''

        metadata = {
            'bios_release_date': profile.get('bios_release_date'),
            'bios_vendor': profile.get('bios_vendor'),
            'bios_version': profile.get('bios_version'),
            'release': os_release + os_release_suffix,
            'rhel_version': system.rhel_version,
            'system_family': os_release,
            'system_vm': '1' if virtual_machine else None,
            'system_type': 'Virtual' if virtual_machine else 'Physical',
        }
        return Response(SatSystemMetadataSerializer(metadata, many=False).data)

    @extend_schema(
        parameters=[branch_id_param],
        responses={200: dict},
    )
    @action(detail=True)
    def links(self, request, uuid, format=None):
        """
        Show links to other systems.

        Classic once tried to understand the links between systems - e.g.
        systems managed by a Satellite, hosts virtualised using OpenStack,
        and so forth.  Then we gave up.  Now we just return an empty list.
        """
        org_id = request_to_org(request)
        get_system_or_404(
            self.get_queryset(), uuid, org_id
        )
        return self._paginated_response(InventoryHost.objects.none())

    def destroy(self, request, uuid, format=None):
        """
        Unregister a current system.

        This basically just deletes the current reports and marks the current
        upload as non-current.  This should then remove the system from view,
        while not actually deleting the host and associated upload and report
        history.
        """
        org_id = request_to_org(request)
        system = get_system_or_404(
            self.get_queryset(), uuid, org_id
        )
        with transaction.atomic():
            # Delete its current reports
            system.host.currentreport_set.all().delete()
            # Delete the previous upload
            system.host.upload_set.filter(current=True).delete()
        return Response(status=HTTP_204_NO_CONTENT)


class V1SystemViewSet(viewsets.ReadOnlyModelViewSet):
    """
    List systems, retrieve a system by UUID, or rename a system by UUID.

    This is used by the client.

    param: uuid: The Insights UUID of a host to retrieve.
    """
    queryset = InventoryHost.objects.all()
    lookup_field = 'insights_id'
    lookup_url_kwarg = 'uuid'
    pagination_class = None
    serializer_class = SatSystemsSerializer

    def get_queryset(self):
        return InventoryHost.objects.for_account(
            self.request, filter_branch_id=False, require_host=False
        ).annotate(
            last_check_in=F('updated'),
            isCheckingIn=isCheckingIn_case(),
            unregistered_at=Case(
                When(
                    per_reporter_staleness__puptoo__culled_timestamp__lt=str(timezone.now()),
                    then=F('per_reporter_staleness__puptoo__culled_timestamp')
                ),
                default=Value(None),
                output_field=DateTimeField(null=True),
            ),
            system_type_id=Value(105),
            product_code=Value('rhel'),
            role=Value('host'),
            report_count=Value(1),
            remote_branch=F('host__branch_id'),
            remote_leaf=F('host__satellite_id'),
        ).select_related('host')  # can't seem to prefetch acks here.

    @extend_schema(
        parameters=[branch_id_param],
        responses={200: SatSystemsSerializer(many=False)},
    )
    def retrieve(self, request, uuid, format=None):
        """
        Retrieve a single system in this account.

        Only systems that are still reporting and that have current reports
        are shown.
        """
        # Because of client problems, it's possible to have more than one
        # system with the given insights_id.  So here we just return the
        # first, because there's no way from the request to make a better pick.
        org_id = request_to_org(request)
        system = get_system_or_404(
            self.get_queryset(), uuid, org_id
        )
        # Acks list is now a property of the system itself
        return Response(SatSystemsSerializer(system).data)

    @extend_schema(
        parameters=[branch_id_param],
        request=SatSystemNewSerializer(many=False),
    )
    def create(self, request, format=None):
        """
        Pretend to register a system with Insights.

        Insights clients will try to POST to this with data of the form:

        {
            "machine_id": "836f969e-2e5c-4ac3-aeb6-4eddfd7264e9",
            "remote_branch": "94a54d2e-a295-4190-9f66-166cdc3d1955",
            "remote_leaf": "3e80d32b-b5fd-4f5c-ab23-ae1b1802662f",
            "hostname": "ibm-p9z-18-lp5.virt.pnr.lab.eng.rdu2.redhat.com"
        }

        At this point the host has not been registered yet and has not
        done an upload so there is almost definitely no record of it in
        Inventory yet.  For this reason we throw all this data away and just
        return it with a 201 status code.
        """
        try:
            logger.info('Classic POST of system %s', dumps(request.data))
        except (Exception,):
            pass  # Just here to not crash on a log statement
        return Response(request.data, status=HTTP_201_CREATED)

    @extend_schema(
        request=SatSystemEditSerializer(many=False),
        responses={200: SatSystemEditSerializer(many=False)},
    )
    def put(self, request, uuid, format=None):
        """
        Update a system with Insights.

        This makes an equivalent PATCH call to Inventory to update the host,
        with the given data, and returns the response.  The UUID given is
        the Insights ID - which may be duplicated, so we give no guarantee
        that the system being updated is actually the system which has that
        hostname. This is best-effort to support compatibility. The official
        way is to set the display_name in the upload or set it using
        the inventory service. Always return a 200 no matter what.
        """
        # Make sure the system exists in this org before we try to update it.
        org_id = request_to_org(request)
        system = get_system_or_404(self.get_queryset(), uuid, org_id)
        try:
            # Validate form
            store_post_data(request, SatSystemEditSerializer)
            serdata = SatSystemEditSerializer(data=request.data)
            serdata.is_valid(raise_exception=True)
            # Connect to Inventory to change its display name
            if not settings.INVENTORY_SERVER_URL:
                return Response('{"error": "Inventory server not configured"}', status=500)
            (response, elapsed) = retry_request(
                'Inventory', settings.INVENTORY_SERVER_URL + "/hosts/" + str(system.id),
                mode='PATCH',
                json={'display_name': serdata.validated_data['display_name']},
                headers={http_auth_header_key: request.META[auth_header_key]},
            )
            if response is None:
                logger.info('Inventory returned no response on PATCH host')
            else:
                logger.info(f'Inventory returned ${response.status_code} on PATCH host')
        except (Exception,):
            # Don't use logger.exception here, it raises an exception that DRF
            # does not expect to handle.
            logger.error('Failed to PATCH display_name')

        # System may not be created at this point.
        # The display_name will be set when the archive hits the inventory so always return 200.
        return Response(request.data, status=HTTP_200_OK)

    def delete(self, request, uuid, format=None):
        """
        Delete a system.

        This makes an equivalent DELETE call to Inventory to delete the host,
        and returns the response.  Given that you might get a random system
        with this insights_id, good luck.
        """
        org_id = request_to_org(request)
        system = get_system_or_404(self.get_queryset(), uuid, org_id)

        if not settings.INVENTORY_SERVER_URL:
            return Response('{"error": "Inventory server not configured"}', status=500)
        (response, elapsed) = retry_request(
            'Inventory', settings.INVENTORY_SERVER_URL + "/hosts/" + str(system.id),
            mode='DELETE',
            headers={http_auth_header_key: request.META[auth_header_key]},
        )
        if response is None:
            return Response('{"error": "Received error trying to update host name in Inventory"}', status=500)

        return Response(status=response.status_code)
