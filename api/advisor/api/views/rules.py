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

from django.conf import settings
from django.db.models import Count, Exists, F, Q, Subquery, OuterRef
from django.db.models.functions import Extract, Now
from django.utils import timezone
from django.shortcuts import get_object_or_404

from rest_framework import viewsets
from rest_framework_csv.renderers import CSVRenderer
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter

from api.filters import (
    value_of_param, filter_on_param, host_tags_query_param,
    filter_system_profile_sap_system_query_param,
    filter_system_profile_sap_sids_contains_query_param,
    filter_system_profile_mssql_query_param,
    filter_system_profile_ansible_query_param,
    rhel_version_query_param, filter_on_rhel_version,
    sort_params_to_fields, sort_param_enum, filter_on_display_name,
    systems_detail_name_query_param, host_group_name_query_param,
    update_method_query_param,
)
from api.models import (
    Ack, CurrentReport, HostAck, Resolution, Rule, Upload,
    get_systems_queryset, get_reports_subquery
)
from api.serializers import (
    RuleForAccountSerializer, RuleUsageStatsSerializer, SystemsForRuleSerializer,
    MultiHostAckSerializer, MultiHostUnAckSerializer, MultiAckResponseSerializer,
    JustificationCountSerializer, ReportForRuleSerializer,
    RuleSerializer, SystemsDetailSerializer
)
from api.permissions import (
    TurnpikeIdentityAuthentication,
    IsRedHatInternalUser, InsightsRBACPermission, CertAuthPermission,
    AssociatePermission, request_to_username, set_resource, ResourceScope,
)
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, store_post_data,
)


class SystemsForRuleCSVRenderer(CSVRenderer):
    header = ['system_uuid']
    labels = {'system_uuid': 'Host UUID'}

    def render(self, data, media_type=None, renderer_context=None):
        """
        The data in the systems-for-a-rule list is a key named
        'host_ids' which contains the list of UUIDs.  The CSV renderer is
        expecting a list of dictionaries, each of which will contain one key -
        'system_uuid'.  So we need to re-wrap the data into the correct
        format for the CSV renderer.
        """
        return super().render([
            {'system_uuid': host_id}
            for host_id in data['host_ids']
        ], media_type, renderer_context)


class RedHatRuleStatsPermission(IsRedHatInternalUser):
    allowed_views = ['Stats', 'Justifications']


category_query_param = OpenApiParameter(
    name='category', location=OpenApiParameter.QUERY,
    description="Display rules of this category (number)",
    required=False,
    many=True, type=OpenApiTypes.INT, enum=(1, 2, 3, 4), style='form',
)
has_playbook_query_param = OpenApiParameter(
    name='has_playbook', location=OpenApiParameter.QUERY,
    description="Display rules that have a playbook",
    required=False,
    type=OpenApiTypes.BOOL,
)
has_tag_query_param = OpenApiParameter(
    name='has_tag', location=OpenApiParameter.QUERY,
    description="Display rules that have (one or more) tags",
    required=False,
    many=True, type=OpenApiTypes.STR, pattern=r'\w+(?:,\w+)*', style='form',
)
# NOTE: host tags are filtered inside the Rule model's for_account
# method.
impact_query_param = OpenApiParameter(
    name='impact', location=OpenApiParameter.QUERY,
    description="Display rules of this impact level (1..4)",
    required=False,
    many=True, type=OpenApiTypes.INT, enum=(1, 2, 3, 4), style='form'
)
impacting_query_param = OpenApiParameter(
    name='impacting', location=OpenApiParameter.QUERY,
    description="Display only rules that are impacting systems currently",
    required=False,
    type=OpenApiTypes.BOOL,
)
incident_query_param = OpenApiParameter(
    name='incident', location=OpenApiParameter.QUERY,
    description="Display only rules that cause an incident",
    required=False,
    type=OpenApiTypes.BOOL,
)
likelihood_query_param = OpenApiParameter(
    name='likelihood', location=OpenApiParameter.QUERY,
    description="Display only rules of this likelihood level (1..4)",
    required=False,
    many=True, type=OpenApiTypes.INT, enum=(1, 2, 3, 4), style='form',
)
pathway_query_param = OpenApiParameter(
    name='pathway', location=OpenApiParameter.QUERY,
    description="Display rules of this Pathway",
    required=False,
    type=OpenApiTypes.STR,
)
reboot_required_query_param = OpenApiParameter(
    name='reboot', location=OpenApiParameter.QUERY,
    description="Display rules that require a reboot to fix",
    type=OpenApiTypes.BOOL,
    required=False,
)
reports_shown_query_param = OpenApiParameter(
    name='reports_shown', location=OpenApiParameter.QUERY,
    description="Display rules where reports are shown or not",
    type=OpenApiTypes.BOOL,
    required=False,
)
rule_status_query_param = OpenApiParameter(
    name='rule_status', location=OpenApiParameter.QUERY,
    description="Display rules which are enabled, disabled (acked) by user, or disabled (acked) by Red Hat",
    required=False,
    type=OpenApiTypes.STR,
    enum=('all', 'enabled', 'disabled', 'rhdisabled'),
)
res_risk_query_param = OpenApiParameter(
    name='res_risk', location=OpenApiParameter.QUERY,
    description="Display rules with this resolution risk level (1..4)",
    required=False,
    many=True, type=OpenApiTypes.INT, enum=(1, 2, 3, 4), style='form',
)
sort_field_map = {  # parameter value to field in Rule queryset
    'category': 'category__name', 'description': 'description',
    'impact': 'impact__impact', 'impacted_count': 'impacted_systems_count',
    'likelihood': 'likelihood', 'playbook_count': 'playbook_count',
    'publish_date': 'publish_date', 'rule_id': 'rule_id',
    'total_risk': 'total_risk', 'resolution_risk': 'resolution__resolution_risk__risk',
}
sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    description="Order by this field",
    required=False,
    type=OpenApiTypes.STR, enum=sort_param_enum(sort_field_map),
    many=True, style='form', default=['rule_id']
)
# Actually based on CurrentReport with fields from InventoryHost
systems_sort_field_map = {
    'display_name': 'inventory__display_name', 'last_seen': 'last_upload',
    'stale_at': 'inventory__stale_timestamp', 'system_uuid': 'host_id',
    'updated': 'inventory__updated'
}
systems_sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    description="Order by this field",
    required=False,
    many=True, type=OpenApiTypes.STR, default=['system_uuid'],
    enum=sort_param_enum(systems_sort_field_map), style='form',
)
systems_detail_sort_fields = [
    'display_name', 'last_seen', 'hits',
    'critical_hits', 'important_hits', 'moderate_hits', 'low_hits',
    'impacted_date', 'rhel_version', 'group_name'
]
# last_seen provided as an annotation in get_systems_queryset
systems_detail_sort_field_map = {
    'rhel_version': [
        'system_profile__operating_system__major',
        'system_profile__operating_system__minor'
    ],
    'group_name': 'groups__0__name'
}
systems_detail_sort_query_param = OpenApiParameter(
    name='sort', location=OpenApiParameter.QUERY,
    description="Order by this field",
    required=False,
    type=OpenApiTypes.STR,
    enum=systems_detail_sort_fields + ['-' + k for k in systems_detail_sort_fields],
    default='display_name'
)
text_query_param = OpenApiParameter(
    name='text', location=OpenApiParameter.QUERY,
    description="Display rules with this text in their text fields",
    required=False,
    type=OpenApiTypes.STR,
)
topic_query_param = OpenApiParameter(
    name='topic', location=OpenApiParameter.QUERY,
    description="Display rules in this topic (slug)",
    required=False,
    type=OpenApiTypes.REGEX, pattern=r'[\w-]+',
    # See note for enums in category list as to why we can't populate the
    # topics with a query.
)
total_risk_query_param = OpenApiParameter(
    name='total_risk', location=OpenApiParameter.QUERY,
    description="Display rules with this total risk level (1..4)",
    required=False,
    many=True, type=OpenApiTypes.INT, enum=(1, 2, 3, 4), style='form',
)


def filter_on_impacting(request):
    # Get the list of current uploads, and filter the rule list by
    # the list of rule IDs in those uploads' reports.  filter_queryset_by
    # can't do this since it looks up the value of the parameter from the
    # query, which we don't care about here.
    impacting = value_of_param(impacting_query_param, request)
    if impacting is not None:
        return Q(has_reports=impacting)
    else:
        return Q()


def filter_on_incident(request):
    # Filter for just a specific 'incident' tag (or absence thereof)
    incident_param = value_of_param(incident_query_param, request)
    if incident_param is None:
        return Q()
    elif incident_param:
        return Q(tags__name='incident')
    else:
        return Q(~ Q(tags__name='incident'))


def filter_on_reboot_required(request):
    # No filter if not set, or present or absent if set
    reboot_param = value_of_param(reboot_required_query_param, request)
    if reboot_param is None:
        return Q()
    else:
        return Q(reboot_required=reboot_param)  # True or False there.


def filter_on_resolution_risk(request):
    # Filtering naively on resolution__resolution_risk involves a join to
    # the resolution table, which then causes row duplication.  So we need to
    # encapsulate that in a subquery.  The simplest subquery therefore is a
    # search of the resolution table listing their associated rule ID number.
    res_risk = value_of_param(res_risk_query_param, request)
    if res_risk:
        return Q(id__in=Subquery(
            Resolution.objects.filter(
                resolution_risk__risk__in=res_risk
            ).values('rule_id')
        ))
    else:
        return Q()


def filter_on_reports_shown(request):
    reports_shown = value_of_param(reports_shown_query_param, request)
    if reports_shown is None:
        # No parameter supplied, no filtering
        return Q()
    else:
        return Q(reports_shown=reports_shown)


def filter_on_rule_status(request):
    rule_status = value_of_param(rule_status_query_param, request)
    if not rule_status or rule_status == 'all':
        return Q()
    else:
        return Q(rule_status=rule_status)


def filter_on_text(request):
    # Filter on text search on all text fields
    srch = value_of_param(text_query_param, request)
    if srch:
        # Thanks, Flake8, for not allowing wrapping of binary operators
        # Also note that any joins here may affect the number of results
        # found in annotations.
        return \
            Q(rule_id__icontains=srch) | \
            Q(description__icontains=srch) | \
            Q(summary__icontains=srch) | \
            Q(generic__icontains=srch) | \
            Q(reason__icontains=srch) | \
            Q(more_info__icontains=srch) | \
            Q(id__in=Subquery(
                Resolution.objects.filter(
                    resolution__icontains=srch
                ).values('rule_id')
            ))
    else:
        return Q()


def filter_on_topic(request):
    topic_param = value_of_param(topic_query_param, request)
    if topic_param:
        # Note: this will produce duplicates if a topic has more than one
        # tag, and a rule has more than one of those tags.
        return Q(tags__topic__slug=topic_param)
    else:
        return Q()


def filter_on_has_playbook(request):
    has_playbook_param = value_of_param(has_playbook_query_param, request)
    if has_playbook_param is None:
        return Q()
    elif has_playbook_param:
        return Q(playbook_count__gt=0)
    else:
        return Q(playbook_count__isnull=True)


class RuleViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    Rules detect a single problem for a given system.
    """
    queryset = Rule.objects.all()  # purely for schema generation - overriden below
    serializer_class = RuleForAccountSerializer
    pagination_class = CustomPageNumberPagination
    resource_name = 'recommendation-results'
    resource_scope = ResourceScope.ORG

    # All three of these have to pass to allow access:
    # * Either RBAC or Cert Auth
    # * Rule Stats and Justifications allow for all other views but deny
    #   non-internal users to those specific views.
    # * Rule Content view allow for all but deny users not using Turnpike
    #   or users not in the insights-rule-devs LDAP group
    # The 'allow all but deny to specific views' behaviour is a misfeature
    # that we should clean up at some point.
    permission_classes = [
        InsightsRBACPermission | CertAuthPermission | RedHatRuleStatsPermission
    ]
    lookup_field = 'rule_id'

    def get_queryset(self):
        return Rule.objects.for_account(self.request)

    @extend_schema(
        parameters=[
            pathway_query_param, category_query_param, has_tag_query_param,
            host_tags_query_param, impact_query_param, impacting_query_param,
            incident_query_param, likelihood_query_param, reboot_required_query_param,
            reports_shown_query_param, rule_status_query_param, res_risk_query_param,
            sort_query_param, text_query_param, topic_query_param,
            total_risk_query_param, has_playbook_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
            host_group_name_query_param, update_method_query_param,
        ],
    )
    def list(self, request, format=None):
        """
        List all active rules for this account.

        If 'acked' is False or not given, then only rules that are not acked
        will be shown.  If acked is set and 'true' as a string or evaluates
        to a true value, then all rules including those that are acked will
        be shown.
        """
        acct_rules = self.get_queryset()

        # NOTE: host tags are filtered inside the Rule model's for_account
        # method.
        if request.query_params:
            # Process parameters in alphabetical order, not because it should
            # make any difference to the query (since the conditions are ANDed
            # together) but for ease of code maintenance.

            acct_rules = acct_rules.filter(
                filter_on_param('pathway__slug', pathway_query_param, request),
                filter_on_param('category_id', category_query_param, request),
                filter_on_param('tags__name', has_tag_query_param, request),
                filter_on_param('impact__impact', impact_query_param, request),
                # We don't really need to look up the impact object, because
                # we're comparing the value directly.
                filter_on_impacting(request),
                filter_on_param('likelihood', likelihood_query_param, request),
                filter_on_reboot_required(request),
                filter_on_reports_shown(request),
                filter_on_rule_status(request),
                filter_on_resolution_risk(request),
                filter_on_text(request),
                filter_on_topic(request),
                filter_on_param('total_risk', total_risk_query_param, request),
                filter_on_has_playbook(request),
            ).filter(
                # If we're querying on tags and incident in the same set
                # of Q objects, then they query the same table for two
                # different values; we need to separate it so it generates
                # a separate join to check the incident tag.
                filter_on_incident(request),
            )

            sort_params = sort_params_to_fields(
                value_of_param(sort_query_param, request),
                sort_field_map
            )

            acct_rules = acct_rules.order_by(*sort_params, 'rule_id')

        return self._paginated_response(acct_rules, request)

    @extend_schema(
        parameters=[host_tags_query_param, host_group_name_query_param],
    )
    def retrieve(self, request, rule_id, format=None):
        """
        Retrieve a single rule and its associated details.

        This includes the account-relevant details such as number of
        impacted systems and host acknowledgements.
        """
        rule = self.get_object()
        return Response(RuleForAccountSerializer(
            rule, many=False, context={'request': request}
        ).data)

    @set_resource('disable-recommendations')
    @extend_schema(
        request=MultiHostAckSerializer(many=False),
        responses={200: MultiAckResponseSerializer(many=False)},
    )
    @action(detail=True, methods=['post'])
    def ack_hosts(self, request, rule_id, format=None):
        """
        Add acknowledgements for one or more hosts to this rule.

        Host acknowledgements will be added to this rule in this account for
        the system UUIDs supplied.  The justification supplied will be given
        for all host acks created.  Any existing host acknowledgements for a
        host on this rule will be updated.  The count of created hosts
        acknowledgements, and the list of systems now impacted by this rule,
        will be returned.  Account-wide acks are unaffected.
        """
        rule: Rule = self.get_object()
        store_post_data(request, MultiHostAckSerializer, context={'request': request})
        serdata = MultiHostAckSerializer(data=request.data, context={'request': request})
        serdata.is_valid(raise_exception=True)
        username = request_to_username(request)
        # Transaction?
        created_count = 0
        for uuid in serdata.validated_data['systems']:
            hostack, created = HostAck.objects.update_or_create(
                account=request.account, org_id=request.auth['org_id'],
                host_id=uuid, rule=rule,
                defaults={
                    'justification': serdata.validated_data['justification'],
                    'created_by': username,
                }
            )
            if created:
                created_count += 1
        data = {
            'count': created_count,
            'host_ids': rule.reports_for_account(
                request
            ).order_by('host_id').values_list('host_id', flat=True),
        }
        # To save the UI requesting it again, and to make sure all the host
        # acks have been added before they request it, we deliver the list
        # of hosts that are (now) impacted by this rule.
        return Response(MultiAckResponseSerializer(
            data, many=False, context={'request': request}
        ).data)

    @set_resource('disable-recommendations')
    @extend_schema(
        request=MultiHostUnAckSerializer(many=False),
        responses={200: MultiAckResponseSerializer(many=False)},
    )
    @action(detail=True, methods=['post'])
    def unack_hosts(self, request, rule_id, format=None):
        """
        Delete acknowledgements for one or more hosts to this rule.

        Any host acknowledgements for this rule in this account for the given
        system are deleted.  Hosts that do not have an acknowledgement for
        this rule in this account are ignored.  The count of deleted host
        acknowledgements, and the list of hosts now impacted by this rule,
        will be returned.  Account-wide acks are unaffected.
        """
        rule = self.get_object()
        store_post_data(request, MultiHostUnAckSerializer, context={'request': request})
        serdata = MultiHostUnAckSerializer(data=request.data, context={'request': request})
        serdata.is_valid(raise_exception=True)
        # Find the host acks for this rule matching the account org_id and system
        # uuids and delete them.
        unacked, model_counts = rule.hostack_set.filter(
            org_id=request.auth['org_id'], host_id__in=serdata.validated_data['systems']
        ).delete()
        # To save the UI requesting it again, and to make sure all the host
        # acks have been deleted before they request it, we deliver the list
        # of hosts that are (now) impacted by this rule.
        data = {
            'count': model_counts.get('api.HostAck', 0),
            'host_ids': rule.reports_for_account(
                request
            ).order_by('host_id').values_list('host_id', flat=True),
        }
        return Response(MultiAckResponseSerializer(
            data, many=False, context={'request': request}
        ).data)

    @set_resource('denied')
    @extend_schema(
        responses={200: RuleUsageStatsSerializer(many=False)},
        # Setting permission classes has no effect here, the permission
        # class needs to act viewset-class wide.
    )
    @action(detail=True)
    def stats(self, request, rule_id, format=None):
        """
        Display usage and impact statistics for this rule.

        For internal use only.  This allows rule developers to see the number
        of systems and accounts impacted by a rule.
        """
        rule = get_object_or_404(Rule, rule_id=rule_id)
        hit_counts = CurrentReport.objects.filter(
            inventory__per_reporter_staleness__puptoo__stale_warning_timestamp__gt=str(timezone.now()),
            rule=rule,
        ).aggregate(
            systems_hit=Count('host_id', distinct=True),
            accounts_hit=Count('org_id', distinct=True),
        )
        return Response(RuleUsageStatsSerializer({
            'rule_id': rule.rule_id,
            'description': rule.description,
            'active': rule.active,
            'systems_hit': hit_counts['systems_hit'],
            'accounts_hit': hit_counts['accounts_hit'],
            'accounts_acked': Ack.objects.filter(rule=rule).count(),
        }, many=False, context={'request': request}).data)

    @set_resource('denied')
    @extend_schema(
        responses={200: JustificationCountSerializer(many=True)},
    )
    @action(detail=True)
    def justifications(self, request, rule_id, format=None):
        """
        List all justifications given for disabling this rule.

        This is an **internal-only** view that allows us to provide feedback
        on why rules are disabled by our customers.  It lists the
        justifications given in both account-wide acks and host-specific acks
        of a rule.
        """
        rule = get_object_or_404(Rule, rule_id=rule_id)
        justifications = (
            Ack.objects.filter(rule=rule)
            .exclude(justification='', created_by=settings.AUTOACK['CREATED_BY'])
            .annotate(count=Count('justification'))
            .values('justification', 'count').union(
                HostAck.objects.filter(rule=rule)
                .exclude(justification='', created_by=settings.AUTOACK['CREATED_BY'])
                .annotate(count=Count('justification'))
                .values('justification', 'count')
            )
            .order_by('justification')
        )
        return Response(JustificationCountSerializer(justifications, many=True).data)

    @extend_schema(
        parameters=[
            host_tags_query_param, systems_sort_query_param,
            systems_detail_name_query_param, rhel_version_query_param,
            host_group_name_query_param, update_method_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
        ],
        responses={200: SystemsForRuleSerializer(many=False)},
    )
    @action(detail=True, renderer_classes=(JSONRenderer, SystemsForRuleCSVRenderer, ))
    def systems(self, request, rule_id, format=None):
        """
        List all systems affected by this rule.

        All systems owned by the user's account, with a current upload
        reporting the given rule, are listed.  Systems are simply listed by
        Insights Inventory UUID.
        """
        rule = get_object_or_404(Rule, rule_id=rule_id)
        sort_fields = sort_params_to_fields(
            value_of_param(systems_sort_query_param, request),
            systems_sort_field_map
        )

        # NOTE: host tags are filtered inside the Rule model's
        # impacted_systems method.  Have to use the reports_for_account method
        # so that we cope with systems that are host-acked as well as this
        # rule being acked.
        last_seen_upload_qs = Upload.objects.filter(
            host_id=OuterRef('host_id'), source_id=1, current=True
        ).order_by().values('checked_on')
        impacted_systems = (
            rule.reports_for_account(request)  # CurrentReport
            .filter(
                filter_on_display_name(
                    request, relation='inventory',
                    param=systems_detail_name_query_param
                ),
                filter_on_rhel_version(request, relation='inventory'),
            )
            .annotate(
                last_upload=Subquery(last_seen_upload_qs)
            )
            .order_by(*sort_fields, 'host_id')
            .values_list('host_id', flat=True)
        )

        return Response(SystemsForRuleSerializer(
            {'host_ids': impacted_systems},
            many=False, context={'request': request}
        ).data)

    @extend_schema(
        parameters=[
            host_tags_query_param, systems_detail_sort_query_param,
            systems_detail_name_query_param, rhel_version_query_param,
            host_group_name_query_param,
            filter_system_profile_sap_system_query_param,
            filter_system_profile_sap_sids_contains_query_param,
            filter_system_profile_mssql_query_param,
            filter_system_profile_ansible_query_param,
        ],
        responses={200: SystemsDetailSerializer(many=True)},
        # should_page=True,  # How do we support this now?
    )
    @action(detail=True)
    def systems_detail(self, request, rule_id, format=None):
        """
        List systems affected by this rule with additional information about each system

        All systems owned by the user's account, with a current upload
        reporting the given rule, are listed in a paginated format.

        Additional information includes hit counts and upload/stale timestamps.
        """
        rule = self.get_object()
        sort_fields = sort_params_to_fields(
            value_of_param(systems_detail_sort_query_param, request),
            systems_detail_sort_field_map
        )
        reports = get_reports_subquery(
            request, exclude_ineligible_hosts=False, host=OuterRef('id'),
            rule=rule
        )
        systems_detail_qs = (
            get_systems_queryset(request)
            .filter(
                filter_on_display_name(
                    request, param=systems_detail_name_query_param,
                ),
                filter_on_rhel_version(request),
                Exists(reports)
            )
            .annotate(impacted_date=Subquery(reports.values('impacted_date')))
            .order_by(*sort_fields, 'display_name')
        )

        return self._paginated_response(
            systems_detail_qs, request, serializer_class=SystemsDetailSerializer
        )


class InternalRuleViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    authentication_classes = [TurnpikeIdentityAuthentication]
    lookup_field = 'rule_id'
    permission_classes = [AssociatePermission]
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer

    @extend_schema(
        responses={200: ReportForRuleSerializer(many=True)},
        # should_page=True,  # how do we support this now
    )
    @action(detail=True)
    def reports(self, request, rule_id, format=None):
        """
        List all the reports for the given rule.

        This is used by the content preview internal application to help
        content editors see how their content looks with the most recent
        rule reports.
        """
        rule = get_object_or_404(Rule, rule_id=rule_id)
        reports = rule.currentreport_set.annotate(
            delta=Extract(Now() - F('upload__checked_on'), 'epoch'),
        ).order_by('-upload__checked_on')

        return self._paginated_response(
            reports, request, serializer_class=ReportForRuleSerializer
        )
