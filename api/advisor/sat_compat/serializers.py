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

from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from api import models
from api.serializers import (
    existing_rule_id_validator,
    NonNullSerializer, NonNullModelSerializer, IntegerMethodField
)
from sat_compat import models as sat_models

from markdown import markdown
import uuid

SEVERITY_NAMES = ['NONE', 'INFO', 'WARN', 'ERROR', 'CRITICAL']


class EmptyListField(serializers.SerializerMethodField, serializers.ListField):
    """
    Just an empty list - for system and group acks.
    """
    def to_representation(self, instance):
        return []


class BooleanMethodField(serializers.SerializerMethodField, serializers.BooleanField):
    pass


class HTMLField(serializers.CharField):
    """
    A field which translates a markdown string into HTML.
    """
    def to_representation(self, instance):
        return markdown(instance, extensions=['fenced_code'])


class FalseField(serializers.BooleanField):
    def get_attribute(self, instance):
        return serializers.BooleanField

    def to_representation(self, instance):
        return False


class UUIDOrMinusOneField(serializers.UUIDField):
    """
    For those wonderful, weird moments where '-1' needs to be a valid UUID.
    """
    def to_internal_value(self, data):
        if (isinstance(data, str) and data == '-1') or (isinstance(data, int) and data == -1):
            data = uuid.UUID('FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF')
        return super().to_internal_value(data)


class LabelSerializer(serializers.Serializer):
    """
    A serializer that uses the label on each field as the field's name,
    rather than the field name itself.
    """

    def to_representation(self, instance):
        """
        Have to rewrite Serializer's to_representation to get at the field
        instances themselves.  Also avoids outputting null fields like a
        NonNullSerializer.

        If you don't set the label, be aware that one will be invented for
        you by the base Serializer field code, and that will have its first
        letter capitalised and underscores removed.  This is rarely what you
        want.
        """
        ret = OrderedDict()
        fields = self._readable_fields

        for field in fields:
            # A fair bit of error handling has been taken out for situations
            # that we don't need to handle.  Specifically, SkipField handling
            # and PKOnlyObject attribute handling.  Saves on coverage tests.
            attribute = field.get_attribute(instance)
            # If value is None, attribute is None, so don't include the field.
            if attribute is None:
                continue

            label = field.label
            value = field.to_representation(attribute)
            ret[label] = value

        return ret


##############################################################################
# Actual serializers


class DRF400ErrorSerializer(serializers.Serializer):
    "List of form errors"
    errors = serializers.ListSerializer(child=serializers.CharField())


class SatAccountProductsSerializer(serializers.ListSerializer):
    "Account products list"
    child = serializers.CharField()


class SatAccountSettingsSerializer(serializers.Serializer):
    "Account settings object"
    name = serializers.CharField()
    value = serializers.BooleanField()


class SatAckSerializer(NonNullModelSerializer):
    "Rule acknowledgement object (disable viewing of a rule)"
    rule_id = serializers.CharField(source='rule.rule_id', read_only=True)
    account_number = serializers.CharField(source='account')
    org_id = serializers.CharField()

    class Meta:
        model = models.Ack
        fields = ('id', 'rule_id', 'account_number', 'org_id')


class SatAckInputSerializer(serializers.Serializer):
    "Select a rule to be disabled in the rule list"
    rule_id = serializers.CharField(max_length=240, validators=[existing_rule_id_validator])


class SatRuleInAckSerializer(serializers.ModelSerializer):
    "A rule as displayed in the list of acknowledged/disabled rules"
    description_html = HTMLField(source='description')
    summary_html = HTMLField(source='summary')
    generic_html = HTMLField(source='generic')
    more_info_html = HTMLField(source='more_info')
    error_key = serializers.SerializerMethodField()
    plugin = serializers.SerializerMethodField()
    category = serializers.CharField(source='category.name')
    severity = serializers.SerializerMethodField()
    rec_impact = serializers.IntegerField(source='impact.impact')
    rec_likelihood = serializers.IntegerField(source='likelihood')
    retired = FalseField()

    @extend_schema_field(serializers.CharField)
    def get_error_key(self, value):
        return value.rule_id.split('|')[1]

    @extend_schema_field(serializers.CharField)
    def get_plugin(self, value):
        return value.rule_id.split('|')[0]

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value.total_risk]

    class Meta:
        model = models.Rule
        fields = (
            'active', 'node_id', 'reboot_required', 'publish_date',
            'description', 'summary', 'generic', 'reason', 'more_info',
            'description_html', 'summary_html', 'generic_html', 'more_info_html',
            'severity', 'rule_id', 'error_key', 'plugin', 'retired',
            'category', 'rec_impact', 'rec_likelihood',
        )


class SatAckWithRuleSerializer(serializers.Serializer):
    "Rule acknowledgement with full rule details"
    id = IntegerMethodField()
    rule = SatRuleInAckSerializer()
    rule_id = serializers.SerializerMethodField(read_only=True)
    account_number = serializers.CharField(source='account')
    org_id = serializers.CharField()

    @extend_schema_field(serializers.IntegerField)
    def get_id(self, value):
        # For some reason, this serializer really doesn't want to output an
        # id field unless we get it specially.  Y THO...
        return value.id

    @extend_schema_field(serializers.CharField)
    def get_rule_id(self, value):
        return value.rule.rule_id

    class Meta:
        model = models.Ack
        fields = ('id', 'rule_id', 'rule', 'account_number', 'org_id')


class SatArticleOverviewSerializer(serializers.Serializer):
    "Articles overview object"
    content_html = serializers.CharField()
    id = serializers.CharField()
    title = serializers.CharField()
    content = serializers.CharField()


class SatBranchInfoSerializer(serializers.Serializer):
    "Branch and leaf information, hard code in Classic"
    remote_leaf = serializers.IntegerField()
    remote_branch = serializers.IntegerField()


class SatEvaluationStatusSerializer(serializers.Serializer):
    "Evaluation status object"
    expired = serializers.BooleanField()
    purchased = serializers.BooleanField()
    # current = serializers.CharField(allow_null=True)
    available = serializers.ListField(child=serializers.CharField())


class SatExportReportSerializer(serializers.ModelSerializer):
    # System Name,System ID,Rule,Rule ID,Category,Severity,URL,Article,Reported Time (UTC)
    # """Stephen Super Computer""",18579840-1c44-48ad-b903-e25e7c71d677,Network connections will hang when insufficient memory is allocated for the TCP packet fragmentation,network_tcp_connection_hang|NETWORK_TCP_CONNECTION_HANG_WARN,Availability,High,https://access.redhat.com/insights/actions/availability/network_tcp_connection_hang|NETWORK_TCP_CONNECTION_HANG_WARN?machine=18579840-1c44-48ad-b903-e25e7c71d677,,2020-06-18 21:07:18
    display_name = serializers.CharField()
    insights_id = serializers.UUIDField()
    title = serializers.CharField()
    rule_id_name = serializers.CharField()
    category = serializers.CharField()
    severity = serializers.SerializerMethodField()
    url = serializers.CharField()
    article = serializers.CharField()
    reported_time = serializers.DateTimeField()

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value.severity]

    class Meta:
        model = models.CurrentReport
        fields = (
            'display_name', 'insights_id', 'title', 'rule_id_name', 'category', 'severity',
            'url', 'article', 'reported_time',
        )


class SatExportSystemSerializer(serializers.ModelSerializer):
    # System Name,System ID,System Type,Registration Date (UTC),Last Check In (UTC),Stale,Actions,URL
    # 1acab4decb1c.mylabserver.com,a2a99650-1930-4b11-8e98-0dd959aa4283,RHEL Server,2020-10-20 09:39:53,2020-10-20 09:40:41,true,1,https://console.redhat.com/insights/advisor/systems/classic/a2a99650-1930-4b11-8e98-0dd959aa4283
    system_type = serializers.CharField(source='system_type_name')
    stale = serializers.BooleanField()
    actions = serializers.IntegerField(source='actions_count')
    url = serializers.CharField()

    class Meta:
        model = models.InventoryHost
        fields = (
            'display_name', 'insights_id', 'system_type', 'created', 'updated',
            'stale', 'actions', 'url'
        )


class SatGroupSerializer(NonNullSerializer):
    pass


class SatMaintenanceActionCSVSerializer(serializers.ModelSerializer):
    display_name = serializers.CharField()
    insights_id = serializers.UUIDField()
    description = serializers.CharField()
    category = serializers.CharField()
    severity = serializers.CharField()
    article = serializers.URLField()
    completed = serializers.BooleanField()
    start = serializers.DateTimeField()
    end = serializers.DateTimeField()

    class Meta:
        model = sat_models.SatMaintenanceAction
        fields = (
            'display_name', 'insights_id', 'description', 'category',
            'severity', 'article', 'completed', 'start', 'end',
        )


class SatMaintenanceActionAddPlaybookSerializer(serializers.Serializer):
    "Select the resolution type for this maintenance action"
    resolution_type = serializers.CharField()


class SatMaintenanceActionRuleSerializer(serializers.ModelSerializer):
    "Rule details in action detail of maintenance object"
    id = serializers.CharField(source='rule_id')
    description_html = HTMLField(source='description')
    severity = serializers.SerializerMethodField(source='total_risk')
    ansible = serializers.BooleanField()
    ansible_fix = serializers.BooleanField()
    ansible_mitigation = serializers.BooleanField()
    rec_impact = serializers.IntegerField()
    rec_likelihood = serializers.IntegerField(source='likelihood')
    category = serializers.CharField()

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value.total_risk]

    class Meta:
        model = models.Rule
        fields = (
            'id', 'description', 'description_html', 'severity',
            'ansible', 'ansible_fix', 'ansible_mitigation', 'category',
            'reboot_required', 'rec_impact', 'rec_likelihood',
        )


class SatMaintenanceActionSystemSerializer(serializers.ModelSerializer):
    "System details in action detail of maintenance object"
    # Based on InventoryHost model for the fields, although the queryset is
    # actually based on the Host model and includes the Inventory fields.
    toString = serializers.CharField(source='display_name')
    isCheckingIn = serializers.BooleanField()
    system_id = serializers.UUIDField(source='inventory.insights_id')
    hostname = serializers.CharField(source='display_name')
    system_type_id = serializers.IntegerField()
    last_check_in = serializers.DateTimeField()

    class Meta:
        model = models.InventoryHost
        fields = (
            'toString', 'isCheckingIn', 'system_id', 'display_name',
            'hostname', 'last_check_in', 'system_type_id',
        )


class SatMaintenanceActionReportSerializer(serializers.ModelSerializer):
    "(Optional) report information for action detail of maintenance object"
    class Meta:
        model = models.CurrentReport
        fields = ('id', 'details',)


class SatMaintenanceActionSerializer(NonNullModelSerializer):
    "An available action for maintenance"
    done = serializers.BooleanField()
    maintenance_id = serializers.IntegerField(source='plan_id')
    system = SatMaintenanceActionSystemSerializer(
        source='host', many=False
    )
    rule = SatMaintenanceActionRuleSerializer(many=False)
    current_report = SatMaintenanceActionReportSerializer(
        many=False, required=False
    )

    class Meta:
        model = sat_models.SatMaintenanceAction
        fields = (
            'id', 'maintenance_id', 'system', 'rule', 'current_report', 'done'
        )


class SatMaintenanceActionSimpleSerializer(NonNullModelSerializer):
    "An available action for maintenance, without sub-data"
    done = serializers.BooleanField()
    maintenance_id = serializers.IntegerField(source='plan_id')

    class Meta:
        model = sat_models.SatMaintenanceAction
        fields = ('id', 'maintenance_id', 'done')


class SatMaintenancePlayResolutionSerializer(serializers.ModelSerializer):
    """
    List of playbook information for this rule.
    """
    resolution_type = serializers.CharField(source='type')
    rule_id = serializers.CharField()
    system_type_id = serializers.IntegerField()
    # Probably needs to be per playbook?
    needs_reboot = serializers.BooleanField()
    resolution_risk = serializers.IntegerField()

    class Meta:
        model = models.Playbook
        fields = (
            'resolution_type', 'description', 'rule_id', 'system_type_id',
            'needs_reboot', 'resolution_risk'
        )


class SatMaintenancePlayRuleSerializer(serializers.ModelSerializer):
    "Rule details in play detail of maintenance plan"
    category = serializers.CharField(source='category_name')
    severity = serializers.SerializerMethodField()

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value.total_risk]

    class Meta:
        model = models.Rule
        fields = (
            'rule_id', 'description', 'category', 'severity',
        )


class SatMaintenancePlaySerializer(serializers.ModelSerializer):
    "A set of resolutions for the rules in a plan"
    system_type_id = IntegerMethodField()
    rule = SatMaintenancePlayRuleSerializer(many=False)
    ansible_resolutions = SatMaintenancePlayResolutionSerializer(many=True)

    @extend_schema_field(serializers.IntegerField)
    def get_system_type_id(self, value):
        # rhel/host, since we don't store this per host at all.
        return 105

    class Meta:
        model = sat_models.SatMaintenanceAction
        fields = (
            'system_type_id', 'rule', 'ansible_resolutions'
        )


class SatMaintenanceSerializer(NonNullModelSerializer):
    "Maintenance details object"
    # Note: when being added, use the 'SatMaintenanceAddSerializer' below.
    maintenance_id = serializers.IntegerField(source='id', read_only=True)
    remote_branch = serializers.UUIDField(source='branch_id', read_only=True)
    start = serializers.DateTimeField(required=False, allow_null=True)
    end = serializers.DateTimeField(required=False, allow_null=True)
    overdue = serializers.BooleanField(required=False, read_only=True)
    actions = SatMaintenanceActionSerializer(many=True, allow_null=True, required=False)

    class Meta:
        model = sat_models.SatMaintenance
        fields = (
            'maintenance_id', 'remote_branch', 'name', 'suggestion',
            'description', 'start', 'end', 'created_by', 'overdue',
            'silenced', 'hidden', 'allow_reboot', 'actions',
        )
        read_only_fields = (
            'maintenance_id', 'remote_branch', 'suggestion', 'created_by',
            'overdue',
        )


class SatMaintenanceAddActionSerializer(serializers.Serializer):
    """
    A rule, applied to either a single host or (when null) to all hosts on
    this Satellite.
    """
    rule_id = serializers.CharField(validators=[existing_rule_id_validator])
    system_id = serializers.UUIDField(required=False)


class SatMaintenanceAddSerializer(serializers.Serializer):
    """
    Satellite creates a plan by supplying a name and the 'add' field, which
    is a list of SatMaintenanceAddActionSerializer actions.
    """
    name = serializers.CharField()
    description = serializers.CharField(required=False)
    start = serializers.DateTimeField(required=False)
    end = serializers.DateTimeField(required=False)
    hidden = serializers.BooleanField(required=False)
    add = SatMaintenanceAddActionSerializer(many=True)


def existing_action_id_validator(pk):
    if not sat_models.SatMaintenanceAction.objects.filter(pk=pk).exists():
        raise serializers.ValidationError(f"Action with ID '{pk}' does not exist")


class SatMaintenanceEditSerializer(serializers.ModelSerializer):
    """
    Almost like the add and view serializers but has extra fields that can
    remove, change and add actions.
    """
    # Actions to be deleted - compare 'actions' field
    delete = serializers.ListField(child=serializers.IntegerField(
        validators=[existing_action_id_validator],
        help_text='A list of action IDs to delete from this plan'
    ), required=False)
    # Actions that should remain - compare 'delete' field
    actions = serializers.ListField(child=serializers.IntegerField(
        validators=[existing_action_id_validator],
        help_text='A list of action IDs to leave in this plan, removing all others'
    ), required=False)
    # Add new actions
    add = SatMaintenanceAddActionSerializer(many=True, required=False)

    class Meta:
        model = sat_models.SatMaintenance
        fields = (
            'id', 'name', 'description', 'start', 'end', 'silenced',
            'hidden', 'delete', 'actions', 'add',
        )


class SatMaintenanceNewMaintenancePlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = sat_models.SatMaintenance
        fields = ('id',)


class SatMeSerializer(serializers.Serializer):
    """
    Data about the account making this request.

    That's all that Satellite uses.
    """
    account_number = serializers.CharField()
    org_id = serializers.CharField()


class SatPlaybookSerializer(serializers.ModelSerializer):
    """
    Data about a specific playbook.
    """
    resolution_type = serializers.CharField(source='type')
    rule_id = serializers.CharField()
    system_type_id = serializers.IntegerField()
    needs_reboot = serializers.BooleanField()
    needs_pydata = serializers.BooleanField()
    resolution_risk = serializers.IntegerField()

    class Meta:
        model = models.Playbook
        fields = (
            'id', 'resolution_type', 'rule_id', 'system_type_id',
            'description', 'play', 'version', 'needs_reboot', 'needs_pydata',
            'resolution_risk',
        )


class SatPluginSerializer(serializers.ModelSerializer):
    plugin = serializers.CharField()
    name = serializers.CharField()

    class Meta:
        model = models.Rule
        fields = ('plugin', 'name')


class SatReportSystemSerializer(NonNullModelSerializer):
    """
    System information for the reports view
    """
    system_id = serializers.UUIDField()
    display_name = serializers.CharField()
    last_check_in = serializers.DateTimeField()

    class Meta:
        model = models.Host
        fields = (
            'system_id', 'display_name', 'last_check_in',
        )


class SatReportSerializer(serializers.ModelSerializer):
    """
    Reports of a rule impacting a host.
    """
    # Used by both `/cves`, which is null because we don't show them, and
    # `/reports`.
    rule_id = serializers.CharField(source='rule_name')
    system_id = serializers.UUIDField(source='insights_id')
    account_number = serializers.CharField(source='account')
    date = serializers.DateTimeField()
    # Not showing the uuid field - why, when we've got an ID?
    system = SatReportSystemSerializer(source='host', many=False)
    # Not expanding the rule yet until we see 'expand=rule' used

    class Meta:
        model = models.CurrentReport
        fields = (
            'id', 'rule_id', 'system_id', 'account_number', 'org_id', 'date', 'system',
        )


class SatResolutionSerializer(serializers.ModelSerializer):
    """
    List of resolutions for this rule.
    """
    system_type_id = serializers.CharField()
    resolution_risk = serializers.IntegerField(source='risk_level')

    class Meta:
        model = models.Resolution
        fields = ('system_type_id', 'resolution', 'resolution_risk')


class SatRuleTagSerializer(serializers.ModelSerializer):
    """
    A list of tag names.  Since tags in the content, and in Advisor, don't
    actually have a description, we omit this.
    """
    class Meta:
        model = models.Tag
        fields = ('name', )


class SatRuleSerializer(NonNullModelSerializer):
    """
    Rule information when we know the account, and therefore know which
    systems are affected by this rule.
    """
    description_html = HTMLField(source='description')
    summary_html = HTMLField(source='summary')
    generic_html = HTMLField(source='generic')
    reason_html = HTMLField(source='reason')
    more_info_html = HTMLField(source='more_info', allow_blank=True)
    plugin_name = serializers.CharField(source='description')
    error_key = serializers.CharField()
    plugin = serializers.CharField()
    id = serializers.CharField(source='rule_id')
    name = serializers.CharField(source='rule_id')
    category = serializers.CharField(source='category_name')
    severity = serializers.SerializerMethodField(source='total_risk')
    resolution_risk = serializers.IntegerField()
    rec_impact = serializers.IntegerField()
    rec_likelihood = serializers.IntegerField(source='likelihood')
    impacted_systems = serializers.IntegerField()
    report_count = serializers.IntegerField()
    ansible = IntegerMethodField()
    hasIncidents = serializers.IntegerField()
    retired = FalseField()
    tags = SatRuleTagSerializer(many=True)
    resolution_set = SatResolutionSerializer(many=True)
    ack_id = IntegerMethodField(required=False)
    system_acks = EmptyListField()
    group_acks = EmptyListField()
    article = serializers.CharField(allow_blank=True)

    @extend_schema_field(serializers.IntegerField)
    def get_ack_id(self, value):
        # ack_id here is a list of one ID for this account and branch
        if value.ack_id:
            return value.ack_id[0].id
        else:
            return None

    @extend_schema_field(serializers.IntegerField)
    def get_ansible(self, value):
        return value.ansible or 0

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value.total_risk]

    class Meta:
        model = models.Rule
        fields = (
            'rule_id',
            'active', 'node_id', 'tags', 'reboot_required', 'publish_date',
            'description', 'summary', 'generic', 'reason', 'more_info',
            'description_html', 'summary_html', 'generic_html', 'reason_html',
            'more_info_html',
            'plugin_name', 'severity', 'error_key', 'plugin', 'resolution_risk',
            'category', 'rec_impact', 'rec_likelihood', 'id', 'name',
            'impacted_systems', 'hasIncidents', 'ack_id',
            'tags', 'resolution_set', 'report_count', 'ansible', 'retired',
            'system_acks', 'group_acks', 'article',
        )


class SatRuleTopicRuleSerializer(serializers.ModelSerializer):
    """
    The rule list within a topic for Satellite compatibility.
    """
    # Because we can't annotate the rule query here, we have to do the work
    # in the serializer.
    category = serializers.CharField(source='category_name')
    severity = serializers.SerializerMethodField(source='total_risk')
    summary_html = HTMLField(source='summary')
    hitCount = serializers.IntegerField()
    error_key = serializers.CharField()
    plugin = serializers.CharField()
    plugin_name = serializers.CharField(source='description')
    ansible = serializers.IntegerField()
    rec_impact = serializers.IntegerField()
    rec_likelihood = serializers.IntegerField(source='likelihood')
    resolution_risk = serializers.IntegerField(source='risk_level')
    acked = serializers.IntegerField()

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value.total_risk]

    class Meta:
        model = models.Rule
        fields = (
            'rule_id', 'description', 'category', 'severity', 'hitCount',
            'summary', 'summary_html', 'plugin', 'error_key', 'plugin_name',
            'ansible', 'rec_impact', 'rec_likelihood', 'resolution_risk',
            'acked',
        )


class SatRuleTopicSerializer(serializers.ModelSerializer):
    """
    The view of rule topics for Satellite compatibility.
    """
    # This source is generated by a Prefetch in the list method and in the
    # elements of the dict passed by the retrieve method.
    rules = SatRuleTopicRuleSerializer(source='tag.rules', many=True)
    hitCount = serializers.IntegerField()
    affectedSystemCount = serializers.IntegerField()
    slug = serializers.CharField()
    ruleBinding = serializers.CharField()
    alwaysShow = serializers.BooleanField()
    priority = serializers.IntegerField()
    title = serializers.CharField(source='name')
    summary = serializers.CharField(source='name')
    summary_html = HTMLField(source='name')
    slug = serializers.CharField()
    content = serializers.CharField(source='description')
    content_html = HTMLField(source='description')
    listed = serializers.CharField()
    tag = serializers.CharField(source='tag_name')
    hidden = serializers.BooleanField()

    class Meta:
        model = models.RuleTopic
        fields = (
            'id', 'rules', 'hitCount', 'affectedSystemCount', 'slug',
            'ruleBinding', 'alwaysShow', 'id', 'title', 'summary',
            'summary_html', 'content', 'content_html', 'priority', 'listed',
            'tag', 'hidden'
        )


class SatStatsSubSSerializer(serializers.Serializer):
    """
    A count of total and affected systems.
    """
    total = serializers.IntegerField()
    affected = serializers.IntegerField()


class SatStatsSubRRSerializer(serializers.Serializer):
    """
    Rules and reports both get a total count and a per-risk and per-category
    count.
    """
    total = serializers.IntegerField()
    info = serializers.IntegerField()
    warn = serializers.IntegerField()
    error = serializers.IntegerField()
    critical = serializers.IntegerField()
    availability = serializers.IntegerField()
    security = serializers.IntegerField()
    stability = serializers.IntegerField()
    performance = serializers.IntegerField()


class SatStatsSerializer(serializers.Serializer):
    """
    Statistics about systems, reports and rules.
    """
    systems = SatStatsSubSSerializer()
    reports = SatStatsSubRRSerializer()
    rules = SatStatsSubRRSerializer()


class SatSystemAcksSerializer(serializers.Serializer):
    """
    A combined list of global and system recommendation disablements.
    """
    system = serializers.BooleanField()
    groups = EmptyListField()
    is_global = serializers.BooleanField(label='global')
    rule_id = serializers.CharField()


class SatSystemsSerializer(serializers.ModelSerializer):
    """
    System information when we know the account, and therefore can count
    how many reports of enabled recommendations the system has.
    """
    # Note: cannot use NonNullModelSerializer because unregistered_at has to
    # be transmitted to the client for the client to determine that it's
    # registered.
    toString = serializers.CharField(source='display_name')
    isCheckingIn = serializers.BooleanField()
    system_id = serializers.UUIDField(source='insights_id')
    account_number = serializers.CharField(source='account')
    org_id = serializers.CharField()
    hostname = serializers.CharField(source='display_name')
    last_check_in = serializers.DateTimeField(source='updated')
    created_at = serializers.DateTimeField(source='created')
    updated_at = serializers.DateTimeField(source='updated')
    unregistered_at = serializers.DateTimeField(required=False, allow_null=True)
    system_type_id = serializers.IntegerField()
    role = serializers.CharField()
    product_code = serializers.CharField()
    report_count = serializers.IntegerField()
    remote_branch = serializers.UUIDField()
    remote_leaf = serializers.UUIDField()
    acks = SatSystemAcksSerializer(many=True)

    class Meta:
        model = models.InventoryHost
        fields = (
            'toString', 'isCheckingIn', 'system_id', 'display_name',
            'account_number', 'org_id', 'hostname', 'last_check_in', 'created_at',
            'updated_at', 'unregistered_at', 'system_type_id', 'role',
            'product_code', 'report_count', 'remote_branch', 'remote_leaf',
            'acks',
        )


class SatSystemNewSerializer(serializers.ModelSerializer):
    """
    Data used to pretend to create a new system in Insights.

    Data is validated but no host is created, because the host must perform a
    successful upload for it to be recognised by Inventory.
    """
    machine_id = serializers.UUIDField(source='inventory_id')
    remote_branch = UUIDOrMinusOneField(source='branch_id')
    remote_leaf = UUIDOrMinusOneField(source='satellite_id')
    hostname = serializers.CharField()

    class Meta:
        model = models.Host
        fields = ('machine_id', 'remote_branch', 'remote_leaf', 'hostname')


class SatSystemEditSerializer(serializers.ModelSerializer):
    """
    Used for updating a host's display name.
    """

    class Meta:
        model = models.InventoryHost
        fields = ('display_name', )


class SatReportRuleSerializer(serializers.ModelSerializer):
    """
    Rule information related to reports of this rule
    """
    resolution = serializers.CharField()
    error_key = serializers.SerializerMethodField()
    plugin = serializers.SerializerMethodField()
    category = serializers.CharField(source='category_name')
    severity = serializers.SerializerMethodField(source='total_risk')
    resolution_risk = serializers.IntegerField()
    rec_impact = serializers.IntegerField()
    rec_likelihood = serializers.IntegerField(source='likelihood')
    more_info_html = serializers.CharField(source='more_info')
    ansible = serializers.BooleanField()
    ansible_fix = serializers.BooleanField()
    ansible_mitigation = serializers.BooleanField()
    retired = FalseField()

    @extend_schema_field(serializers.CharField)
    def get_error_key(self, value):
        return value['rule_id'].split('|')[1]

    @extend_schema_field(serializers.CharField)
    def get_plugin(self, value):
        return value['rule_id'].split('|')[0]

    @extend_schema_field(serializers.CharField)
    def get_severity(self, value):
        return SEVERITY_NAMES[value['total_risk']]

    class Meta:
        model = models.Rule
        fields = (
            'rule_id', 'error_key', 'plugin',
            'active', 'node_id', 'reboot_required', 'publish_date',
            'description', 'summary', 'generic', 'reason', 'more_info', 'more_info_html',
            'severity', 'resolution', 'resolution_risk',
            'category', 'rec_impact', 'rec_likelihood',
            'ansible', 'ansible_fix', 'ansible_mitigation', 'retired',
        )


class SatSystemReportSerializer(NonNullModelSerializer):
    """
    Details of a report affecting a system.
    """
    rule_id = serializers.CharField(source='rule.rule_id')
    system_id = serializers.CharField(source='insights_id')
    account_number = serializers.CharField(source='account')
    org_id = serializers.CharField()
    date = serializers.DateTimeField(source='checked_on')
    rule = SatReportRuleSerializer(many=False)
    maintenance_actions = SatMaintenanceActionSimpleSerializer(many=True)

    class Meta:
        model = models.CurrentReport
        fields = (
            'details', 'id', 'rule_id', 'system_id', 'account_number', 'org_id',
            'date', 'rule', 'maintenance_actions',
        )


class SatSystemReportsSerializer(NonNullModelSerializer):
    """
    System information and reports for a single system.
    """
    toString = serializers.CharField(source='display_name')
    isCheckingIn = serializers.BooleanField()
    system_id = serializers.UUIDField(source='insights_id')
    account_number = serializers.CharField(source='account')
    org_id = serializers.CharField()
    hostname = serializers.CharField(source='display_name')
    last_check_in = serializers.DateTimeField(source='updated')
    created_at = serializers.DateTimeField(source='created')
    updated_at = serializers.DateTimeField(source='updated')
    system_type_id = serializers.IntegerField()
    role = serializers.CharField()
    product_code = serializers.CharField()
    remote_branch = serializers.UUIDField()
    remote_leaf = serializers.UUIDField()
    reports = SatSystemReportSerializer(many=True)

    class Meta:
        model = models.InventoryHost
        fields = (
            'toString', 'isCheckingIn', 'system_id', 'display_name',
            'account_number', 'org_id', 'hostname', 'last_check_in', 'created_at',
            'updated_at', 'system_type_id', 'role', 'product_code',
            'remote_branch', 'remote_leaf', 'reports',
        )


class SatSystemMetadataSerializer(LabelSerializer):
    """
    Metadata for a system.
    """
    bios_release_date = serializers.CharField(
        label='bios_information.release_date', required=False)
    bios_vendor = serializers.CharField(
        label='bios_information.vendor', required=False)
    bios_version = serializers.CharField(
        label='bios_information.version', required=False)
    release = serializers.CharField(
        label='release', required=False)
    rhel_version = serializers.CharField(
        label='rhel_version', required=False)
    system_family = serializers.CharField(
        label='system_information.family', required=False)
    system_type = serializers.CharField(
        label='system_information.machine_type', required=False)
    system_vm = serializers.CharField(
        label='system_information.virtual_machine', required=False)
