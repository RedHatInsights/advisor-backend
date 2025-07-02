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
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer

from api import models


def existing_rule_id_validator(rule_id):
    if not models.Rule.objects.filter(rule_id=rule_id).exists():
        raise serializers.ValidationError(f"Rule with ID '{rule_id}' does not exist")


def existing_host_id_validator(host_id):
    if not models.InventoryHost.objects.filter(pk=host_id).exists():
        raise serializers.ValidationError(f"Host with UUID '{host_id}' not found")


##############################################################################
# Abstract base serializer and field classes

class NonNullSerializer(serializers.Serializer):
    """
    Serializer which removes any null entries when 'to_representation' is called.
    """
    def to_representation(self, instance):
        """Override Serializer's to_representation method."""
        original = super().to_representation(instance)
        return OrderedDict([(key, val) for key, val in original.items() if val is not None])


class NonNullModelSerializer(serializers.ModelSerializer, NonNullSerializer):
    """
    ModelSerializer which removes any null entries when 'to_representation' is called.
    """
    pass


class IntegerMethodField(serializers.SerializerMethodField, serializers.IntegerField):
    """
    This allows a serializer method field to be detected as returning an
    integer.
    """
    pass


class FloatMethodField(serializers.SerializerMethodField, serializers.FloatField):
    """
    This allows a serializer method field to be detected as returning an
    integer.
    """
    pass


class ListMethodField(serializers.SerializerMethodField, serializers.ListField):
    """
    This allows a serializer method field to be detected as returning a
    list of objects.
    """
    pass


##############################################################################
# Actual serializers


class OrgIdSerializer(serializers.Serializer):
    """
    A specific org id for a Red Hat customer.
    """
    org_id = serializers.CharField(max_length=10, min_length=6)


class HostCountSerializer(serializers.Serializer):
    """
    The count of hosts for a specific account.
    """
    total_hosts = serializers.IntegerField(
        help_text='The total number of hosts in this account')
    stale_hosts = serializers.IntegerField(
        help_text='The number of hosts that are stale and being warned about')
    warn_hosts = serializers.IntegerField(
        help_text='The number of hosts that are stale and being hidden from reports')
    fresh_hosts = serializers.IntegerField(
        help_text='The number of refreshing regularly hosts')


class RuleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = models.RuleCategory
        fields = ('id', 'name',)


class RuleImpactSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.RuleImpact
        fields = ('name', 'impact',)


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Tag
        fields = ('name', )


class TagNameSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=32)

    help_text = "Tag name"


class PlaybookSerializer(serializers.ModelSerializer):
    resolution_risk = serializers.IntegerField(read_only=True)
    resolution_type = serializers.CharField(source='type')

    class Meta:
        model = models.Playbook
        fields = ('resolution_risk', 'resolution_type', 'play', 'description', 'path', 'version')


class ResolutionRiskSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ResolutionRisk
        fields = ('name', 'risk',)


class ResolutionSerializer(serializers.ModelSerializer):
    has_playbook = serializers.BooleanField(read_only=True)
    resolution_risk = ResolutionRiskSerializer(many=False, read_only=True)
    # playbook_set = PlaybookSerializer(many=True, read_only=True)

    class Meta:
        model = models.Resolution
        fields = ('system_type', 'resolution', 'resolution_risk', 'has_playbook')


class RuleSerializer(NonNullModelSerializer):
    """
    The standard rule information.  Used for models and relations that don't
    know the account and therefore can't know the acks or impacted systems.
    """
    category = RuleCategorySerializer(many=False)
    # drf_spectacular doesn't seem to understand the model's null=True when
    # it's also editable=False.  So we mark it as not required here too.
    deleted_at = serializers.DateTimeField(required=False)
    impact = RuleImpactSerializer(many=False)
    resolution_set = ResolutionSerializer(many=True)
    tags = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_tags(self, value):
        return ' '.join(tag.name for tag in value.tags.order_by('name'))

    class Meta:
        model = models.Rule
        fields = (
            'rule_id', 'created_at', 'updated_at', 'deleted_at',
            'description', 'active', 'category', 'impact',
            'likelihood', 'node_id', 'tags', 'reboot_required',
            'publish_date', 'summary', 'generic', 'reason', 'more_info',
            'resolution_set', 'total_risk'
        )


class PathwayInputSerializer(serializers.Serializer):
    """
    Serializer specifically for handling
    CREATE and UPDATE views for Pathways
    """
    name = serializers.CharField()
    description = serializers.CharField()
    component = serializers.CharField()
    resolution_risk = serializers.CharField()
    publish_date = serializers.DateTimeField()


class PathwaySerializer(NonNullModelSerializer):
    """
    Serializer specifically for listing
    all Pathways currently in the system
    """
    slug = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()
    component = serializers.CharField()
    resolution_risk = ResolutionRiskSerializer()
    publish_date = serializers.DateTimeField()
    has_playbook = serializers.BooleanField()
    impacted_systems_count = serializers.IntegerField()
    reboot_required = serializers.BooleanField()
    has_incident = serializers.BooleanField()
    categories = ListMethodField(child=RuleCategorySerializer())
    recommendation_level = serializers.FloatField()
    incident_count = serializers.IntegerField()
    critical_risk_count = serializers.IntegerField()
    high_risk_count = serializers.IntegerField()
    medium_risk_count = serializers.IntegerField()
    low_risk_count = serializers.IntegerField()

    def get_categories(self, value):
        categories = value.categories(self.context['request']).all()
        return RuleCategorySerializer(categories, many=True).data

    class Meta:
        model = models.Pathway
        fields = ('slug', 'name', 'description', 'component', 'resolution_risk', 'publish_date',
                  'has_playbook', 'impacted_systems_count', 'reboot_required',
                  'has_incident', 'categories', 'recommendation_level', 'incident_count',
                  'critical_risk_count', 'high_risk_count', 'medium_risk_count',
                  'low_risk_count'
                  )


class RulePathwaySerializer(serializers.ModelSerializer):
    resolution_risk = ResolutionRiskSerializer(many=False, read_only=True)

    class Meta:
        model = models.Pathway
        fields = ('name', 'component', 'resolution_risk')


class RuleForAccountSerializer(NonNullModelSerializer):
    """
    Rule information when we know the account, and therefore can calculate
    the number of impacted systems and the reports_shown/rule_status flags.
    We have to declare those explicitly here because they're not part of the model.
    """
    category = RuleCategorySerializer(many=False)
    # drf_spectacular doesn't seem to understand the model's null=True when
    # it's also editable=False.  So we mark it as not required here too.
    deleted_at = serializers.DateTimeField(required=False)
    impact = RuleImpactSerializer(many=False)
    # Annotated fields aren't found in the model definition, so we have to
    # add their definition explicitly here.  Their values are still picked up
    # from the queryset data correctly.
    impacted_systems_count = serializers.IntegerField(read_only=True)
    playbook_count = IntegerMethodField(read_only=True)
    hosts_acked_count = serializers.IntegerField(read_only=True)
    reports_shown = serializers.BooleanField(read_only=True)
    rule_status = serializers.CharField(read_only=True)
    resolution_set = ResolutionSerializer(many=True)
    tags = serializers.SerializerMethodField()
    rating = serializers.IntegerField(read_only=True)
    pathway = RulePathwaySerializer(many=False, required=False)

    def get_playbook_count(self, value):
        return 0 if value.playbook_count is None else value.playbook_count

    @extend_schema_field(OpenApiTypes.STR)
    def get_tags(self, value):
        return ' '.join(tag.name for tag in value.tags.order_by('name'))

    class Meta:
        model = models.Rule
        fields = (
            'rule_id', 'created_at', 'updated_at', 'deleted_at',
            'description', 'active', 'category', 'impact',
            'likelihood', 'node_id', 'tags', 'playbook_count',
            'reboot_required', 'publish_date', 'summary', 'generic',
            'reason', 'more_info', 'impacted_systems_count', 'reports_shown', 'rule_status',
            'resolution_set', 'total_risk', 'hosts_acked_count', 'rating', 'pathway'
        )


class ExportHitsSerializer(serializers.Serializer):
    """
    The basic report information for each system affected by a rule.  Only
    lists basic details of the host and rule, and links to more information.
    """

    hostname = serializers.CharField()
    rhel_version = serializers.CharField()
    uuid = serializers.UUIDField()
    last_seen = serializers.DateTimeField()
    title = serializers.CharField()
    solution_url = serializers.URLField(allow_blank=True)
    total_risk = serializers.IntegerField()
    likelihood = serializers.IntegerField()
    publish_date = serializers.DateTimeField()
    stale_at = serializers.DateTimeField()
    results_url = serializers.URLField()


class ReportExportSerializer(NonNullModelSerializer):
    """
    Report information for export.  Based on CurrentReport with fields from
    Rule and Host pulled through for convenience.
    """
    host_id = serializers.UUIDField(source='host_id'),
    rule_id = serializers.CharField(source='rule__rule_id')
    reports_url = serializers.CharField()
    report_time = serializers.DateTimeField(source='upload__checked_on')

    class Meta:
        model = models.CurrentReport
        fields = (
            'rule_id', 'host_id', 'reports_url', 'report_time', 'details', 'impacted_date',
        )


class RuleExportSerializer(NonNullModelSerializer):
    """
    Rule information for export.
    """
    category = serializers.CharField(source='category_name')
    impact = serializers.CharField(source='impact_name')
    playbook_count = serializers.IntegerField()
    impacted_systems_count = serializers.IntegerField()
    resolution_set = ResolutionSerializer(many=True)
    rule_status = serializers.CharField(read_only=True)
    hosts_acked_count = serializers.IntegerField()
    tags = serializers.SerializerMethodField()
    rating = serializers.IntegerField(read_only=True)
    reports_shown = serializers.BooleanField(read_only=True)

    @extend_schema_field(OpenApiTypes.STR)
    def get_tags(self, value):
        return ' '.join(tag.name for tag in value.tags.order_by('name'))

    class Meta:
        model = models.Rule
        fields = (
            'rule_id', 'created_at', 'updated_at', 'deleted_at',
            'description', 'active', 'category', 'impact',
            'likelihood', 'node_id', 'tags', 'playbook_count',
            'reboot_required', 'publish_date', 'summary', 'generic',
            'reason', 'more_info', 'impacted_systems_count', 'rule_status',
            'resolution_set', 'total_risk', 'hosts_acked_count', 'rating',
            'reports_shown',
        )


class RuleSystemsExportSerializer(serializers.Serializer):
    "List of systems with current reports for each rule."
    rules = serializers.DictField(
        child=serializers.ListField(child=serializers.UUIDField())
    )


class AckSerializer(serializers.ModelSerializer):
    rule = serializers.CharField(source='rule.rule_id')

    class Meta:
        model = models.Ack
        fields = ('rule', 'justification', 'created_by', 'created_at', 'updated_at')


class AllAckSerializer(serializers.ModelSerializer):
    account = serializers.CharField()  # Remove at a later time, keep for now for potential backwards compat
    org_id = serializers.CharField()
    rule = serializers.CharField(label='rule_id', source='rule_id_field')

    class Meta:
        model = models.Ack
        fields = (
            'account',  # Remove at a later time, keep for now for potential backwards compat
            'org_id', 'rule', 'justification', 'created_by', 'created_at',
            'updated_at'
        )


class AckInputSerializer(serializers.Serializer):
    rule_id = serializers.CharField(max_length=240, validators=[existing_rule_id_validator])
    justification = serializers.CharField(max_length=255, allow_blank=True, default='')


class AckJustificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Ack
        fields = ('justification',)


class JustificationCountSerializer(serializers.Serializer):
    justification = serializers.CharField()
    count = serializers.IntegerField()


class HostAckSerializer(serializers.ModelSerializer):
    """
    Ignore reports of this rule on this system for this account.
    """
    rule = serializers.SlugRelatedField(
        slug_field='rule_id', many=False,
        queryset=models.Rule.objects.filter(active=True),
    )
    system_uuid = serializers.UUIDField(source='host_id')
    display_name = serializers.CharField(source='host.inventory.display_name', read_only=True)

    class Meta:
        model = models.HostAck
        fields = (
            'id', 'rule', 'system_uuid', 'justification', 'created_by',
            'created_at', 'updated_at', 'display_name',
        )
        read_only_fields = ['id', 'created_by', 'created_at', 'updated_at']


class HostAckInputSerializer(serializers.ModelSerializer):
    """
    Ignore reports of this rule on this system for this account.

    Use this when creating a new HostAck.
    """
    rule = serializers.SlugRelatedField(
        slug_field='rule_id', many=False,
        queryset=models.Rule.objects.filter(active=True),
    )
    system_uuid = serializers.UUIDField(source='host_id')

    class Meta:
        model = models.HostAck
        fields = (
            'rule', 'system_uuid', 'justification',
        )


class HostAckJustificationSerializer(serializers.ModelSerializer):
    """
    Just modify the justification on a Host Ack.
    """
    class Meta:
        model = models.HostAck
        fields = ('id', 'justification')


def validate_hosts_in_org(hosts, org_id, field_name='systems'):
    """
    Check that the hosts given exist, and they are in this org.  We need to
    not distinguish between the two to avoid leaking that a host UUID exists.
    """
    valid_hosts = set(models.InventoryHost.objects.filter(
        org_id=org_id, id__in=hosts
    ).values_list('id', flat=True))
    nonexistent_hosts = {
        str(row): [f"Host with UUID '{str(system_uuid)}' not found"]
        for row, system_uuid in enumerate(hosts)
        if system_uuid not in valid_hosts
    }
    if nonexistent_hosts:
        raise serializers.ValidationError({field_name: nonexistent_hosts})


class MultiHostAckSerializer(serializers.Serializer):
    """
    Add acks to multiple hosts for a single rule.
    """
    systems = serializers.ListField(child=serializers.UUIDField())
    justification = serializers.CharField(max_length=255, allow_blank=True)

    def validate(self, data):
        assert 'request' in self._context, (
            "Supply the request in the context to the serializer, e.g. "
            "context={'request': request}"
        )
        validate_hosts_in_org(data['systems'], self._context['request'].auth['org_id'])
        return data


class MultiHostUnAckSerializer(serializers.Serializer):
    """
    Delete acks from multiple hosts for a single rule.
    """
    systems = serializers.ListField(child=serializers.UUIDField())

    def validate(self, data):
        assert 'request' in self._context, (
            "Supply the request in the context to the serializer, e.g. "
            "context={'request': request}"
        )
        validate_hosts_in_org(data['systems'], self._context['request'].auth['org_id'])
        return data


class MultiAckResponseSerializer(serializers.Serializer):
    """
    The response from adding or deleting multiple acks on a rule.  For backward
    compatibility we include the count, and then list the impacted systems.
    """
    count = serializers.IntegerField()
    host_ids = serializers.ListField(child=serializers.UUIDField())


class ImportStatsSerializer(serializers.Serializer):
    """
    Output of import - statistics of rules added etc.
    """
    stats = serializers.DictField(child=serializers.DictField(child=serializers.IntegerField()))


class KcsSerializer(serializers.Serializer):
    """
    Pairings of C.R.C rule URL and its KCS solution number (node_id)
    """
    rule_url = serializers.URLField(help_text="Rule URL on C.R.C.")
    node_id = serializers.CharField(help_text="KCS solution number")


# This doesn't get invoked, it's just used to decorate the KCS retrieval
KcsRuleSerializer = serializers.ListSerializer(
    child=serializers.URLField(help_text="Rule URL on C.R.C.")
)


class PreferencesInputSerializer(serializers.Serializer):
    """
    User preferences - separated from account settings.
    """
    is_subscribed = serializers.BooleanField()


class RuleIdSerializer(serializers.Serializer):
    """
    Insights Rule ID
    """
    rule_id = serializers.CharField(max_length=240, validators=[existing_rule_id_validator])


class TopicSerializer(serializers.ModelSerializer):
    """
    Topics group rules by a tag shared by all the rules.
    """
    impacted_systems_count = serializers.IntegerField(read_only=True)
    tag = serializers.SlugRelatedField(
        slug_field='name', many=False,
        queryset=models.Tag.objects.all(),
    )

    class Meta:
        model = models.RuleTopic
        fields = (
            'name', 'slug', 'description', 'tag', 'featured',
            'enabled', 'impacted_systems_count',
        )


class TopicEditSerializer(serializers.ModelSerializer):
    """
    Create or edit topics.
    """
    tag = serializers.SlugRelatedField(
        slug_field='name', many=False,
        queryset=models.Tag.objects.all(),
    )

    class Meta:
        model = models.RuleTopic
        fields = (
            'name', 'slug', 'description', 'tag', 'featured', 'enabled',
        )


class ReportSerializer(serializers.ModelSerializer):
    rule = RuleSerializer(many=False, read_only=True)
    details = serializers.JSONField()
    resolution = ResolutionSerializer(many=False, read_only=True)
    impacted_date = serializers.DateTimeField(read_only=True)

    class Meta:
        model = models.CurrentReport
        fields = (
            'rule', 'details', 'resolution', 'impacted_date',
        )


class ReportForRuleSerializer(serializers.ModelSerializer):
    delta = serializers.IntegerField()

    class Meta:
        model = models.CurrentReport
        fields = ('delta', 'details')


class RuleRatingSerializer(serializers.ModelSerializer):
    """
    Rule ratings list the rating (-1, 0 or +1) for one or more rules.  The
    rule is listed by its Insights Rule ID.
    """
    rule = serializers.SlugRelatedField(
        many=False, slug_field='rule_id',
        queryset=models.Rule.objects.filter(active=True),
    )

    class Meta:
        model = models.RuleRating
        fields = ('rule', 'rating')


class AllRuleRatingsSerializer(serializers.ModelSerializer):
    """
    This is only available to internal users and lists ratings from all users.
    """
    rule = serializers.SlugRelatedField(
        many=False, slug_field='rule_id',
        queryset=models.Rule.objects.filter(active=True),
    )

    class Meta:
        model = models.RuleRating
        fields = (
            'rule', 'rating', 'created_at', 'updated_at', 'rated_by', 'account', 'org_id'
        )


class RuleRatingStatsSerializer(serializers.Serializer):
    """
    Output of statistics view of rule ratings - rule ID and totals of ratings.
    """
    rule = serializers.CharField(source='rule__rule_id')
    total_ratings = serializers.IntegerField()
    total_positive = serializers.IntegerField()
    total_negative = serializers.IntegerField()


class RuleUsageStatsSerializer(serializers.Serializer):
    """
    Rule usage statistics for rule developers.
    """
    rule_id = serializers.CharField(max_length=240, validators=[existing_rule_id_validator])
    description = serializers.CharField()
    active = serializers.BooleanField()
    systems_hit = serializers.IntegerField()
    accounts_hit = serializers.IntegerField()
    accounts_acked = serializers.IntegerField()


class SettingDDFSerializer(serializers.Serializer):
    """
    Outputs the description of the settings in a Data-Driven Forms format.
    """
    name = serializers.CharField()
    label = serializers.CharField(required=False)
    title = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    helperText = serializers.CharField(required=False)
    component = serializers.CharField()
    isRequired = serializers.BooleanField()
    initialValue = serializers.BooleanField()
    isDisabled = serializers.BooleanField()


class SettingsDDFSerializer(serializers.Serializer):
    """
    Combining the DDF fields into one 'fields' object.
    """
    fields = SettingDDFSerializer(many=True)


class SettingsInputSerializer(serializers.Serializer):
    """
    Takes the settings input for parsing.  We have no settings currently.
    """


class StatsSerializer(serializers.Serializer):
    """
    Advisor rule or report frequency statisics.
    """
    total = serializers.IntegerField()
    total_risk = serializers.DictField(child=serializers.IntegerField())
    category = serializers.DictField(child=serializers.IntegerField())


class OverviewStatsSerializer(serializers.Serializer):
    """
    For the page overview, giving:

    - number of pathways
    - number of incident recommendations
    - number of critical recommendations
    - number of important recommendations
    """
    pathways = serializers.IntegerField()
    incidents = serializers.IntegerField()
    critical = serializers.IntegerField()
    important = serializers.IntegerField()


class StaleSystemStatsSerializer(serializers.Serializer):
    """
    Display how many hosts are outside their stale warning period, and how
    many hosts are being hidden due to staleness.
    """
    stale_count = serializers.IntegerField(
        help_text='The number of hosts that are stale and being warned about')
    warn_count = serializers.IntegerField(
        help_text='The number of hosts that are stale and being hidden from reports')


class StatusReadySerializer(serializers.Serializer):
    """
    Basic information about whether we are ready to serve information.
    """
    django = serializers.BooleanField()
    database = serializers.BooleanField()
    rbac = serializers.BooleanField(help_text='RBAC (Role-Based Access Control)')
    environment = serializers.BooleanField()
    advisor = serializers.BooleanField()
    errors = serializers.ListField(child=serializers.CharField())


class SystemTypeSerializer(serializers.ModelSerializer):
    """
    RHN-based system types classified by role and product code.
    """
    class Meta:
        model = models.SystemType
        fields = ('id', 'role', 'product_code')


class SystemsForRuleSerializer(serializers.Serializer):
    """
    The list of Inventory Host IDs that are (currently) affected by a given
    rule.
    """
    host_ids = serializers.ListField(child=serializers.UUIDField())


class SystemSerializer(serializers.ModelSerializer):
    # Fields now based on InventoryHost
    system_uuid = serializers.UUIDField(source='pk')
    hits = serializers.IntegerField(read_only=True)
    last_seen = serializers.DateTimeField(source='updated', read_only=True)
    stale_at = serializers.DateTimeField(source='stale_timestamp', read_only=True)
    rhel_version = serializers.CharField()
    critical_hits = serializers.IntegerField(read_only=True)
    important_hits = serializers.IntegerField(read_only=True)
    moderate_hits = serializers.IntegerField(read_only=True)
    low_hits = serializers.IntegerField(read_only=True)
    incident_hits = serializers.IntegerField(read_only=True)
    all_pathway_hits = serializers.IntegerField(read_only=True)
    pathway_filter_hits = serializers.IntegerField(read_only=True)
    group_name = serializers.CharField(allow_null=True, read_only=True)

    class Meta:
        model = models.InventoryHost
        fields = (
            'system_uuid', 'display_name', 'last_seen', 'stale_at', 'hits',
            'critical_hits', 'important_hits', 'moderate_hits', 'low_hits',
            'incident_hits', 'all_pathway_hits', 'pathway_filter_hits',
            'rhel_version', 'group_name'
        )


class SystemsDetailSerializer(SystemSerializer):
    impacted_date = serializers.DateTimeField(read_only=True)

    class Meta(SystemSerializer.Meta):
        fields = (
            'system_uuid', 'display_name', 'last_seen', 'stale_at', 'hits',
            'critical_hits', 'important_hits', 'moderate_hits', 'low_hits',
            'incident_hits', 'all_pathway_hits', 'pathway_filter_hits',
            'rhel_version', 'impacted_date'
        )


class UploadSerializer(serializers.ModelSerializer):
    """
    The list of reports for this upload (which is based on the system).

    We don't show the full list of reports, only the reports of active,
    non-acked rules.
    """
    system_uuid = serializers.UUIDField(source='host_id')
    active_reports = ReportSerializer(many=True, read_only=True)

    class Meta:
        model = models.Upload
        fields = (
            'id', 'system_uuid', 'account', 'org_id', 'system_type', 'checked_on',
            'active_reports',
        )


# This only ever gives the single value output, there's never a list.
@extend_schema_serializer(
    many=False
)
class UsageSerializer(serializers.Serializer):
    """
    An approximation of the number of unique hits per day.
    """
    unique_hits = serializers.IntegerField(source='unique-hits')


class WeeklyReportSubscriptionSerializer(serializers.Serializer):
    is_subscribed = serializers.BooleanField()


class TagListSerializer(serializers.Serializer):
    """Tags from all hosts"""
    tags = serializers.ListSerializer(child=serializers.CharField())


class AckCountSerializer(serializers.Serializer):
    """A rule_id and the number of acks on it"""
    rule_id = serializers.CharField()
    ack_count = serializers.IntegerField()


class SubscriptionExcludedAccountSerializer(serializers.Serializer):
    org_id = serializers.CharField()
    account = serializers.CharField(required=False)


class AutoSubscribeInputSerializer(serializers.Serializer):
    """
    Serializer specifically for handling
    CREATE and UPDATE views for AutoSubscribe
    """
    org_id = serializers.CharField()
    is_auto_subscribed = serializers.BooleanField()


class AutoSubscribeSerializer(NonNullModelSerializer):
    """
    Serializer specifically for listing
    all Pathways currently in the system
    """
    org_id = serializers.CharField()
    is_auto_subscribed = serializers.BooleanField()

    class Meta:
        model = models.WeeklyReportSubscription
        fields = ('org_id', 'is_auto_subscribed', )
