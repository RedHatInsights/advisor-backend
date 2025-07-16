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

from django.core.exceptions import FieldError, ValidationError
from django.db import models
from django.db.models import (
    F, Q, Subquery, OuterRef, Exists, Count, FilteredRelation,
    Case, When, Value
)
from django.db.models.functions import Cast
from django.db.models.lookups import IsNull
from django.utils import timezone
from django_prometheus.models import ExportModelOperationsMixin
from django.contrib.postgres.fields import ArrayField
from django.conf import settings

from api import kessel
from api.kessel import HostId, OrgId, WorkspaceId
from api.permissions import (
    request_to_username, request_to_org, host_group_attr
)
from api.filters import (
    filter_multi_param, filter_on_param, value_of_param,
    category_query_param, host_group_name_query_param, pathway_query_param,
    filter_on_branch_id, filter_on_display_name,
    filter_on_hits, filter_on_host_tags, filter_on_incident, filter_on_rhel_version,
    filter_on_update_method, filter_on_has_disabled_recommendation,
)

import logging
logger = logging.getLogger(settings.APP_NAME)


##############################################################################
# Utility functions
#


def sync_kessel_with_model():
    # TODO: put under default & root workspace
    for host in InventoryHost.objects.all():
        if host.groups is None or len(host.groups) == 0:
            ws_id = WorkspaceId(f'{host.org_id}_ungrouped')
            kessel.client.put_host_in_workspace(HostId(str(host.id)), ws_id)
            kessel.client.put_workspace(ws_id, OrgId(host.org_id))
        else:
            for group in host.groups:
                ws_id = WorkspaceId(group['id'])
                kessel.client.put_host_in_workspace(HostId(str(host.id)), ws_id)
                kessel.client.put_workspace(ws_id, OrgId(host.org_id))


def account_minimum_length(value):
    """
    Account numbers must be all digits and must be at least six digits long -
    leading zeros are not included
    """
    if not value.isdigit():
        raise ValidationError(
            '%(value) must be completely made of digits',
            params={'value': value}
        )
    if not int(value) > 100000:
        raise ValidationError(
            '%(value) is shorter than the minimum account number length',
            params={'value': value}
        )


def org_id_minimum_length(value):
    """
    Org ID numbers must be all digits and must be at least six digits long -
    leading zeros are not included
    """
    if not value.isdigit():
        raise ValidationError(
            '%(value) must be completely made of digits',
            params={'value': value}
        )
    if not int(value) > 100000:
        raise ValidationError(
            '%(value) is shorter than the minimum org id number length',
            params={'value': value}
        )


def calculate_rec_level(percentage_of_systems, has_incidents, max_risk):
    """
    Summary:
    --------
    Pathways recommendation levels are currently defined by three buckets.
    These buckets are defined based on the number of impacted systems
    within an account out of the total number of systems within that account,
    then a combination of whether the pathway contains incidents,
    and the max aggregate risk for that pathway.

    The buckets are as follows:
    - Greater than 25% of systems in an account are impacted
    - Between 10% and 25% of systems in an account are impacted
    - Less than 10% of systems in an account are impacted

    Method:
    -------
    We use a basic scoring criteria based on each of the three factors.

    The numbers here are somewhat arbitrary, and in deference to Richard
    Brantley[1] I won't pretend to understand exactly where they came from.
    My best interpretation of them would be that a pathway having incidents
    scores two, the percentage of systems affected scores four, and the
    maximum risk scores twelve, and the top score is 100% so everything is
    scaled downward from there.

    The matrix of values for this is:

                  .   risk=4   .   risk=3   .   risk=2   .   risk=1   .
     incident? -> | True False | True False | True False | True False |
    --------------+------------+------------+------------+------------+
    More than 25% | 100     98 |  88     86 |  76     74 |  64     62 |
    10% <-> 25%   | 96      94 |  84     82 |  72     70 |  60     58 |
    Less than 10% | 92      90 |  80     78 |  68     66 |  56     54 |
    --------------+------------+------------+------------+------------+

    [1] Richard implemented this as a Pandas DataFrame lookup; this made the
    algorithm slightly easier to follow but still didn't really describe how
    the individual weights of each factor were arrived at.
    """
    if percentage_of_systems > 0.25:
        base = 62
    elif percentage_of_systems > 0.1:
        base = 58
    else:
        base = 54
    base += (2 if has_incidents else 0)
    base += 12 * (min(max(max_risk, 1), 4) - 1)
    return base


def get_host_group_filter(request, relation=None):
    """
    If the request has any host groups attached to it during the authentication
    process, then create a filter searching for a host with an ID being one
    of those listed in the RBAC host group list.  This generates SQL of the
    form:

    SELECT <fields> FROM "inventory"."hosts"
    WHERE "inventory"."hosts"."groups" @> [{"id": <uuid>}]

    We also collect group names via the host_group_name_query_param
    parameter.  Note that this does not allow users to specify null in order
    to see 'hosts not in a group'.

    These two are ANDed together, so a user cannot request to see a group
    by name that they do not have permissions to see by RBAC.
    """
    # If we have a list of groups, combine them in an OR query clause
    host_groups = getattr(request, host_group_attr, [])
    host_groups_param = value_of_param(host_group_name_query_param, request)
    if not (host_groups or host_groups_param):
        return Q()
    group_clause = 'groups'
    if relation:
        group_clause = relation + '__' + group_clause
    group_contains_clause = group_clause + '__contains'
    # Add group names if set
    host_group_name_filter = Q()
    if host_groups_param:
        for group_name in host_groups_param:
            host_group_name_filter |= Q(**{group_contains_clause: [{'name': group_name}]})
    # Add RBAC group IDs
    host_group_rbac_filter = Q()
    assert isinstance(host_groups, list)
    for group in host_groups:
        if group is None:
            group_value = []
            clause_used = group_clause
        else:
            group_value = [{'id': group}]
            clause_used = group_contains_clause
        host_group_rbac_filter |= Q(**{clause_used: group_value})
    # Users can only see groups in both filters.
    return Q(host_group_rbac_filter & host_group_name_filter)


def get_systems_queryset(request):
    """
    A common queryset for both the systems list view here and the exported
    systems list.
    """
    # We don't need to filter out stale systems etc because that's
    # done at the host model level.
    reports_q = get_reports_subquery(
        request, exclude_ineligible_hosts=False, host=OuterRef('id'),
    )
    report_counts = convert_to_count_query(reports_q)

    # pathway subqueries
    pathway_slug = value_of_param(pathway_query_param, request)
    all_pathway_hits = convert_to_count_query(reports_q.filter(rule__pathway__isnull=False))
    pathway_filter_hits = convert_to_count_query(reports_q.filter(rule__pathway__slug=pathway_slug))

    def hits_risk_count(value):
        return Subquery(convert_to_count_query(reports_q.filter(rule__total_risk=value)))

    systems = InventoryHost.objects.for_account(request).annotate(
        hits=Subquery(report_counts),
        last_seen=F('updated'),  # for sorting
        critical_hits=hits_risk_count(4),
        important_hits=hits_risk_count(3),
        moderate_hits=hits_risk_count(2),
        low_hits=hits_risk_count(1),
        incident_hits=Subquery(convert_to_count_query(reports_q.filter(rule__tags__name='incident'))),
        all_pathway_hits=Subquery(all_pathway_hits),
        pathway_filter_hits=Subquery(pathway_filter_hits)
    )
    # We used to set the query.group_by here but that seemed to change the
    # count() values for some reason.

    # if we are filtering by pathway slug this will be greater than zero
    if pathway_slug:
        systems = systems.filter(pathway_filter_hits__isnull=False, pathway_filter_hits__gt=0)

    return systems.filter(
        filter_on_display_name(request),
        filter_on_hits(request),
        filter_on_incident(request),
        filter_on_rhel_version(request),
        filter_on_has_disabled_recommendation(request)
    )


class SubqueryArray(models.Subquery):
    """
    A subquery that allows us to annotate in a list, that we can then query
    using Django's Postgres recognition of array contains operators.

    From schinkel in #django on irc.freenode.org, via:
    https://schinckel.net/2019/07/30/subquery-and-subclasses/
    """
    # Currently not used, due to raw SQL below, but saved here in case we need
    # it in future.
    template = 'ARRAY(%(subquery)s)'

    @property
    def output_field(self):
        output_fields = [x.output_field for x in self.get_source_expressions()]

        if len(output_fields) > 1:
            raise FieldError('More than one column detected')

        return ArrayField(base_field=output_fields[0])


class Relationship(models.ForeignObject):
    """
    Create a django link between models on a field where a foreign key isn't used.
    This class allows that link to be realised through a proper relationship,
    allowing prefetches and select_related.

    Thanks to https://devblog.kogan.com/blog/custom-relationships-in-django
    and https://schinckel.net/2021/07/14/django-implied-relationship/ for
    this code.
    """

    def __init__(self, model, from_fields, to_fields, **kwargs):
        super().__init__(
            model, on_delete=models.DO_NOTHING, from_fields=from_fields,
            to_fields=to_fields, null=True, blank=True, **kwargs,
        )

    def contribute_to_class(self, cls, name, private_only=False, **kwargs):
        # override the default to always make it private
        # this ensures that no additional columns are created
        super().contribute_to_class(cls, name, private_only=True, **kwargs)


def stale_systems_q(org_id, field='host_id'):
    """
    Returns a subquery filter that removes all stale systems.
    The account parameter while not necessary for correctness, does increase performance.
    """
    return Q(**{field + '__in': models.Subquery(
        InventoryHost.objects.annotate(
            puptoo_stale_timestamp=Cast(Cast(
                'per_reporter_staleness__puptoo__stale_warning_timestamp',
                output_field=models.CharField()
            ), output_field=models.DateTimeField())
        ).filter(
            org_id=org_id,
            puptoo_stale_timestamp__gt=timezone.now(),
        ).values('id')
    )})


def cert_auth_q(request, relation=''):
    """
    Returns a Q object that filters InventoryHost on the system's certificate
    if Certificate Authentication is used, or an empty Q object otherwise.
    """
    cert_auth_owner = getattr(request, 'auth_system', None)
    if cert_auth_owner is None:
        return models.Q()
    if relation:
        relation += '__'

    # Good news: if this is a Satellite, then all systems owned by the
    # Satellite will have this owner_id; if this is a system then it gets
    # its own ID as the owner_id - i.e. it's 'self-owned'.  So this always
    # works :-)
    relation_field = relation + 'system_profile__owner_id'

    return models.Q(**{relation_field: cert_auth_owner})


def convert_to_count_query(query, field='host', distinct=False):
    system_counts = query.annotate(
        count=Count(field, distinct=distinct)
    ).values('count')
    system_counts.query.group_by = []

    return system_counts


def get_reports_subquery(
    request, exclude_ineligible_rules=True, exclude_ineligible_hosts=True,
    filter_branch_id=True,
    use_joins=False, **outer_table_join
):
    """
    This produces a highly optimised filtered query on the CurrentReport
    model for the current request with all the filtering that the Advisor API
    requires:

    * In the current users' account
    * host tags [1]
    * system profile filtering [1]
    * satellite-controlled hosts [1]
    * stale systems [1]
    * active rule [2]
    * rule not disabled with an account-wide ack [2]
    * rule not disabled on this host with a host-specific ack

    [1] These filters can be disabled by setting the `exclude_ineligible_hosts`
    option to False.  All hosts would be included.
    [2] These filters can be disabled by setting the `exclude_ineligible_rules`
    option to False.  All rules would be included.

    There is no option to disable host-specific rule acknowledgements.

    Other relational parameters can be supplied in the `outer_table_join`
    keyword arguments - i.e. this can be used as similar to a Django model
    manager's `filter` keyword.

    The use_joins option reformats the query to use joins rather than id__in
    sub-queries. This is strictly performance related and should not affect
    the correctness of the final result.  The version of the query tends to
    be faster when current report is the top level query (reports, stats,
    export). The sub-query version tends to be faster when systems or rules
    are the top level query.
    """
    org_id = request_to_org(request)
    if not org_id:
        return CurrentReport.objects.none()
    host_tags_q = filter_on_host_tags(request)

    system_profile_filter = filter_multi_param(
        request, 'system_profile', field_prefix='inventory'
    )

    category_filter = Q()
    category_ids = request.query_params.getlist('category')
    category_ids = category_ids[0].split(',') if category_ids else None
    if category_ids and all(catid.isdigit() for catid in category_ids):  # Hack for sat compat
        category_filter = filter_on_param('rule__category_id', category_query_param, request)

    branch_id_filter = Q()
    if filter_branch_id:
        branch_id_filter = filter_on_branch_id(request, relation='host')

    ack_filter = Q()
    if exclude_ineligible_rules:
        if use_joins:
            ack_filter = Q(Exists(Ack.objects.filter(org_id=org_id, rule_id=OuterRef('rule_id'))))
        else:
            ack_filter = Q(
                rule_id__in=Rule.objects.order_by().filter(active=False).values('id').union(
                    Ack.objects.order_by().filter(org_id=org_id).values('rule_id')
                ))

    stale_systems_filter = Q(
        Exists(InventoryHost.objects.annotate(
            puptoo_stale_timestamp=Cast(Cast(
                'per_reporter_staleness__puptoo__stale_warning_timestamp',
                output_field=models.CharField()
            ), output_field=models.DateTimeField())
        ).filter(
            id=OuterRef('host'),
            org_id=org_id,
            puptoo_stale_timestamp__gt=timezone.now()
        ))
    ) if use_joins else Q(stale_systems_q(org_id), org_id=org_id)

    return CurrentReport.objects.filter(
        Q(
            host_tags_q, system_profile_filter,
            category_filter,
            cert_auth_q(request, relation='inventory'),
            branch_id_filter,
            filter_on_update_method(request, relation='inventory'),
            get_host_group_filter(request, relation='inventory'),
            stale_systems_filter,
        ) if exclude_ineligible_hosts else Q(),
        **outer_table_join
    ).filter(
        Q(rule__active=True) if use_joins and exclude_ineligible_rules else Q()
    ).exclude(
        ack_filter
    ).exclude(
        Exists(HostAck.objects.filter(org_id=org_id, rule_id=OuterRef('rule_id'), host_id=OuterRef('host')))
    )


##############################################################################
# Abstract models:
#


class TimestampedModel(models.Model):
    """
    Equivalent to Sequelize's 'timestamp' property, but with the following
    changes:

    * the field names are underscored ('created_at') rather than camelCase.
    * the field names are always named 'created_at' and 'updated_at'.
    * both fields are always present and cannot be removed.
    """
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class ParanoidTimestampedModel(TimestampedModel):
    """
    Equivalent to Sequelize's 'timestamp' property with 'paranoid' turned on.

    This prevents the deletion of the object and instead sets the 'deleted_at'
    property to the current time.  If the 'deleted_at' property is not null,
    then do not allow any edits to this model.
    """
    deleted_at = models.DateTimeField(null=True, editable=False)

    def save(self, *args, **kwargs):
        if self.deleted_at:
            # Should we raise an error here?
            return None
        else:
            return super(ParanoidTimestampedModel, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if not self.deleted_at:
            self.deleted_at = timezone.now()
            if hasattr(self, 'active'):
                self.active = False
            # Don't use our own overridden save method now.
            super(ParanoidTimestampedModel, self).save(*args, **kwargs)
        else:
            # Should we raise an error here?
            return None

    class Meta:
        abstract = True


##############################################################################
# Concrete models:
#


class Ack(ExportModelOperationsMixin('ack'), TimestampedModel):
    """
    A customer can 'acknowledge' a rule to turn it off for all systems in
    their account.  This is then deleted later if the customer wants to now
    see rule reports for that rule.  This does not stop reports being
    generated for this rule on the customers' systems, it only stops them
    being reported.
    """
    rule = models.ForeignKey('Rule', on_delete=models.CASCADE)
    account = models.CharField(db_index=True, max_length=10, blank=True, null=True)
    org_id = models.CharField(db_index=True, max_length=50)
    justification = models.CharField(max_length=255, blank=True, default="",
                                     help_text="The reason the rule was acked")
    created_by = models.CharField(max_length=255, blank=True, default="",
                                  help_text="The user who created the ack")

    def __str__(self):
        return f'ack for {self.rule} for org {self.org_id} by {self.created_by}'

    class Meta:
        ordering = ('org_id', 'rule__rule_id', )
        unique_together = (('rule', 'org_id', ),)


class CurrentReport(ExportModelOperationsMixin('currentreport'), models.Model):
    """
    A current report of a rule impacting a system.  This should always be the
    most recent report of a rule, so the upload it's connected to should have
    its 'current' flag True.

    Because the system_uuid and account are often linked to in displaying
    reports, we de-normalise the Upload model to store them here.
    """
    id = models.BigAutoField(primary_key=True)
    account = models.CharField(max_length=10, blank=True, null=True)
    org_id = models.CharField(max_length=50)
    rule = models.ForeignKey('Rule', on_delete=models.CASCADE, db_index=False)
    host = models.ForeignKey('Host', on_delete=models.CASCADE, db_index=False, db_column='system_uuid')
    inventory = Relationship(
        'InventoryHost', from_fields=['host_id'], to_fields=['id'],
        related_name='currentreports'
    )
    upload = models.ForeignKey('Upload', on_delete=models.CASCADE, db_index=True)
    details = models.JSONField()
    impacted_date = models.DateTimeField(default=timezone.now, editable=False, null=True)

    @property
    def resolution(self):
        # Have to look up the resolution ourselves, there's no implicit link
        # Also fall back to rhel/host system type 105, because there will
        # always be a resolution for rhel/host.
        try:
            return Resolution.objects.get(
                rule=self.rule, system_type=self.upload.system_type_id
            )
        except Resolution.DoesNotExist:
            return Resolution.objects.get(
                rule=self.rule, system_type=105
            )

    def __str__(self):
        return f"current report of {self.rule.rule_id} in upload {self.upload_id}"

    class Meta:
        unique_together = (('org_id', 'rule', 'host'),)
        indexes = [
            models.Index(
                fields=['host', 'rule_id'],
                name='curreport_system_uuid_rule_id',
            ),
            models.Index(
                fields=['upload_id'],
                name='currentreport_upload_id'
            )
        ]


class InventoryHostManager(models.Manager):
    def for_account(
        self, request, filter_stale=True,
        filter_branch_id=True, require_host=True
    ):
        """
        Provide a view of the Inventory for a particular account.  This
        filters:

        * System's org_id number
        * Staleness
        * System by owner CN when certificate authentication is used
        * Host tags when supplied
        * System profile filter when supplied
        * Branch ID parameter when supplied
        * Host groups when supplied
        """
        host_tags_q = filter_on_host_tags(request, field_name='id')
        system_profile_filter = filter_multi_param(request, 'system_profile')
        staleness_filter = Q()
        if filter_stale:  # field defined in annotate below
            staleness_filter = Q(puptoo_stale_timestamp__gt=timezone.now())
        branch_id_filter = Q()
        if filter_branch_id:
            branch_id_filter = filter_on_branch_id(request, relation='host')
        require_host_filter = Q()
        if require_host:
            require_host_filter = Q(host__isnull=False)
        host_group_filter = get_host_group_filter(request)

        return InventoryHost.objects.annotate(
            puptoo_stale_timestamp=Cast(Cast(
                'per_reporter_staleness__puptoo__stale_warning_timestamp',
                output_field=models.CharField()
            ), output_field=models.DateTimeField())
        ).filter(
            host_tags_q, system_profile_filter,
            cert_auth_q(request), branch_id_filter, staleness_filter,
            filter_on_update_method(request),
            require_host_filter, host_group_filter,
            org_id=request.auth['org_id']
        )


class InventoryHost(models.Model):
    """
    A view of the Inventory table embedded in the Advisor database, which
    allows us to get direct information from Inventory without having to
    query it.

    To clarify the use of the stale dates:
      * the `stale_timestamp` date is the date after which the host is considered
        **stale**.  After this time a warning will be shown that this host
        is not updating
      * the `stale_warning_timestamp` date is the date *before* which warnings will be
        shown, and *after* which a host will be **hidden**.  After this time
        the host will be excluded from all listings.
      * at some point after that we expect the Inventory to issue a DELETE
        message for this host and all its reports to be removed.  The host
        record is left but is excluded because it does not have any current
        uploads.

    Therefore, the `stale_at` date is always **before** the `stale_warn_at`
    date, and passes first.
    """
    id = models.UUIDField(primary_key=True)
    account = models.CharField(max_length=10, blank=True, null=True)
    org_id = models.CharField(max_length=50)
    display_name = models.CharField(max_length=200)
    tags = models.JSONField()
    groups = models.JSONField()
    updated = models.DateTimeField()
    created = models.DateTimeField()
    stale_timestamp = models.DateTimeField()
    stale_warning_timestamp = models.DateTimeField()
    culled_timestamp = models.DateTimeField()
    insights_id = models.UUIDField()  # the ID that the Insights client assigns itself.
    system_profile = models.JSONField()
    per_reporter_staleness = models.JSONField(null=True)

    objects = InventoryHostManager()

    @staticmethod
    def get_rhel_version(profile):
        "Derive the OS version from the system profile"
        if 'operating_system' not in profile:
            return "Unknown system version"
        os_details = profile['operating_system']
        if 'major' in os_details and 'minor' in os_details:
            return f"{os_details['major']}.{os_details['minor']}"
        elif 'major' in os_details:
            return str(os_details['major'])
        elif 'name' in os_details:
            return f"Unknown {os_details['name']} version"
        else:
            return "Unknown OS version"

    @property
    def rhel_version(self):
        "Helper to display RHEL version from Inventory"
        return self.get_rhel_version(self.system_profile)

    @property
    def group_name(self):
        return self.groups[0].get('name', None) if self.groups and len(self.groups) > 0 else None

    @property
    def acks(self):
        """
        List the 'global' and 'local' acks, for Satellite compatibility:
        """
        # This is not used at all by the client so we should just skimp here.
        return []

    def __str__(self):
        return f"{self.display_name} ({self.id})"

    class Meta:
        managed = False
        db_table = '"inventory"."hosts"'


class Host(ExportModelOperationsMixin('host'), TimestampedModel):
    """
    The information about a host that Inventory doesn't store...
    """
    inventory = models.OneToOneField(
        InventoryHost, on_delete=models.DO_NOTHING, primary_key=True,
        db_constraint=False, db_column='system_uuid',
    )
    account = models.CharField(max_length=10, blank=True, null=True)
    org_id = models.CharField(max_length=50)
    satellite_id = models.UUIDField(
        db_index=True, null=True,
        help_text='ID according to the managing Satellite server'
    )
    branch_id = models.UUIDField(
        db_index=True, null=True,
        help_text='ID of Satellite server that manages this host'
    )

    @property
    def rhel_version(self):
        return self.inventory.rhel_version

    def __str__(self):
        return str(self.inventory_id)


class HostAck(ExportModelOperationsMixin('hostack'), TimestampedModel):
    """
    A customer can 'acknowledge' a rule to turn it off for ONE system in
    their account.  This is then deleted later if the customer wants to now
    see rule reports for that rule.  This does not stop reports being
    generated for this rule on the customers' systems, it only stops them
    being reported.  Each acknowledgement records a justification and the
    user that created it, to help other users understand the reason for the
    acknowledgement.
    """
    rule = models.ForeignKey('Rule', on_delete=models.CASCADE)
    host = models.ForeignKey('Host', on_delete=models.CASCADE, db_column='system_uuid')
    account = models.CharField(db_index=True, max_length=10, blank=True, null=True)
    org_id = models.CharField(db_index=True, max_length=50)
    justification = models.CharField(max_length=255, blank=True, default="")
    created_by = models.CharField(
        max_length=255, blank=True, default="",
        help_text="The username that created this acknowledgement"
    )

    def __str__(self):
        return u'ack for {r} for account {a} by org {o} for {s}'.format(
            r=self.rule, a=self.account, o=self.org_id, s=self.host_id
        )

    class Meta:
        ordering = ('org_id', 'host', 'rule__rule_id', )
        unique_together = (('rule', 'org_id', 'host'),)


class Playbook(ExportModelOperationsMixin('playbook'), models.Model):
    """
    A Resolution (rule + system_type) may have multiple playbooks.  The
    resolution text may list multiple methods to resolve the issue, eg a
    permanent fix, a choice of fixes, a temporary workaround, etc and each of
    these methods is represented by a single playbook.
    """
    resolution = models.ForeignKey('Resolution', on_delete=models.CASCADE)
    type = models.CharField(max_length=100, help_text="Eg fixit, workaround, kernel_update")
    play = models.TextField(null=True, help_text="Ansible playbook")
    description = models.CharField(max_length=255)
    path = models.CharField(max_length=255, help_text="Path to playbook file on disk")
    version = models.CharField(max_length=40, null=True, help_text="Git commit of last modification")

    def __str__(self):
        return u"playbook {t} for {r}".format(t=self.type, r=self.resolution)


class Resolution(ExportModelOperationsMixin('resolution'), models.Model):
    """
    Each rule can have one or more resolutions - e.g. direct fixes, work
    arounds or temporary solutions.
    """
    rule = models.ForeignKey('Rule', on_delete=models.CASCADE)
    system_type = models.ForeignKey('SystemType', on_delete=models.CASCADE)
    resolution = models.TextField()
    resolution_risk = models.ForeignKey('ResolutionRisk', on_delete=models.CASCADE)

    @property
    def resolution_risk_name(self):
        return self.resolution_risk.name

    @property
    def resolution_risk_value(self):
        return self.resolution_risk.risk

    @property
    def has_playbook(self):
        # Check if this resolution has any associated playbooks
        return self.playbook_set.exists()

    def __str__(self):
        return u'resolution for {r} on {st}' .format(r=self.rule, st=self.system_type)

    class Meta:
        ordering = ('rule__rule_id', 'system_type__role', 'system_type__product_code')
        unique_together = (('rule', 'system_type'), )


class ResolutionRisk(ExportModelOperationsMixin('resolution_risk'), models.Model):
    """
    Each resolution has a resolution risk, named and rated from 0 (nothing)
    to 4 (high risk).  Updated from the Insights Content repository / server.
    """
    name = models.CharField(max_length=80, unique=True, default="None")
    risk = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return '{n}({r})'.format(n=self.name, r=self.risk)

    class Meta:
        ordering = ('name',)


class PathwayManager(models.Manager):
    def for_account(self, request, impacting=True):
        """
        Show only pathways for this account. Pathways only show up
        for accounts if there is a rule hit on a rule within a Pathway.
        Otherwise, no pathways show up.
        """
        # Because we only have a limited number of pathways, it's faster to
        # do all the counts in one pass here rather than trying to build the
        # gigantic set of subqueries, and then annotate the counts in.
        # Start by collecting the reports for this account
        report_query = get_reports_subquery(
            request, rule__pathway_id__isnull=False
        ).annotate(
            rule_is_incident=Exists(Tag.objects.filter(
                name='incident', rules__id=OuterRef('rule_id')
            )),
        ).values(
            'id', 'rule__pathway_id', 'rule__total_risk', 'rule_is_incident',
            'host_id',
        )

        # Allocate those reports into various fields per pathway, indexed by id
        pathway_agg_data = {}
        pathway_count_keys = [
            'impacted_systems', 'incidents', 'low_risk', 'medium_risk',
            'high_risk', 'critical_risk',
        ]
        total_risk_to_risk_name = [
            None, 'low_risk', 'medium_risk', 'high_risk', 'critical_risk'
        ]
        for cr in report_query:  # this always has a pathway_id
            pathway_id = cr['rule__pathway_id']
            host_id = cr['host_id']
            # Fill with default data
            if pathway_id not in pathway_agg_data:
                pathway_agg_data[pathway_id] = {
                    key: set()
                    for key in pathway_count_keys
                }
            # Add system to the impacted, incident and risk name sets
            pathway_agg_data[pathway_id]['impacted_systems'].add(host_id)
            if cr['rule_is_incident']:
                pathway_agg_data[pathway_id]['incidents'].add(host_id)
            pathway_agg_data[pathway_id][
                total_risk_to_risk_name[cr['rule__total_risk']]
            ].add(host_id)
        if not pathway_agg_data:
            # Need to at least annotate in sortable fields so that sorting
            # the empty query doesn't raise a FieldError and a 500 response.
            return self.get_queryset().none().annotate(
                impacted_systems_count=Value(0),
                recommendation_level=Value(0),
            )

        # get the total systems in an account
        # used for calculating the rec level
        # This doesn't change per pathway so only query it once.
        systems_in_account = get_systems_queryset(request).count()

        # Add fields from pathway and aggregate rule data to the reports
        for pathway in self.get_queryset().filter(
            id__in=pathway_agg_data.keys()
        ).annotate(
            reboot_required=Exists(
                Rule.objects.filter(pathway_id=OuterRef('id'), reboot_required=True)
            ),
            max_risk=models.Max('rule__total_risk')
        ).values('id', 'reboot_required', 'max_risk'):
            pathway_id = pathway['id']
            agg_data = pathway_agg_data[pathway_id]
            # Reduce sets to counts
            for key in pathway_count_keys:
                agg_data[key] = len(agg_data[key])

            # Fill in incident flag boolean
            agg_data['has_incident'] = (
                agg_data['incidents'] > 0)
            # Disable the reboot_required flag if we care about whether the
            # pathway impacts systems, and it doesn't.  (Odd logic but hey...)
            agg_data['reboot_required'] = (
                agg_data['impacted_systems'] > 0 and  # noqa: W504
                pathway['reboot_required'] and impacting
            )
            # We can also annotate in the recommendation level here
            if systems_in_account > 0:
                percentage_of_systems = agg_data['impacted_systems'] / systems_in_account
                rec_level = calculate_rec_level(
                    percentage_of_systems,
                    agg_data['has_incident'],
                    pathway['max_risk']
                )
                agg_data['recommendation_level'] = rec_level
            else:
                agg_data['recommendation_level'] = 0

        # This defaults to only showing Pathways that are impacting systems
        impacting_ids = Q(id__in=pathway_agg_data.keys()) if impacting else models.Q()

        def pathway_agg_case(field, output_field=models.PositiveIntegerField(), default=0):
            if len(pathway_agg_data) == 1:
                # popitem returns tuple key,val; val is the dict of fields
                return Value(pathway_agg_data.popitem()[1][field], output_field=output_field)
            field_vals = set(pathway[field] for pathway in pathway_agg_data.values())
            if len(field_vals) == 1:
                return Value(field_vals.pop(), output_field=output_field)
            return Case(
                *(
                    When(id=pathway_id, then=Value(pathway[field]))
                    for pathway_id, pathway in pathway_agg_data.items()
                    if pathway[field] != default  # Only mention differences
                ),
                default=Value(default),
                output_field=output_field
            )

        # Return all pathways that are published.  Because this is a
        # relatively small list, we then annotate the values we determined above
        return self.get_queryset().filter(
            impacting_ids, publish_date__lte=timezone.now()
        ).annotate(
            total_systems_in_account=Value(systems_in_account),
            impacted_systems_count=pathway_agg_case('impacted_systems'),
            has_playbook=Exists(Playbook.objects.filter(
                resolution__rule__pathway_id=OuterRef('id')
            )),
            reboot_required=pathway_agg_case('reboot_required', models.BooleanField(), False),
            incident_count=pathway_agg_case('incidents'),
            has_incident=pathway_agg_case('has_incident', models.BooleanField(), False),
            recommendation_level=pathway_agg_case('recommendation_level'),
            critical_risk_count=pathway_agg_case('critical_risk'),
            high_risk_count=pathway_agg_case('high_risk'),
            medium_risk_count=pathway_agg_case('medium_risk'),
            low_risk_count=pathway_agg_case('low_risk'),
        )


class Pathway(ExportModelOperationsMixin('pathway'), models.Model):
    """
    Pathways group resolutions by resolution risk, component and category
    """
    slug = models.SlugField(max_length=240, unique=True, null=False)
    name = models.CharField(max_length=240, unique=True, null=False)
    description = models.CharField(max_length=240)
    component = models.CharField(max_length=80, null=False)
    # We can't link directly to the resolution risk, partly because it leads
    # to a circular dependency where pathways depend on resolution risks
    # which depend on resolutions which depend on rules, and partly because
    # the rule content lists resolution risks by name and pathway data
    # couldn't refer to the ID of that related resolution risk model object.
    resolution_risk_name = models.CharField(max_length=80, default="None")
    resolution_risk = Relationship(ResolutionRisk,
        from_fields=['resolution_risk_name'], to_fields=['name'],
    )
    publish_date = models.DateTimeField(null=True)

    objects = PathwayManager()

    """
    These fields are specific to a Pathway.
    They do not take into account an account, its systems
    reports, rule hits, or incidents. These fields are
    purely metadata associated with a Pathway
    """
    @property
    def pathway_rules(self):
        return self.rule_set.filter(active=True).order_by('id')

    @property
    def pathway_rule_count(self):
        return self.pathway_rules.count()

    @property
    def pathway_categories(self):
        return RuleCategory.objects.filter(
            id__in=self.pathway_rules.values('category_id')).order_by('id')

    @property
    def pathway_category_count(self):
        return self.pathway_categories.count()

    """
    These fields are specific to a Pathway and the
    account in question. They all take into account
    an account, its systems, reports, rule hits, and
    incidents.
    """
    def get_reports(self, request):
        report_query = get_reports_subquery(
            request, rule_id__in=self.pathway_rules.values('id')
        )
        return report_query

    def rules(self, request):
        # Need to use this to make sure we account for acks/hostacks and
        # show impacted systems counts etc.
        return Rule.objects.for_account(request).filter(pathway=self).order_by('id')

    def rules_count(self, request):
        return self.rules(request).count()

    def categories(self, request):
        # If filtering on category, only return pathway categories that are in the filter
        category_ids = self.rules(request).filter(
            filter_on_param('category_id', category_query_param, request)
        ).order_by().values('category_id').distinct()
        return RuleCategory.objects.filter(id__in=category_ids).order_by('id')

    def categories_count(self, request):
        return self.categories(request).count()

    def impacted_systems(self, request):
        if self.impacted_systems_count:
            report_query = self.get_reports(request)
            system_query = get_systems_queryset(request)
            filtered_systems_queryset = system_query.filter(id__in=report_query.values('host__inventory'))
            return filtered_systems_queryset
        else:
            return InventoryHost.objects.none()

    def has_incident(self):
        return self.rule_set.filter(active=True, tags__name='incident').exists()

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name',)
        unique_together = (('component', 'resolution_risk_name'), )


class RuleManager(models.Manager):
    def for_account(self, request):
        """
        Gives a queryset with an annotation for the number of systems
        currently impacted by each rule, and whether this rule has its
        reports acked.  Only active rules are returned.  The account and
        other settings relating to what rules to show are derived from the
        request object.
        """
        # At the moment this 'account' name refers to the organisation; we
        # filter everything by matching org_id.  At some point we can do the
        # semantic name change to `for_org()`.
        username = request_to_username(request)

        report_query = get_reports_subquery(
            request, exclude_ineligible_rules=False, rule_id=OuterRef('id'),
        )
        report_count_query = convert_to_count_query(report_query)

        org_id = request.auth['org_id']
        # Because the only time we can get a rule list is in views that have
        # already authenticated, we must have an account here.

        system_profile_filter = filter_multi_param(
            request, 'system_profile', field_prefix='host__inventory'
        )
        playbooks_for_rule = Playbook.objects.filter(
            resolution__rule=models.OuterRef('id')
        ).order_by()
        hosts_acked_for_rule = HostAck.objects.filter(
            filter_on_host_tags(request, field_name='host_id'),
            system_profile_filter,
            stale_systems_q(org_id, field='host_id'),
            org_id=org_id, rule=models.OuterRef('id'),
        ).annotate(
            hosts_acked=models.Count('id')
        ).values('hosts_acked').order_by()
        hosts_acked_for_rule.query.group_by = []  # Otherwise it groups by host_id

        return self.get_queryset().filter(
            active=True
        ).annotate(
            acks=FilteredRelation('ack', condition=Q(ack__org_id=org_id)),
            reports_shown=IsNull(models.F('acks'), True),
            rule_status=Case(
                When(acks__isnull=True, then=Value('enabled')),
                When(
                    acks__isnull=False,
                    acks__created_by=settings.AUTOACK['CREATED_BY'],
                    then=Value('rhdisabled')
                ),
                default=Value('disabled'),
                output_field=models.CharField(),
            ),
            has_reports=Exists(report_query),
            playbook_count=models.Subquery(
                playbooks_for_rule.values('resolution__rule').annotate(
                    playbooks=models.Count('pk')
                ).values('playbooks'),
                output_field=models.PositiveSmallIntegerField()
            ),
            impacted_systems_count=models.Subquery(report_count_query),
            hosts_acked_count=models.Subquery(
                hosts_acked_for_rule,
                output_field=models.PositiveSmallIntegerField()
            ),
            rating=models.functions.Coalesce(
                RuleRating.objects.filter(
                    rule=models.OuterRef('id'), rated_by=username
                ).values('rating').order_by(),
                models.Value(0),
                output_field=models.IntegerField(),
            ),
        ).select_related(
            'category', 'impact', 'pathway', 'ruleset'
        ).prefetch_related(
            'resolution_set', 'resolution_set__resolution_risk',
            'resolution_set__playbook_set'
        )


class Rule(ExportModelOperationsMixin('rule'), ParanoidTimestampedModel):
    """
    An individual rule, based on the output of 'make_response' with a unique
    error key.  This is based on ParanoidTimestampedModel so it can be updated
    but is not deleted, but rather deactivated.

    Each rule set would provide its own specific information about the rule;
    this is the basics that every rule set will need.
    """
    ruleset = models.ForeignKey('RuleSet', on_delete=models.CASCADE)
    rule_id = models.CharField(max_length=240, unique=True, help_text="Rule ID from Insights")
    description = models.CharField(max_length=240)
    # Classifications section
    total_risk = models.PositiveSmallIntegerField(default=1)
    active = models.BooleanField(default=False)
    reboot_required = models.BooleanField(default=False)
    publish_date = models.DateTimeField(null=True)
    category = models.ForeignKey('RuleCategory', on_delete=models.CASCADE)
    impact = models.ForeignKey('RuleImpact', null=True, on_delete=models.SET_NULL)
    likelihood = models.PositiveSmallIntegerField(default=0)
    pathway = models.ForeignKey('Pathway', null=True, on_delete=models.SET_NULL)
    # Display section
    node_id = models.CharField(blank=True, max_length=10, help_text="KCS solution number")
    summary = models.TextField()
    generic = models.TextField()
    reason = models.TextField()
    more_info = models.TextField(blank=True)
    tags = models.ManyToManyField('Tag', related_name='rules')

    objects = RuleManager()

    @property
    def has_playbook(self):
        # Can't use the playbook_count since that's only an annotation on
        # the rule objects queryset.
        return self.resolution_set.filter(playbook__isnull=False).exists()

    def playbooks(self):
        "List playbooks for all the resolutions of this rule"
        # Used only for Satellite compatibility views.
        return (
            Playbook.objects
            .filter(resolution__rule=self)
            .order_by('resolution__system_type_id', 'type')
            .annotate(
                rule_id=models.F('resolution__rule__rule_id'),
                system_type_id=models.F('resolution__system_type_id'),
                needs_reboot=models.F('resolution__rule__reboot_required'),
                resolution_risk=models.F('resolution__resolution_risk__risk')
            ).select_related(
                'resolution', 'resolution__rule', 'resolution__resolution_risk'
            )
        )

    def reports_for_account(self, request):
        """
        List all current reports of the given account based on org_id number affected by this
        rule in the current account.

        Reports are filtered by host tags, host staleness, satellite status,
        rule and host acks

        If this rule is inactive, or deleted, or it has been acked by this
        account, a null queryset (using none()) is returned.

        param: request: the request object (for the x-rh-identity header)

        returns: a queryset of current reports for this rule.
        """
        org_id = request.auth['org_id']
        # The only views that can request this have already authenticated,
        # so they should have a valid account org_id number.
        if (not self.active) or (self.deleted_at) or (self.ack_set.filter(org_id=org_id).exists()):
            return CurrentReport.objects.none()

        return get_reports_subquery(
            request, rule__id=self.id
        )

    def __str__(self):
        return u'{r} in {rs}'.format(r=self.rule_id, rs=self.ruleset)

    class Meta:
        ordering = ('rule_id',)


class RuleCategory(ExportModelOperationsMixin('rule_category'), models.Model):
    """
    The category for a rule.  In Advisor this is one of 'Security',
    'Availability', 'Stability' or 'Performance'.  We don't use a Choices
    field because we want other projects to use this and choose their own
    categories.
    """
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name',)


class RuleImpact(ExportModelOperationsMixin('rule_impact'), models.Model):
    """
    The impact of finding a rule occurring on a system, named and rated from
    0 (nothing) to 4 (high risk).  Updated from the Insights Content
    repository / server.
    """
    name = models.CharField(max_length=80, unique=True, default="None")
    impact = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return '{n}({r})'.format(n=self.name, r=self.impact)

    class Meta:
        ordering = ('name',)


RATING_CHOICES = ((-1, 'Dislike'), (0, 'Neutral'), (1, 'Like'))


class RuleRating(ExportModelOperationsMixin('rule_rating'), TimestampedModel):
    """
    Users can rate rules, giving them a 'like' or 'dislike'.
    """
    rule = models.ForeignKey('Rule', on_delete=models.CASCADE, help_text="Insights Rule ID")
    rated_by = models.CharField(
        max_length=255, blank=True, default="",
        help_text="The username that rated this rule"
    )
    account = models.CharField(max_length=10, blank=True, null=True)
    org_id = models.CharField(max_length=50)
    rating = models.SmallIntegerField(choices=RATING_CHOICES)

    def __str__(self):
        return f"{self.rated_by} gave {self.rating} to {self.rule.rule_id}"

    class Meta:
        ordering = ('rule__rule_id', 'rated_by',)
        unique_together = [('rule', 'rated_by',)]


class RuleSet(ExportModelOperationsMixin('rule_set'), TimestampedModel):
    """
    A set of rules, stored in a repository.

    This might also store other information, like the end-points of APIs we
    reach into for content and playbook information, or MQTT channel names.
    """
    rule_source = models.URLField(unique=True)
    description = models.CharField(max_length=120)
    module_starts_with = models.CharField(max_length=80, default="invalid")

    def __str__(self):
        return self.description

    class Meta:
        ordering = ('rule_source',)


class RuleTopic(ExportModelOperationsMixin('rule_topic'), TimestampedModel):
    """
    Topics group rules together.

    They can be based on tags in the rule, or just by selecting rules
    directly.  Insights administrators choose the rules for a topic and it is
    shown to all customers.  New rules with a tag that matches a topic's tags
    will be added to that topic; likewise rules that update their list of
    tags.  Rules can be in more than one topic, and topics usually have more
    than one rule.
    """
    name = models.CharField(max_length=80, unique=True)
    slug = models.SlugField(max_length=20, unique=True, help_text="Rule topic slug")
    description = models.TextField()
    tag = models.ForeignKey(
        'Tag', related_name='topic', null=True, on_delete=models.SET_NULL
    )
    featured = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)

    def reports_for_account(self, request):
        """
        Returns a queryset of current reports for all the rules in this topic
        for this account.
        """
        return get_reports_subquery(request, rule__tags__topic=self)

    def tagged_rules(self):
        """
        Return a queryset of the rules that have this topics' tag.
        """
        return Rule.objects.filter(tags=self.tag)

    def __str__(self):
        return f"Topic {self.name}"

    class Meta:
        ordering = ('name', )


class SystemType(ExportModelOperationsMixin('system_type'), models.Model):
    """
    The system role and product code.  We only seem to recognise system type
    105.
    """
    role = models.CharField(max_length=15)
    product_code = models.CharField(max_length=10)

    def __str__(self):
        return self.product_code + u'/' + self.role

    class Meta:
        ordering = ('role', 'product_code',)
        unique_together = (('role', 'product_code'),)


class Tag(ExportModelOperationsMixin('tag'), models.Model):
    """
    Rules and topics use tags to identify specific things that they deal with.
    """
    name = models.CharField(max_length=32, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name', )


class Upload(ExportModelOperationsMixin('upload'), models.Model):
    """
    An upload of a set of rule reports on a system, from processing that
    occurred on a particular date.  Customers are usually interested in the
    most recent upload of reports.

    An upload may contain no reports; it may contain different reports of
    different rules from those previous.

    There should only ever be one 'current' upload for a system from a source.
    """
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    account = models.CharField(max_length=10, blank=True, null=True)
    org_id = models.CharField(max_length=50)
    system_type = models.ForeignKey('SystemType', on_delete=models.CASCADE, db_index=False)
    source = models.ForeignKey('UploadSource', on_delete=models.CASCADE, db_index=False)
    checked_on = models.DateTimeField(auto_now_add=True)
    current = models.BooleanField(default=True)
    is_satellite = models.BooleanField(default=True)

    def active_reports(self):
        """
        List all reports in this upload of active, non-acked rules.
        """
        return self.currentreport_set.filter(
            rule__active=True
        ).exclude(
            rule__in=models.Subquery(
                Ack.objects.filter(org_id=self.org_id).values('rule')
            )
        ).exclude(
            id__in=models.Subquery(
                CurrentReport.objects.filter(
                    rule__hostack__rule=models.OuterRef('id'),
                    rule__hostack__host=models.OuterRef('host'),
                    rule__hostack__org_id=self.org_id
                ).values('id')
            )
        )

    def __str__(self):
        return f"host {self.host_id} uploaded on {self.checked_on}"

    class Meta:
        ordering = ('host', 'checked_on',)
        # Note, the 'unique_for_date' field property only applies to the
        # date portion, and is enforced by Django not by the database.  We
        # want to allow multiple uploads per day, but each upload would be
        # a unique date, and we want the database to enforce this.
        constraints = [
            models.UniqueConstraint(
                fields=['host', 'source'],
                condition=models.Q(current=True),
                name='api_upload_current_host_source_uniqueness',
            )
        ]
        indexes = [
            models.Index(
                fields=['org_id', 'host', 'id'],
                condition=models.Q(current=True),
                name='api_upload_org_id_host_id',
            ),
        ]


class UploadSource(ExportModelOperationsMixin('upload_source'), models.Model):
    """
    Each upload comes from one source, which is an assumed distinct set of
    rules being processed.  Each source may combine one or more rulesets,
    but we don't track the connection between source and ruleset here.  The
    upload source is given during upload processing.
    """
    name = models.CharField(max_length=50, default='insights-client', unique=True)

    def __str__(self):
        return f"upload source '{self.name}'"


class WeeklyReportSubscription(
    ExportModelOperationsMixin('weekly_report_subscription'), models.Model
):
    """
    Users can individually opt into receiving a weekly report generated from
    statistics across their account.  The presence of a record in this model
    indicates that the user has opted into receiving this report.  If the
    user opts out again, then the record is deleted.

    There cannot be two people with the same username in the one account.
    The same username can be used in multiple accounts (e.g. 'admin').

    We also record the last time this user was sent an email.  It would be
    wise to not send them a weekly email again if, say, the emails for this
    week had only partly been sent out.

    The autosub field indicates if a subscription was created via the frontend
    logic that makes a request to the weekly report subscription endpoint
    to subscribe first-time visitors to the Advisor weekly report automatically.
    """
    username = models.CharField(unique=True, max_length=255,
                                help_text="User to receive reports")
    account = models.CharField(db_index=True, max_length=10, blank=True, null=True)
    org_id = models.CharField(db_index=True, max_length=50)
    last_email_at = models.DateTimeField(null=True, default=None)
    autosub = models.BooleanField(default=False)

    def __str__(self):
        return f"sub for {self.username} in {self.account} and org {self.org_id}"

    class Meta:
        ordering = ('org_id', 'username')


class SubscriptionExcludedAccount(
    ExportModelOperationsMixin('subscription_excluded_accounts'), models.Model
):
    """
    This model will contain all the accounts which need to be excluded
    for the WeeklyReport and/or Auto-Subscribed reports
    """
    org_id = models.CharField(db_index=True, max_length=50)
    account = models.CharField(db_index=True, max_length=10, blank=True, null=True)

    def __str__(self):
        return f"SubscriptionExcludedAccount account: {self.account} and org {self.org_id}"

    class Meta:
        ordering = ('org_id', 'account')
