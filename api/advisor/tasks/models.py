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

import uuid

from django.db import models
from django.db.models.expressions import RawSQL
from django.contrib.postgres.fields import ArrayField

from api.models import Relationship

# Choices classes


class ExecutedTaskStatusChoices(models.IntegerChoices):
    RUNNING = 1
    COMPLETED = 2
    COMPLETED_WITH_ERRORS = 3
    FAILURE = 4
    CANCELLED = 5


class JobStatusChoices(models.IntegerChoices):
    RUNNING = 1
    SUCCESS = 2
    FAILURE = 3
    TIMEOUT = 4
    CANCELLED = 5

    # To find the status value from a string, use the Enum item access:
    # >>> StatusChoices['RUNNING']
    # StatusChoices.RUNNING


class TaskTypeChoices(models.TextChoices):
    ANSIBLE = 'A', 'Ansible'
    SCRIPT = 'S', 'Script'


# Helpers

class ArrayNoNull(models.Func):
    template = 'ARRAY_REMOVE(%(function)s[%(expressions)s]::varchar(255)[], null)'
    function = 'ARRAY'


# Models


class ExecutedTask(models.Model):
    """
    A task being executed on one or more systems by a user.
    """
    name = models.CharField(max_length=200)
    task = models.ForeignKey('Task', on_delete=models.CASCADE)
    org_id = models.CharField(max_length=50)
    initiated_by = models.CharField(help_text='username', max_length=80)
    is_org_admin = models.BooleanField(default=False)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True)
    status = models.PositiveSmallIntegerField(choices=ExecutedTaskStatusChoices.choices)
    token = models.UUIDField(default=uuid.uuid4, unique=True)

    def __str__(self):
        return f"{self.name} started by {self.initiated_by} ({self.get_status_display()})"


class ExecutedTaskParameter(models.Model):
    """
    The task parameter, with its value, used by this executed task.  This is
    sent to all systems in this executed task.  Only parameters with a value
    """
    executed_task = models.ForeignKey(
        'ExecutedTask', on_delete=models.CASCADE, related_name='parameters'
    )
    parameter = models.ForeignKey('TaskParameter', on_delete=models.CASCADE)
    value = models.CharField(max_length=250, blank=True)

    class Meta:
        unique_together = [['executed_task', 'parameter']]
        ordering = ['parameter__index']

    def __str__(self):
        return f"ET ID {self.executed_task_id} {self.parameter.key}={self.value}"


class Host(models.Model):
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

    @property
    def os_version(self):
        "Helper to display OS version from Inventory"
        profile = self.system_profile
        if 'operating_system' not in profile:
            return "Unknown operating system"
        os_details = profile['operating_system']
        if 'name' not in os_details:
            return "Unknown OS name"
        if 'major' in os_details and 'minor' in os_details:
            return f"{os_details['name']} {os_details['major']}.{os_details['minor']}"
        elif 'major' in os_details:
            return f"{os_details['name']} {os_details['major']}"
        else:
            return f"Unknown {os_details['name']} version"

    @staticmethod
    def tag_query(tag_key):
        """
        This returns an expression that allows you to query a tag value from a host given its key.
        There's probably a more django way to do this without raw sql but this is much easier.
        https://stackoverflow.com/questions/58094851/lateral-join-in-django-queryset-in-order-to-use-jsonb-to-recordset-postgresql-f
        """
        raw_sql = """
        SELECT tag.val ->> 'value' AS tag_value
        FROM inventory.hosts t
                JOIN LATERAL JSONB_ARRAY_ELEMENTS(t.tags) tag(val)
                    ON tag.val ->> 'namespace' = 'satellite' AND tag.val ->> 'key' = %s
        WHERE t.id = "inventory"."hosts".id
        """
        return RawSQL(raw_sql, [tag_key])

    def __str__(self):
        return f"{self.display_name} ({self.id})"

    class Meta:
        managed = False
        db_table = '"inventory"."hosts"'


class JobManager(models.Manager):
    def original_queryset(self):
        return super().get_queryset()

    def get_queryset(self):
        return self.original_queryset().annotate(
            display_name=models.F('system__display_name'),
            has_stdout=models.Case(
                models.When(
                    models.Q(stdout__isnull=True) | models.Q(stdout=''),
                    then=models.Value(False)
                ),
                default=models.Value(True),
                output_field=models.BooleanField()
            ),
            connection_type=models.Case(
                models.When(
                    system__display_name__isnull=True,
                    then=models.Value('none'),
                ),
                models.When(
                    system__system_profile__rhc_client_id__isnull=False,
                    then=models.Value('direct'),
                ),
                default=models.Value('satellite'),
                output_field=models.CharField()
            )
        )


class Job(models.Model):
    """
    A task being executed on a single system.  Records the status of the
    executed task on this system.

    Note that there is no foreign key relationship to the Inventory hosts
    table because the 'table' is in fact a view (and therefore cannot support
    foreign keys).  This means that if a system gets deleted, nothing happens
    to its jobs.
    """
    executed_task = models.ForeignKey('ExecutedTask', on_delete=models.CASCADE)
    system_id = models.UUIDField()
    system = Relationship(
        'Host', from_fields=['system_id'], to_fields=['id'],
        related_name='jobs'
    )
    status = models.PositiveSmallIntegerField(choices=JobStatusChoices.choices)
    stdout = models.TextField(blank=True, default='')
    results = models.JSONField()
    updated_on = models.DateTimeField()
    run_id = models.UUIDField()  # The playbook dispatcher run identifier
    rhc_client_id = models.UUIDField(null=True, db_index=True)

    objects = JobManager()

    def __str__(self):
        return f"{self.executed_task.task.title} run on {self.system.display_name}: {self.get_status_display()}"

    def new_log(self, is_ok, line):
        """
        Write a new log line for this job.  Used mainly for logging the
        internal processes for a job.
        """
        log = JobLog(job=self, is_ok=is_ok, line=line)
        log.save()


class JobLog(models.Model):
    """
    A log of events relating to a particular job.  This allows external and
    internal applications a way to write events, and in turn allows us to
    provide the customer with more information about what is happening to a
    job.
    """
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    job = models.ForeignKey('Job', related_name='log', on_delete=models.CASCADE)
    is_ok = models.BooleanField(default=True)
    line = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.id}: '{self.line}' ({'ok' if self.is_ok else 'bad'})"


class SatelliteRhc(models.Model):
    """
    Tracks RHC connections for each Satellite instance.  The 'instance_id'
    corresponds to the Host's 'satellite:satellite_instance_id' value.  The
    'source_id' is an arbitrary number.  The 'rhc_client_id' is what the
    Cloud Connector and Playbook Dispatcher use to contact this actual
    system.
    """
    instance_id = models.UUIDField(primary_key=True)
    source_id = models.BigIntegerField(unique=True)
    rhc_client_id = models.UUIDField(null=True, db_index=True)


class Task(models.Model):
    """
    A description of a task playbook, written by Red Hat and available to run.
    """
    slug = models.SlugField(unique=True)
    type = models.CharField(
        max_length=1, choices=TaskTypeChoices.choices, default=TaskTypeChoices.ANSIBLE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    publish_date = models.DateTimeField()
    active = models.BooleanField(default=False)
    playbook = models.TextField()
    timeout = models.PositiveIntegerField(default=3600)
    filter_message = models.CharField(max_length=200, null=True)
    filters = ArrayField(models.SlugField(max_length=40), default=list)

    def __str__(self):
        return self.title


class TaskParameter(models.Model):
    """
    Parameters to be fed into the task when it is executed.  These have a key,
    to be filled in with a value in the executed task.  No type is enforced.
    Optional parameters should have the 'required' field set to False.  A
    default can be supplied - if the field is required, a default must be
    supplied.
    """
    task = models.ForeignKey('Task', on_delete=models.CASCADE, related_name='taskparameters')
    key = models.CharField(max_length=100)
    title = models.CharField(max_length=250)
    values = ArrayField(base_field=models.CharField(max_length=250))
    default = models.CharField(max_length=250, null=True, blank=True)
    description = models.TextField()
    required = models.BooleanField(default=False)
    multi_valued = models.BooleanField(default=False)
    index = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['task', 'index'], name='taskparameter_task_index_uniqueness')
        ]

        ordering = ['index']

    def __str__(self):
        return f"{self.task.title} key {self.key}"
