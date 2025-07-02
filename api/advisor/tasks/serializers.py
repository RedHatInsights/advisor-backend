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

from rest_framework import serializers

from api.serializers import validate_hosts_in_org
from tasks import models
from tasks.models import TaskTypeChoices
from tasks.utils import requirements


def existing_task_slug_validator(slug):
    if not models.Task.objects.filter(slug=slug).exists():
        raise serializers.ValidationError(f"Task with slug '{slug}' not found")


class JobTaskSerializer(serializers.ModelSerializer):
    """
    The jobs for a particular executed task
    """
    display_name = serializers.CharField(allow_blank=True, required=False)
    status = serializers.CharField(source='get_status_display')
    has_stdout = serializers.BooleanField()
    log_link = serializers.HyperlinkedIdentityField(
        view_name='tasks-job-log', lookup_field='id', lookup_url_kwarg='id',
    )
    stdout_link = serializers.HyperlinkedIdentityField(
        view_name='tasks-job-stdout', lookup_field='id', lookup_url_kwarg='id',
    )

    class Meta:
        model = models.Job
        fields = (
            'id', 'system_id', 'display_name', 'status', 'run_id',
            'has_stdout', 'results', 'updated_on', 'log_link', 'stdout_link',
        )


class JobLogTaskSerializer(serializers.ModelSerializer):
    """
    The log of all jobs for a particular executed task
    """
    system_id = serializers.UUIDField()
    display_name = serializers.CharField()
    run_id = serializers.UUIDField(source='job.run_id')

    class Meta:
        model = models.JobLog
        fields = (
            'system_id', 'display_name', 'created_at', 'is_ok', 'line', 'run_id'
        )


class ExecutedTaskParameterSerializer(serializers.ModelSerializer):
    """
    The parameter's key and value as well as the display options.
    """
    key = serializers.CharField(source='parameter.key')
    title = serializers.CharField(source='parameter.title', read_only=True, required=False)
    value = serializers.CharField(required=True, allow_blank=True)
    # Don't require these fields for input, just output:
    description = serializers.CharField(source='parameter.description', read_only=True, required=False)
    default = serializers.CharField(source='parameter.default', read_only=True, required=False)
    required = serializers.BooleanField(source='parameter.required', read_only=True, required=False)
    values = serializers.ListField(source='parameter.values', read_only=True, required=False)
    multi_valued = serializers.BooleanField(source='parameter.multi_valued', read_only=True, required=False)
    index = serializers.IntegerField(source='parameter.index', read_only=True, required=False)

    # Validation is done in the ExecuteTaskSerializer, where it knows the
    # task name and can therefore look up the unique task parameter (we
    # assume that a task parameter key might be shared across more than one
    # tasks - e.g. "verbose").  This also applies to the value being in the
    # given array of values.
    class Meta:
        model = models.ExecutedTaskParameter
        fields = (
            'id', 'key', 'title', 'value', 'description', 'default',
            'required', 'values', 'multi_valued', 'index'
        )


class ExecuteTaskParameterSerializer(serializers.ModelSerializer):
    """
    The parameter key and value to be used when executing a task.
    """
    key = serializers.CharField(source='parameter.key')
    value = serializers.CharField(required=True, allow_blank=True)

    class Meta:
        model = models.ExecutedTaskParameter
        fields = ('key', 'value')


class ExecutedTaskOneSerializer(serializers.ModelSerializer):
    """
    A single executed task, as well as the task details, parameters and jobs.
    """
    task_url = serializers.HyperlinkedIdentityField(
        view_name='tasks-task-detail', lookup_field='task_slug',
        lookup_url_kwarg='slug',
    )
    task_slug = serializers.SlugField()
    task_title = serializers.CharField()
    task_description = serializers.CharField()
    task_filter_message = serializers.CharField()
    status = serializers.CharField(source='get_status_display')
    systems_count = serializers.IntegerField()
    jobs = JobTaskSerializer(many=True)
    parameters = ExecutedTaskParameterSerializer(many=True)

    class Meta:
        model = models.ExecutedTask
        fields = (
            'id', 'name', 'task_slug', 'task_url', 'task_title',
            'task_description', 'task_filter_message', 'initiated_by',
            'start_time', 'end_time', 'status', 'jobs', 'systems_count',
            'parameters'
        )


class ExecutedTaskSerializer(serializers.ModelSerializer):
    """
    An executed task in a list, with less detail than the single view.
    """
    this_url = serializers.HyperlinkedIdentityField(
        view_name='tasks-executedtask-detail', lookup_field='id',
    )
    task_url = serializers.HyperlinkedIdentityField(
        view_name='tasks-task-detail', lookup_field='task_slug',
        lookup_url_kwarg='slug',
    )
    task_slug = serializers.SlugField()
    task_title = serializers.CharField()
    task_description = serializers.CharField()
    task_filter_message = serializers.CharField()
    status = serializers.CharField(source='get_status_display')
    systems_count = serializers.IntegerField()
    running_jobs_count = serializers.IntegerField()
    completed_jobs_count = serializers.IntegerField()
    failure_jobs_count = serializers.IntegerField()
    timeout_jobs_count = serializers.IntegerField()

    class Meta:
        model = models.ExecutedTask
        fields = (
            'id', 'name', 'this_url', 'task_url', 'task_slug', 'task_title',
            'task_description', 'task_filter_message', 'initiated_by',
            'start_time', 'end_time', 'status', 'systems_count',
            'running_jobs_count', 'completed_jobs_count', 'failure_jobs_count', 'timeout_jobs_count'
        )


class ExecuteTaskSerializer(serializers.Serializer):
    """
    Execute a task on a given set of hosts.

    Creates an ExecutedTask object and one or more Job objects, one for each
    recognised host.
    """
    task = serializers.SlugField(validators=[existing_task_slug_validator])
    # Do host validation in main validator to check if hosts are in org
    hosts = serializers.ListField(child=serializers.UUIDField())
    parameters = ExecuteTaskParameterSerializer(many=True, required=False)
    name = serializers.CharField(required=False)

    def validate(self, data):
        """
        If parameters are supplied, check that all required parameters that
        have no default are supplied.  The parameter serializer will check if
        they have both a key and a value, since both are required, but not
        unique (since it has no memory of what else has been seen in this
        request).  This also fills in any parameters that are required, and
        not supplied, with their default value.
        """
        # Field validation has passed, so we can assume that the required
        # fields of the execute task serializer are present.
        if 'hosts' not in data or len(data['hosts']) == 0:
            raise serializers.ValidationError({
                'hosts': ['Task must be run on at least one host']
            })
        assert 'request' in self._context, (
            "Supply the request in the context to the serializer, e.g. "
            "context={'request': request}"
        )
        validate_hosts_in_org(data['hosts'], self._context['request'].auth['org_id'], 'hosts')

        # Validate parameters
        provided_parameters = set()
        task_parameters_qs = models.TaskParameter.objects.filter(
            task__slug=data['task']
        ).order_by('key')
        task_parameters = {
            param.key: param
            for param in task_parameters_qs
        }
        required_parameters = task_parameters_qs.filter(required=True)
        unrecognised_parameters = set()
        unmatched_values = []
        if 'parameters' not in data:
            # We only have to worry about required parameters that have no
            # default...
            missing_parameters = required_parameters.filter(default=None)
        else:
            # note that we use the task parameter key field's source name here...
            duplicated_parameters = set()
            for param in data['parameters']:
                # Because the 'key' field in ExecutedTaskParameterSerializer
                # has the source 'parameter.key', the key here actually
                # appears as a dict within 'parameter' within the parameter,
                # but the value is just within the parameter itself.
                key = param['parameter']['key']
                if key not in task_parameters:
                    unrecognised_parameters.add(key)
                elif key in provided_parameters:
                    duplicated_parameters.add(key)
                else:
                    # Have a valid parameter
                    provided_parameters.add(key)
                    # Check that the supplied value is in the list of allowed values for this parameter
                    # Split the supplied value on comma if parameter supports multiple values
                    param_values = task_parameters[key].values
                    supplied_values = [param['value']]
                    if task_parameters[key].multi_valued:
                        supplied_values = param['value'].split(',')  # commas are the delimiter, for now
                    for supplied_value in supplied_values:
                        if supplied_value not in param_values:
                            unmatched_values.append(
                                f"Supplied value '{supplied_value}' for parameter '{key}' "
                                f"needs to be one of {param_values}"
                            )
            # Raise on unrecognised parameters first
            if unrecognised_parameters:
                raise serializers.ValidationError({
                    'parameters': [
                        f"Parameter '{key}' is not a valid parameter for task {data['task']}"
                        for key in unrecognised_parameters
                    ]
                })
            # Raise on duplicated parameters next
            if duplicated_parameters:
                raise serializers.ValidationError({
                    'parameters': [
                        f"Parameter '{key}' is duplicated"
                        for key in sorted(duplicated_parameters)
                    ]
                })
            # And then unmatched values
            if unmatched_values:
                raise serializers.ValidationError({
                    'parameters': unmatched_values
                })
            # Finally find any remaining missing parameters
            missing_parameters = (
                required_parameters.filter(default=None)
                .exclude(key__in=provided_parameters)
            )
        if missing_parameters.exists():
            raise serializers.ValidationError({
                'parameters': [
                    f"Parameter '{param.key}' requires a value"
                    for param in missing_parameters
                ]
            })

        # We cannot have any side-effects here - adding the parameters that
        # were not given, are required, and have a default, has to happen in
        # the code after is_valid() is called.
        return data


class HostSerializer(serializers.ModelSerializer):
    os_version = serializers.CharField()
    connection_type = serializers.CharField()
    tags = serializers.ListField(child=serializers.DictField())
    connected = serializers.BooleanField()
    last_check_in = serializers.DateTimeField()

    class Meta:
        model = models.Host
        fields = (
            'id', 'display_name', 'tags', 'groups', 'os_version', 'updated',
            'connection_type', 'stale_timestamp', 'stale_warning_timestamp',
            'culled_timestamp', 'connected', 'last_check_in', 'system_profile'
        )


class JobSerializer(serializers.ModelSerializer):
    system = serializers.UUIDField(source='system_id')
    status = serializers.CharField(source='get_status_display')
    display_name = serializers.CharField(allow_blank=True, required=False)
    connection_type = serializers.CharField()
    has_stdout = serializers.BooleanField()
    log_link = serializers.HyperlinkedIdentityField(
        view_name='tasks-job-log', lookup_field='id', lookup_url_kwarg='id',
    )
    stdout_link = serializers.HyperlinkedIdentityField(
        view_name='tasks-job-stdout', lookup_field='id', lookup_url_kwarg='id',
    )
    executed_task_link = serializers.HyperlinkedIdentityField(
        view_name='tasks-executedtask-detail', lookup_field='executed_task_id',
        lookup_url_kwarg='id'
    )

    class Meta:
        model = models.Job
        fields = (
            'id', 'executed_task', 'executed_task_link', 'system', 'display_name',
            'connection_type', 'status', 'run_id', 'has_stdout', 'results',
            'updated_on', 'log_link', 'stdout_link', 'rhc_client_id',
        )


class JobLogSerializer(serializers.ModelSerializer):
    """
    A line of information relating to the progress of a job.
    """
    run_id = serializers.UUIDField(source='job.run_id')

    class Meta:
        model = models.JobLog
        fields = (
            'created_at', 'is_ok', 'line', 'run_id'
        )


class TaskParameterSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.TaskParameter
        fields = (
            'key', 'title', 'description', 'values', 'default', 'required', 'multi_valued', 'index'
        )


class TaskSerializer(serializers.ModelSerializer):
    type = serializers.CharField(source='get_type_display')
    parameters = TaskParameterSerializer(source='taskparameters', many=True)
    systems_url = serializers.HyperlinkedIdentityField(
        view_name='tasks-task-systems', lookup_field='slug',
    )

    class Meta:
        model = models.Task
        fields = (
            'slug', 'title', 'type', 'description', 'publish_date', 'parameters',
            'filter_message', 'systems_url',
        )


class TaskContentSerializer(serializers.ModelSerializer):
    type = serializers.ChoiceField(source='get_type_display', required=False, choices=TaskTypeChoices.choices)
    parameters = TaskParameterSerializer(source='taskparameters', many=True, required=False)
    filters = serializers.MultipleChoiceField(
        choices=sorted(requirements.keys()), required=False
    )

    def validate_parameters(self, params):
        """
        Ensure paramter indexes are unique for the same task
        """
        indexes = set()
        for param in params:
            new_index = param.get('index')

            if new_index in indexes:
                raise serializers.ValidationError(
                    f"Task parameters must have unique indexes for the same task. "
                    f"Index {new_index} is duplicated."
                )
            indexes.add(new_index)

        return params

    def validate(self, data):
        if 'filters' in data and isinstance(data['filters'], set):
            # Change from set to list for saving in ArrayField
            data['filters'] = list(data['filters'])
        return data

    def create(self, validated_data):
        """
        Create the task, and then create any parameters associated with it.
        """
        if 'taskparameters' in validated_data:
            parameters = validated_data['taskparameters']
            del validated_data['taskparameters']
        else:
            parameters = []
        if 'get_type_display' in validated_data:
            validated_data['type'] = validated_data['get_type_display']
            del validated_data['get_type_display']
        # Create new Task object:
        task = models.Task(**validated_data)
        task.save()
        # Create any additional parameters
        if parameters:
            params_to_create = [
                models.TaskParameter(task=task, **param)
                for param in parameters
            ]
            models.TaskParameter.objects.bulk_create(params_to_create)
        # and finished
        return task

    def update(self, instance, validated_data):
        """
        Update the task, and then completely replace any parameters associated
        with the old task with the given ones.  Could try to do a nicer
        retain/insert/update/delete quadrage maybe.  If the `taskparameters`
        key (i.e. the 'parameters' field in the serializer) is not supplied,
        the task's parameters are unchanged.
        """
        if 'taskparameters' in validated_data:
            parameters = validated_data['taskparameters']
            del validated_data['taskparameters']
        else:
            parameters = None

        # make sure we update the choice field, since request comes in as display value
        if 'get_type_display' in validated_data:
            validated_data['type'] = validated_data['get_type_display']
            del validated_data['get_type_display']

        # Update the Task
        for key, value in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        # And then replace and update its parameters if the property was set
        # in the incoming data.
        if parameters:
            instance.taskparameters.all().delete()
            params_to_create = [
                models.TaskParameter(task=instance, **param)
                for param in parameters
            ]
            models.TaskParameter.objects.bulk_create(params_to_create)
        # and finished
        return instance

    class Meta:
        model = models.Task
        fields = (
            'slug', 'title', 'type', 'description', 'publish_date', 'active',
            'playbook', 'parameters', 'filter_message', 'filters'
        )
        # Since the slugs aren't the primary key, we can allow users to edit
        # them without changing any references from ExecutedTask.


class TaskHostSerializer(serializers.ModelSerializer):
    os_version = serializers.CharField()
    connection_type = serializers.CharField()
    tags = serializers.ListField(child=serializers.DictField())
    requirements = serializers.ListField(child=serializers.CharField())
    connected = serializers.BooleanField()
    last_check_in = serializers.DateTimeField()

    class Meta:
        model = models.Host
        fields = (
            'id', 'display_name', 'tags', 'groups', 'os_version', 'updated',
            'connection_type', 'requirements', 'stale_timestamp',
            'stale_warning_timestamp', 'culled_timestamp', 'connected',
            'last_check_in', 'system_profile'
        )
