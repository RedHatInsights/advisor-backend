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

from django.db.models import Count, Q
from django.test import TestCase

from tasks.models import (
    ExecutedTask, ExecutedTaskStatusChoices, Job, JobStatusChoices,
    TaskParameter
)


class TestDataTestCase(TestCase):
    fixtures = ['basic_task_test_data']

    def test_executed_tasks_must_have_jobs(self):
        executed_tasks_with_no_jobs = ExecutedTask.objects.filter(
            job__id__isnull=True
        )
        self.assertEqual(
            executed_tasks_with_no_jobs.count(), 0,
            [
                f"Executed task {extask.id} has no jobs"
                for extask in executed_tasks_with_no_jobs
            ]
        )

    def test_successful_jobs_have_results(self):
        def show_jobs(jobs, desc):
            return (
                'jobs (' + ', '.join(str(j.id) for j in jobs) + ') have '
                'succeeded but ' + desc
            )
        done_jobs = Job.objects.filter(status=JobStatusChoices.SUCCESS).annotate(
            log_count=Count('log')
        )
        self.assertEqual(
            done_jobs.filter(results__isnull=True).count(), 0,
            show_jobs(done_jobs.filter(results__isnull=True), "have no results")
        )
        self.assertEqual(
            done_jobs.filter(Q(stdout__isnull=True) | Q(stdout='')).count(), 0,
            show_jobs(done_jobs.filter(Q(stdout__isnull=True) | Q(stdout='')), "have an empty stdout")
        )
        self.assertEqual(
            done_jobs.filter(log_count=0).count(), 0,
            show_jobs(done_jobs.filter(log_count=0), "have no logs")
        )
        # Could check that results match what's parsed from stdout
        # Could check that results have findings

    def test_executed_task_job_status_match(self):
        for extask in ExecutedTask.objects.prefetch_related('job_set'):
            job_statuses = set(extask.job_set.values_list('status', flat=True))
            if extask.status == ExecutedTaskStatusChoices.RUNNING:
                # Should still be at least one running job
                self.assertIn(
                    JobStatusChoices.RUNNING, job_statuses,
                    f"ExTask {extask.id}: {extask.name} running but no running jobs"
                )
                # And no cancelled jobs
                self.assertNotIn(
                    JobStatusChoices.CANCELLED, job_statuses,
                    f"ExTask {extask.id}: {extask.name} running but has cancelled jobs"
                )
            elif extask.status == ExecutedTaskStatusChoices.COMPLETED:
                # No running jobs
                self.assertNotIn(
                    JobStatusChoices.RUNNING, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed but has running jobs"
                )
                # And no failed jobs
                self.assertNotIn(
                    JobStatusChoices.FAILURE, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed but has failed jobs"
                )
                # Nor any cancelled jobs
                self.assertNotIn(
                    JobStatusChoices.CANCELLED, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed but has cancelled jobs"
                )
            elif extask.status == ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS:
                # No running jobs
                self.assertNotIn(
                    JobStatusChoices.RUNNING, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed with errors but has running jobs"
                )
                # And has at least one successful job
                self.assertIn(
                    JobStatusChoices.SUCCESS, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed with errors but has no successful jobs"
                )
                # And has at least one failed or timed out job
                self.assertIn(
                    JobStatusChoices.FAILURE, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed with errors but has no failed jobs"
                )
                # No cancelled jobs
                self.assertNotIn(
                    JobStatusChoices.CANCELLED, job_statuses,
                    f"ExTask {extask.id}: {extask.name} completed with errors but has cancelled jobs"
                )
            elif extask.status == ExecutedTaskStatusChoices.FAILURE:
                # No running jobs
                self.assertNotIn(
                    JobStatusChoices.RUNNING, job_statuses,
                    f"ExTask {extask.id}: {extask.name} failed but has running jobs"
                )
                # And no successful jobs
                self.assertNotIn(
                    JobStatusChoices.SUCCESS, job_statuses,
                    f"ExTask {extask.id}: {extask.name} failed but has successful jobs"
                )
                # Nor any cancelled jobs
                self.assertNotIn(
                    JobStatusChoices.CANCELLED, job_statuses,
                    f"ExTask {extask.id}: {extask.name} failed but has cancelled jobs"
                )
            elif extask.status == ExecutedTaskStatusChoices.CANCELLED:
                # No running tasks
                self.assertNotIn(
                    JobStatusChoices.RUNNING, job_statuses,
                    f"ExTask {extask.id}: {extask.name} cancelled but has running jobs"
                )
                # And at least one cancelled tasks
                self.assertIn(
                    JobStatusChoices.CANCELLED, job_statuses,
                    f"ExTask {extask.id}: {extask.name} cancelled but no cancelled jobs"
                )

    def test_task_parameter_values(self):
        """
        Test that the values given in defaults and executed task parameters
        are one of the given list of that parameter's values.
        """
        for param in TaskParameter.objects.all():
            # Check the parameter default value is in the list of allowed values for this parameter
            self.assertIn(
                param.default, param.values + [None] if param.default is None else param.values,
                f"Task {param.task.id}: {param.task.slug} parameter {param.key} "
                f"default {param.default} not in values list {param.values}"
            )
            # Check if any invalid values were supplied in the executed task parameters
            if param.multi_valued:
                invalid_values = []
                for etp in param.executedtaskparameter_set.values():
                    invalid_values.extend(
                        [etp for value in etp['value'].split(',') if value not in param.values]
                    )
            else:
                invalid_values = list(
                    param.executedtaskparameter_set.exclude(value__in=param.values).values()
                )

            self.assertEqual(
                invalid_values, [],
                f"Task {param.task.id}: {param.task.slug} parameter {param.key} "
                f"has executed task parameter value not in values list for IDs "
                f"{[etp['id'] for etp in invalid_values]}"
            )
