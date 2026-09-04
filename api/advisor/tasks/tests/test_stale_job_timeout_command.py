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

from django.test import TestCase
from django.contrib.postgres.aggregates import ArrayAgg

from tasks.management.commands.stale_job_timeout import check_stale_jobs_for
from tasks.models import Job, JobStatusChoices, ExecutedTaskStatusChoices, Task
from tasks.tests import constants


class StaleJobTimeoutCommandTestCase(TestCase):
    fixtures = ['basic_task_test_data']

    def test_stale_job_timeout(self):
        log4shell = Task.objects.get(id=constants.task_id)
        self.assertEqual(log4shell.timeout, 3600)
        # Check that example data hasn't changed for some reason
        self.assertEqual(log4shell.slug, constants.task_slug)
        self.assertEqual(
            Job.objects.filter(
                executed_task__task=log4shell,
                executed_task__status=ExecutedTaskStatusChoices.RUNNING
            ).count(), 3
        )
        # Check that we at least have some tasks that will be timed out
        task_jobs = Job.objects.filter(executed_task__task=log4shell)
        stale_jobs = task_jobs.filter(updated_on__lt="2023-10-19T00:00:00Z")
        self.assertGreater(
            stale_jobs.filter(status=JobStatusChoices.RUNNING).count(), 0,
            stale_jobs.filter(status=JobStatusChoices.RUNNING)
        )
        # And assume that because the test data is old, all jobs will be
        # timed out.
        self.assertEqual(
            task_jobs.filter(updated_on__gte="2023-10-19T00:00:00Z").count(), 0
        )

        # Run the stale jobs check
        check_stale_jobs_for(log4shell)
        # Note that this changes the updated_on, status and executed_task.status
        # fields.  So the 'stale_jobs' query now doesn't really apply.

        # Now check that those jobs got timed out
        self.assertEqual(
            task_jobs.filter(status=JobStatusChoices.RUNNING).count(), 0,
            task_jobs.filter(status=JobStatusChoices.RUNNING)
        )
        self.assertGreater(
            task_jobs.filter(status=JobStatusChoices.TIMEOUT).count(), 0,
        )
        # The executed tasks should not be running
        self.assertEqual(
            log4shell.executedtask_set.filter(
                status=ExecutedTaskStatusChoices.RUNNING
            ).count(), 0,
            log4shell.executedtask_set.filter(
                status=ExecutedTaskStatusChoices.RUNNING
            )
        )
        # The one with only failed jobs should be a failure, the one with
        # cancelled jobs should be cancelled, and the other ones should be
        # completed with errors.
        for extask in log4shell.executedtask_set.annotate(
            job_statuses=ArrayAgg('job__status', distinct=True)
        ):
            if extask.job_statuses == [JobStatusChoices.FAILURE]:
                self.assertEqual(extask.status, ExecutedTaskStatusChoices.FAILURE)
            elif JobStatusChoices.CANCELLED in extask.job_statuses:
                self.assertEqual(extask.status, ExecutedTaskStatusChoices.CANCELLED)
            elif JobStatusChoices.SUCCESS in extask.job_statuses:
                self.assertEqual(extask.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
