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

from datetime import timedelta

from django.core.management.base import BaseCommand
# from django.db.models import
from django.utils import timezone

from advisor_logging import logger
from tasks.models import (
    ExecutedTask, JobStatusChoices, Task
)
from tasks.management.commands.tasks_service import update_executed_task_status


def check_stale_jobs_for(task):
    """
    Find all running jobs
    """
    now = timezone.now()
    timeout = timedelta(seconds=task.timeout)
    required_last_update = now - timeout
    # Here we're going to step through by executed task, since we then only
    # have to update the executed task status once after all the job
    timed_out_extasks = ExecutedTask.objects.filter(
        task=task, job__status=JobStatusChoices.RUNNING,
        job__updated_on__lt=required_last_update
    )

    if not timed_out_extasks.exists():
        return
    logger.warning(
        f"Found task {task.slug} had jobs past the {task.timeout}s timeout"
    )
    for extask in timed_out_extasks:
        # Maybe not obvious but the filter on the extasks queryset does not
        # extend to the jobs of each executed_task selected by job_set.
        for job in extask.job_set.filter(
            status=JobStatusChoices.RUNNING, updated_on__lt=required_last_update
        ):
            job.new_log(False, f"Job timed out after {task.timeout} seconds (run ID {job.run_id})")
            job.status = JobStatusChoices.TIMEOUT
            job.updated_on = now
            job.save()
        # Check and update the executed task status if no more running jobs
        update_executed_task_status(extask)


class Command(BaseCommand):
    help = "Time out any 'stale' jobs and complete their executed tasks if necessary"

    def handle(self, *args, **options):
        """
        Check each task in turn for jobs in executed tasks that have passed
        its time-out value.
        """
        logger.info('Stale job timeout command starting up')

        # Because the time-out is different per task, we step through the
        # tasks in turn and time out all jobs and executions related to that
        # task.  We only need to do this for active tasks since you can't
        # launch executions for inactive tasks.
        for task in Task.objects.filter(active=True):
            check_stale_jobs_for(task)

        logger.info('Stale job timeout command completed')
