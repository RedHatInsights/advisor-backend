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

from django.core.management.base import BaseCommand
from django.db.models import Q

from advisor_logging import logger
from tasks.management.commands.tasks_service import update_executed_task_status
from tasks.models import ExecutedTask


class Command(BaseCommand):
    help = "Updates the job and executed task states based on Kafka messages"

    def add_arguments(self, parser):
        parser.add_argument(
            '--executed_task', '--executed-task', '-e', type=int, nargs='+',
            help='Select by Executed Task ID'
        )
        parser.add_argument(
            '--job', '--job', '-j', type=int, nargs='+',
            help='Select by Job ID'
        )
        parser.add_argument(
            '--org', '--org', '-o', type=int, nargs='+',
            help='Select by Organisation ID'
        )
        parser.add_argument(
            '--task', '-t', type=str, nargs='+',
            help='Select by Task slug'
        )
        parser.add_argument(
            '--delete_empty', '--delete-empty',
            action='store_true', default=False,
            help="Delete 'empty' executed tasks with no jobs"
        )

    def handle(self, *args, **options):
        """
        Run through all executed tasks and change their state if necessary.
        """
        filters = []
        if options['executed_task']:
            filters.append(Q(id__in=options['executed_task']))
        if options['job']:
            filters.append(Q(job__id__in=options['job']))
        if options['org']:
            filters.append(Q(org_id__in=options['org']))
        if options['task']:
            filters.append(Q(task__slug__in=options['task']))
        etqs = ExecutedTask.objects.filter(*filters)
        logger.info("Checking executed task status on {n} tasks".format(
            n=etqs.count()
        ))
        delete_empty = options['delete_empty']
        for extask in etqs:
            update_executed_task_status(extask, send_message=False, delete_empty=delete_empty)
