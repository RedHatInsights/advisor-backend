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

from django.core.management import call_command
from django.test import TestCase

from tasks.models import ExecutedTask, ExecutedTaskStatusChoices, JobStatusChoices
from tasks.tests import constants


class UpdateExecutedTaskStatusTestCase(TestCase):
    fixtures = ['basic_task_test_data']

    def get_extask_objects(self):
        extask1 = ExecutedTask.objects.get(id=constants.executed_task_id)
        extask2 = ExecutedTask.objects.get(id=constants.executed_task_id_org_2)
        return (extask1, extask2)

    def update_extask_objects(self, extask1, extask2):
        # So update the running jobs to be finished.
        extask1.job_set.filter(status=JobStatusChoices.RUNNING).update(status=JobStatusChoices.SUCCESS)
        # Delete all of another executed task's jobs (simulates an old launch
        # problem)
        extask2.job_set.all().delete()

    def test_update_executed_task_status_command(self):
        # We have to modify some of the executed tasks in the basic test
        # data, because they're actually correct.
        extask1, extask2 = self.get_extask_objects()
        # It has running jobs
        self.assertNotEqual(
            extask1.job_set.filter(status=JobStatusChoices.RUNNING).count(), 0
        )
        # And some failed jobs
        self.assertNotEqual(
            extask1.job_set.filter(status=JobStatusChoices.FAILURE).count(), 0
        )
        # And it should be in the running state.
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.RUNNING)
        # Update the executed tasks
        self.update_extask_objects(extask1, extask2)
        # Now run the command
        call_command('update_executed_task_status')
        # Now the first executed task should be finished.
        extask1.refresh_from_db()
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        # But the second executed task should still exist in the database.
        self.assertTrue(
            ExecutedTask.objects.filter(id=extask2.id).exists()
        )

    # Test runs with different (correct) parameters
    # Extask 1 and 2 are both 'log4shell' tasks, but in different orgs and
    # with different jobs.

    def test_update_executed_task_status_command_executed_task_parameter(self):
        extask1, extask2 = self.get_extask_objects()
        self.update_extask_objects(extask1, extask2)
        call_command('update_executed_task_status', executed_task=[1])
        # Now the first executed task should be finished.
        extask1.refresh_from_db()
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        # And the second executed task should still exist.
        self.assertTrue(
            ExecutedTask.objects.filter(id=extask2.id).exists()
        )

    def test_update_executed_task_status_command_job_parameter(self):
        extask1, extask2 = self.get_extask_objects()
        self.update_extask_objects(extask1, extask2)
        call_command('update_executed_task_status', job=[1])
        # Now the first executed task should be finished.
        extask1.refresh_from_db()
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        # And the second executed task should still exist.
        self.assertTrue(
            ExecutedTask.objects.filter(id=extask2.id).exists()
        )

    def test_update_executed_task_status_command_org_id_parameter(self):
        extask1, extask2 = self.get_extask_objects()
        self.update_extask_objects(extask1, extask2)
        call_command('update_executed_task_status', org=[9876543])
        # Now the first executed task should be finished.
        extask1.refresh_from_db()
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        # And the second executed task should still exist.
        self.assertTrue(
            ExecutedTask.objects.filter(id=extask2.id).exists()
        )

    def test_update_executed_task_status_command_task_parameter(self):
        extask1, extask2 = self.get_extask_objects()
        self.update_extask_objects(extask1, extask2)
        call_command('update_executed_task_status', task=['log4shell'])
        # Now the first executed task should be finished.
        extask1.refresh_from_db()
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        # But the second executed task should still exist in the database
        # because we don't delete by default.
        self.assertTrue(
            ExecutedTask.objects.filter(id=extask2.id).exists()
        )

    def test_update_executed_task_status_command_delete_parameter(self):
        extask1, extask2 = self.get_extask_objects()
        self.update_extask_objects(extask1, extask2)
        call_command('update_executed_task_status', delete_empty=True)
        # Now the first executed task should be finished.
        extask1.refresh_from_db()
        self.assertEqual(extask1.status, ExecutedTaskStatusChoices.COMPLETED_WITH_ERRORS)
        # And the second executed task should be gone from the database!
        self.assertFalse(
            ExecutedTask.objects.filter(id=extask2.id).exists()
        )
