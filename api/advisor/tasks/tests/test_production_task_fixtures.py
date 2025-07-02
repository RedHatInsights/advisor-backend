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

from os import path
from sys import stdout
import yaml

from django.test import TestCase

from tasks.models import Task, TaskTypeChoices
from tasks.management.commands.tasks_sync_playbook_content import (
    playbook_dir, fixture_name,
)


def playbook_path(task_slug):
    playbook_file = f'{task_slug}.yml'
    return path.join(playbook_dir, playbook_file)


def warn(*args, end='\n'):
    stdout.write(' '.join(args) + end)


class ProductionFixturesTestCase(TestCase):
    fixtures = [fixture_name]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def test_tasks_have_playbook_file(self):
        """
        In all environments, each active task should have a playbook file.
        """
        if not path.exists(playbook_dir):
            return
        for task in Task.objects.filter(active=True):
            pb_path = playbook_path(task.slug)
            self.assertTrue(
                path.exists(pb_path), f"Task {task.id} - {task.slug} "
                f"does not have a playbook file in {pb_path}"
            )
            # Don't test content here - that depends on environment

    def test_tasks_have_signature(self):
        """
        In all environments, each active task's playbook should have a
        signature.  Verification of this signature is left as an exercise
        for elsewhere.
        """
        for task in Task.objects.filter(active=True):
            playbook = yaml.load(task.playbook, yaml.Loader)
            self.assertIsInstance(playbook, list)
            self.assertEqual(len(playbook), 1)
            # self.assertIn('hosts', playbook[0], f'Task {task.id} - {task.slug} - has no "hosts" field')
            # self.assertIsInstance(playbook[0]['hosts'], str)
            self.assertIn('vars', playbook[0])
            self.assertIsInstance(playbook[0]['vars'], dict)
            self.assertIn('insights_signature', playbook[0]['vars'])
            self.assertIsInstance(playbook[0]['vars']['insights_signature'], bytes)
            self.assertIn('insights_signature_exclude', playbook[0]['vars'])
            self.assertIsInstance(playbook[0]['vars']['insights_signature_exclude'], str)
            # maybe controversial - make sure we have something in the
            # playbook that outputs the right delimiters and data to be
            # picked up by the tasks service.
            if task.type == TaskTypeChoices.ANSIBLE:
                self.assertIn('tasks', playbook[0])
                self.assertIsInstance(playbook[0]['tasks'], list)
                # Find the last task in the playbook, which could be within an always block
                last_playbook_task = playbook[0]['tasks'][-1]
                if 'always' in last_playbook_task:
                    last_playbook_task = last_playbook_task['always'][-1]
                self.assertIn(
                    'ansible.builtin.debug', last_playbook_task,
                    f'Task {task.id} - {task.slug} playbook - last task is '
                    f'not "ansible.builtin.debug"'
                )
                self.assertIsInstance(
                    last_playbook_task['ansible.builtin.debug'], dict
                )
                self.assertIn(
                    'var', last_playbook_task['ansible.builtin.debug'],
                    f'Task {task.id} - {task.slug} playbook - last task has '
                    f'no "var" to print using "ansible.builtin.debug"'
                )
                self.assertEqual(
                    last_playbook_task['ansible.builtin.debug']['var'],
                    'task_results',
                    f'Task {task.id} - {task.slug} playbook - last task does '
                    f'not print `task_results` var using "ansible.builtin.debug"'
                )
            elif task.type == TaskTypeChoices.SCRIPT:
                self.assertIn('content', playbook[0]['vars'])
                self.assertIsInstance(playbook[0]['vars']['content'], str)
                self.assertIn(
                    '### JSON START ###', playbook[0]['vars']['content'],
                    f'Task {task.id} - {task.slug} playbook - content is '
                    f'missing the "### JSON START ###" delimiter'
                )
                self.assertIn(
                    '### JSON END ###', playbook[0]['vars']['content'],
                    f'Task {task.id} - {task.slug} playbook - content is '
                    f'missing the "### JSON END ###" delimiter'
                )

    def test_playbook_file_matches_fixture_content(self):
        """
        The playbook file content must match that in the fixture.
        """
        for task in Task.objects.filter(active=True):
            pb_path = playbook_path(task.slug)
            # Ignore nonexistent files, tested above
            if not path.exists(pb_path):
                warn(f"Couldn't find {pb_path}")
                continue
            with open(pb_path, 'r') as fh:
                file_content = fh.read()
            self.assertEqual(
                task.playbook, file_content,
                f"Task {task.id} - {task.slug} - content differs from {pb_path}"
                f" - run manage.py tasks_sync_playbook_content"
            )
