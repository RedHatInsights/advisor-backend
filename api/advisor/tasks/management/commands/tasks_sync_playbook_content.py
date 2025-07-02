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

import json
from os import path

from django.core.management.base import BaseCommand

from advisor_logging import logger
from api.utils import resolve_path

# Paths relative to repository root
playbook_dir = resolve_path('api/advisor/tasks/playbooks')
assert playbook_dir is not None, "Could not find playbook directory"
fixture_name = 'production_tasks'
fixture_path = resolve_path('api/advisor/tasks/fixtures/', f'{fixture_name}.json')
assert fixture_path is not None, "Could not find production tasks fixture file"
logger.debug("Playbook dir: %s", playbook_dir)
logger.debug("Fixture path: %s", fixture_path)


def playbook_path(task_slug):
    playbook_file = f'{task_slug}.yml'
    return path.join(playbook_dir, playbook_file)


class Command(BaseCommand):
    help = "Check and update Tasks fixtures based on files in playbooks directory"

    def handle(self, *args, **options):
        if not path.exists(fixture_path):
            logger.error(
                "Fixture file not found in %s", fixture_path
            )
        with open(fixture_path, 'r') as fh:
            fixture_list = json.load(fh)
        file_is_changed = False
        fixture_for_task = {
            model['fields']['slug']: {
                'id': model['pk'], 'fields': model['fields']
            }
            for model in fixture_list
            if model['model'] == "tasks.Task"
        }
        # Don't use the Task model, as we might not have loaded the production
        # tasks fixture here.  Rely on the fixture data itself.
        for task_slug, task in fixture_for_task.items():
            task_id = task['id']
            fixture_fields = task['fields']
            # logger.info("Checking task %s - %s", task.id, task.slug)
            logger.info("Checking task %s - %s", task_id, task_slug)
            pb_path = playbook_path(task_slug)
            # Non-existent playbook content need to be written to files
            if not path.exists(pb_path):
                # Write file out
                with open(pb_path, 'w') as fh:
                    fh.write(fixture_fields['playbook'])
                logger.warn(
                    "Created %s for task %s - %s - use `git add` to add it to repository",
                    pb_path, task_id, task_slug
                )
                # And don't bother replacing the fixture
                continue
            with open(pb_path, 'r') as fh:
                file_content = fh.read()
            if fixture_fields['playbook'] != file_content:
                # Replace fixture's playbook with content
                fixture_fields['playbook'] = file_content
                file_is_changed = True
        if file_is_changed:
            with open(fixture_path, 'w') as fh:
                json.dump(fixture_list, fh, ensure_ascii=False, indent=2)
            logger.info(
                "Updated fixture file `%s` - use `git commit` to add those changes",
                fixture_path
            )
