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

import yaml
from django.test import TestCase
from django.db import connection

from api.utils import resolve_path


class FlooristQueryTest(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'basic_task_test_data'
    ]

    def test_floorist_queries_run(self):
        """
        Simple test that runs the floorist queries to ensure each query is valid SQL.
        """
        clowdpp_path = resolve_path('clowdapp.yml')
        with open(clowdpp_path, "r") as stream:
            clowdapp = yaml.safe_load(stream)

        self.assertIn(
            'objects', clowdapp,
            f"'objects' not found in {clowdapp.keys()}"
        )
        queries_done = 0
        for clowdappobj in clowdapp['objects']:
            self.assertIn(
                'kind', clowdappobj,
                f"'kind' not found in {clowdappobj.keys()}"
            )
            if clowdappobj['kind'] == 'FloorPlan':
                self.assertIn(
                    'spec', clowdappobj,
                    f"'spec' not found in {clowdappobj.keys()=}"
                )
                self.assertIn(
                    'queries', clowdappobj['spec'],
                    f"'queries' not found in {clowdappobj['spec'].keys()=}"
                )
                # sql_yaml = clowdappobj['data']['floorplan.yaml']
                # floor_plans = yaml.safe_load(sql_yaml)
                # self.assertEqual(len(floor_plans), 9)
                with connection.cursor() as cursor:
                    for floor_plan in clowdappobj['spec']['queries']:
                        cursor.execute(floor_plan['query'])
                        queries_done += 1

        self.assertGreater(
            queries_done, 0,
            "There must have been at least one query in Floorist"
        )
