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
from django.urls import reverse

from project_settings import settings
from tasks.tests import constants

from openapi_spec_validator import validate


class TasksApiDocsTestCaseClass(TestCase):
    fixtures = ['basic_task_test_data']
    schema_path_name = 'tasks-schema'
    auth_dict = {}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        response = cls.client_class().get(
            reverse(cls.schema_path_name), HTTP_ACCEPT=constants.json_mime,
            **cls.auth_dict
        )
        cls.status_code = response.status_code
        cls.content = response.content.decode('utf-8')
        cls.swagger = response.json()


class NoauthTasksSchemaTestCase(TasksApiDocsTestCaseClass):
    """Test that the Tasks schema is accessible without authentication."""
    def test_schema_has_docs(self):
        self.assertEqual(self.status_code, 200, self.content)
        self.assertIn('info', self.swagger)
        self.assertIn('title', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['title'], '')
        self.assertIn('description', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['description'], '')
        self.assertIn('version', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['version'], '')
        self.assertIn('paths', self.swagger)
        self.assertIsInstance(self.swagger['paths'], dict)

    def test_schema_has_tasks_title(self):
        self.assertEqual(self.swagger['info']['title'], 'Insights Tasks API')

    def test_schema_paths_use_tasks_prefix(self):
        prefix = '/' + settings.TASKS_PATH_PREFIX
        for path in self.swagger['paths']:
            self.assertTrue(
                path.startswith(prefix),
                f"Path '{path}' does not start with tasks prefix '{prefix}'"
            )


class NoauthTasksJSONSpecTestCase(TasksApiDocsTestCaseClass):
    """Test the Tasks schema via the JSON endpoint accessible without authentication."""
    schema_path_name = 'tasks-openapi-spec-json'

    def test_schema_has_docs(self):
        self.assertEqual(self.status_code, 200, self.content)
        self.assertIn('info', self.swagger)
        self.assertIn('title', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['title'], '')
        self.assertIn('description', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['description'], '')
        self.assertIn('version', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['version'], '')
        self.assertIn('paths', self.swagger)
        self.assertIsInstance(self.swagger['paths'], dict)


class TasksOpenAPI3SchemaValidation(TasksApiDocsTestCaseClass):
    """Validate the Tasks schema against the OpenAPI 3 specification."""

    def test_openapi_3_schema_validation(self):
        self.assertIn('version', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['version'], '')
        self.assertIsNone(validate(self.swagger))
