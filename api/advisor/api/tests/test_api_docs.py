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

from datetime import datetime
import responses

from django.test import TestCase
from django.urls import reverse

from project_settings import settings
from api.permissions import auth_header_for_testing
from api.tests import constants

from openapi_spec_validator import validate_spec


class ApiDocsTestCaseClass(TestCase):
    fixtures = ['rulesets']
    schema_path_name = 'advisor-openapi-spec'
    # Replace auth_dict with a call to auth_header_for_testing for view auth
    auth_dict = {}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Test the schema that we get from the Swagger endpoint
        response = cls.client_class().get(
            reverse(cls.schema_path_name), HTTP_ACCEPT=constants.json_mime,
            **cls.auth_dict
        )
        cls.swagger = response.json()


class UnauthedUserAPIDocsTestCase(ApiDocsTestCaseClass):
    def test_schema_has_docs(self):
        self.assertIn('info', self.swagger)
        self.assertIn('title', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['title'], '')
        self.assertIn('description', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['description'], '')
        self.assertIn('version', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['version'], '')
        self.assertIn('paths', self.swagger)
        self.assertIsInstance(self.swagger['paths'], dict)
        paths = self.swagger['paths']
        # We should not have paths that require authentication:
        for auth_reqd_path in (
            '/ack/', '/export/hits/', '/rule/',
            '/system/', '/stats/', '/user-preferences'
        ):
            self.assertNotIn(auth_reqd_path, paths)


class RegularUserAPIDocsTestCase(ApiDocsTestCaseClass):
    schema_path_name = 'advisor-openapi-spec-json'  # just to test the view
    auth_dict = auth_header_for_testing()

    def test_schema_has_docs(self):
        self.assertIn('info', self.swagger)
        self.assertIn('title', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['title'], '')
        self.assertIn('description', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['description'], '')
        self.assertIn('version', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['version'], '')
        self.assertIn('paths', self.swagger)
        self.assertIsInstance(self.swagger['paths'], dict)
        paths = self.swagger['paths']
        # We should not have paths that only internal users can see:
        for auth_reqd_path in (
            '/ackcount/',
            '/rule/{rule_id}/ack_hosts', '/rule/{rule_id}/stats/',
            '/rating/all_ratings/', '/rating/stats/',
        ):
            self.assertNotIn(
                auth_reqd_path, paths,
                f'{auth_reqd_path} should not be in {paths.keys()}'
            )


class APIDocsTestCase(ApiDocsTestCaseClass):
    auth_dict = auth_header_for_testing(user_opts={'is_internal': True})

    def test_schema_has_docs(self):
        self.assertIn('info', self.swagger)
        self.assertIn('title', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['title'], '')
        self.assertIn('description', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['description'], '')
        self.assertIn('version', self.swagger['info'])
        self.assertNotEqual(self.swagger['info']['version'], '')

    def test_all_methods_have_description(self):
        self.assertIn('paths', self.swagger)
        for endpoint, end_data in self.swagger['paths'].items():
            # Check endpoint parameters if any:
            if 'parameters' in end_data:
                for param_data in end_data['parameters']:
                    self.assertIn('description', param_data,
                        "Endpoint {e} parameter {p} must have a description".format(
                            e=endpoint, p=param_data['name']
                        )
                    )
                    self.assertNotEqual(
                        param_data['description'], "",
                        "Endpoint '{e}' parameter {p} description must not be blank".format(
                            e=endpoint, p=param_data['name']
                        )
                    )
            # Check operators on endpoint
            for operator, op_data in end_data.items():
                # Ignore parameter definition in endpoint
                if operator in ('parameters',):
                    continue
                # Check for description
                self.assertIn(
                    'description', op_data,
                    f"Endpoint {endpoint} operator {operator} must have a description "
                    "- use the two-paragraph format in the method's docstrong"
                )
                self.assertNotEqual(
                    op_data['description'], "",
                    "Endpoint '{e}' operand '{o}' description must not be blank".format(
                        e=endpoint, o=operator
                    )
                )
                # TODO: get back in schema scan with drf_spectacular
                # self.assertIn(
                #     'summary', op_data,
                #     f"Endpoint {endpoint} operator {operator} must have a summary "
                #     "- use the two-paragraph format in the method's docstring"
                # )
                # Check operator parameters if any
                if 'parameters' in op_data:
                    for param_data in op_data['parameters']:
                        if operator in ('post', 'delete', 'patch') and param_data['in'] == 'body':
                            self.assertNotIn(
                                'description', op_data['parameters'],
                                'Special handling for body parameters lacking '
                                'a description is still in place - please '
                                'remove this check now that post parameters '
                                'can be described'
                            )
                            continue
                        # TODO: get back in schema scan with drf_spectacular
                        # self.assertIn('description', param_data,
                        #     "Endpoint '{e}' operation '{o}' parameter '{p}' must have a description".format(
                        #         e=endpoint, o=operator, p=param_data['name']
                        #     )
                        # )
                        # self.assertNotEqual(
                        #     param_data['description'], "",
                        #     "Endpoint '{e}' operation '{o}' parameter {p} description must not be blank".format(
                        #         e=endpoint, o=operator, p=param_data['name']
                        #     )
                        # )
                # Each operator also has a dict of responses - e.g. 200, 404.
                # But it's difficult to set that description for all
                # responses.

    def test_parameter_default_types(self):
        # Parameters should all have their 'default' type as the same type
        # of thing that the parameter defines.  Note that this includes
        # parameters that are handled as lists - e.g. sort parameters with
        # multiple sort fields - but are specified in OpenAPI 3 as a
        # parameter that can take multiple values and can also be specified
        # e.g. as comma separated values (e.g. 'display_name,-id')
        # Mappings from the OpenAPI 3 type value to a Python type.
        # OpenApiTypes is an enum and is no help here.
        # Just define non-string types; everything else should be a string.
        type_of_value = {
            'boolean': bool, 'date': datetime, 'number': float,
        }
        self.assertIn('openapi', self.swagger)
        self.assertEqual(self.swagger['openapi'], '3.0.3')
        self.assertIn('paths', self.swagger)
        for endpoint, end_data in self.swagger['paths'].items():
            for operator, op_data in end_data.items():
                # Ignore parameter definition in endpoint
                if operator in ('parameters',):
                    continue
                if 'parameters' not in op_data:
                    continue
                for param_data in op_data['parameters']:
                    self.assertIn(
                        'schema', param_data,
                        f"Param {param_data['name']} has no schema?"
                    )
                    schema = param_data['schema']
                    self.assertIn(
                        'type', schema,
                        f"Param {param_data['name']} schema has no type?"
                    )
                    if 'default' not in schema:
                        continue
                    default = schema['default']
                    # If we've got a list parameter, then check that we've
                    # got a list as the default.  Then check it's item type.
                    if schema['type'] == 'array':
                        self.assertIsInstance(
                            default, list,
                            f"The {param_data['name']} parameter in '{endpoint}' "
                            f"is defined with many=True, but the default value "
                            f"'{default}' is not a list"
                        )
                        self.assertIn('items', schema)
                        self.assertIsInstance(schema['items'], dict)
                        self.assertIn('type', schema['items'])
                        self.assertNotIn('enum', schema)
                        default = default[0]
                        expected_type = type_of_value.get(schema['items']['type'], str)
                    else:
                        expected_type = type_of_value.get(schema['type'], str)
                    self.assertIsInstance(
                        default, expected_type,
                        f"The {param_data['name']} parameter in '{endpoint}' "
                        f"is defined as type {schema['type']}, which maps to a "
                        f"{expected_type}, but the default parameter "
                        f"'{default}' is of type '{type(default)}'"
                    )

    def test_stats_views_take_parameters(self):
        # Test for problems in schema generation where
        # stats endpoints don't have parameters
        for stats_view in ('reports', 'rules', 'systems'):
            path = f"/api/insights/v1/stats/{stats_view}/"
            op = self.swagger['paths'][path]['get']
            self.assertIn('parameters', op)

    def test_regex_parameters_have_pattern(self):
        # Test for problem in schema generation where
        # regex parameters don't have patterns
        for path, methods in self.swagger['paths'].items():
            for method, op_dict in methods.items():
                if 'parameters' not in method:
                    continue
                for param in method['parameters']:
                    schema = param['schema']
                    if schema['type'] == 'string' and 'format' in schema and schema['format'] == 'regex':
                        self.assertIn('pattern', schema)
                    if schema['type'] == 'array' and schema['items']['type'] == 'string' and 'format' in schema['items'] and schema['items']['format'] == 'regex':
                        self.assertIn('pattern', schema['items'])

    def test_unique_operation_ids(self):
        seen_operation_ids = {}
        for endpoint, end_data in self.swagger['paths'].items():
            for operation, op_data in end_data.items():
                if operation == 'parameters':
                    continue
                this_id = op_data['operationId']
                desc = f"Endpoint '{endpoint}' operation '{operation}'"
                # Annoyingly, it's hard for us to narrow this down because
                # the message is evaluated before it goes into the assertNotIn
                # call, which means that we get a KeyError because of course
                # most of the time the operation Id isn't in there...
                self.assertNotIn(
                    this_id, seen_operation_ids,
                )
                # The death-by-assert means we only ever get new opIds.
                seen_operation_ids[this_id] = [desc]

    def test_system_detail_reports_lists_unpaginated(self):
        for endpoint, end_data in self.swagger['paths'].items():
            if not ('/system/{uuid}/' in endpoint and 'reports/' in endpoint):
                continue
            for operation, op_data in end_data.items():
                self.assertIn('responses', op_data)
                self.assertIn('200', op_data['responses'])
                self.assertIn('content', op_data['responses']['200'])
                self.assertIn('application/json', op_data['responses']['200']['content'])
                self.assertIn('schema', op_data['responses']['200']['content']['application/json'])
                schema = op_data['responses']['200']['content']['application/json']['schema']
                # This would be '$ref': '#/components/schemas/PaginatedReportList'
                # in the old paginated schema
                self.assertNotIn('$ref', schema)
                # Instead this should be an array type referring to the
                # Report.
                self.assertIn('type', schema)
                self.assertEqual(schema['type'], 'array')
                self.assertIn('items', schema)
                self.assertIn('$ref', schema['items'])
                if operation == 'system_reports_list':
                    self.assertEqual(
                        schema['items']['$ref'], '#/components/schemas/Report'
                    )

    def test_list_views_are_paginated(self):
        ignore_entirely = {
            '/api/insights/v1/status/',
            '/api/insights/v1/status/live/', '/api/insights/v1/status/ready/',
        }
        for endpoint, end_data in self.swagger['paths'].items():
            if endpoint in ignore_entirely:
                continue
            if '{' in endpoint:
                # Detail endpoints have a parameter - not list views
                continue
            self.assertIn('get', end_data)
            list_ep = end_data['get']
            self.assertIn('responses', list_ep)
            self.assertIn(
                '200', list_ep['responses'],
                f"Endpoint {endpoint} does not have a 200 response"
            )
            self.assertIn(
                'content', list_ep['responses']['200'],
                f"Endpoint {endpoint} does not have a content response"
            )
            self.assertIn('application/json', list_ep['responses']['200']['content'])
            self.assertIn('schema', list_ep['responses']['200']['content']['application/json'])
            ep_schema = list_ep['responses']['200']['content']['application/json']['schema']
            # This is probably a reference to a component schema - just check that...
            if '$ref' not in ep_schema:
                continue
            self.assertTrue(ep_schema['$ref'].startswith('#/components/schemas/'))
            schema_name = ep_schema['$ref'].split('/')[3]
            self.assertIn(schema_name, self.swagger['components']['schemas'])
            response_schema = self.swagger['components']['schemas'][schema_name]
            if schema_name.startswith('Paginated'):
                # Finally, we can check that this obeys the pagination schema
                self.assertEqual(
                    response_schema['type'], 'object',
                    f"Endpoint {endpoint} response schema {schema_name} looks "
                    f"paginated but is not an object"
                )
                self.assertIn('properties', response_schema)
                self.assertIn('data', response_schema['properties'])
                self.assertIn('meta', response_schema['properties'])
                self.assertEqual(response_schema['properties']['data']['type'], 'array')
                self.assertEqual(response_schema['properties']['meta']['type'], 'object')
            elif schema_name == 'Stats':
                self.assertEqual(
                    response_schema['type'], 'object',
                    f"Endpoint {endpoint} response schema {schema_name} looks "
                    f"like a stats object but is not an object"
                )
                # Stats endpoints are 'special'
                self.assertIn('properties', response_schema)
                self.assertNotIn('data', response_schema['properties'])
                self.assertNotIn('meta', response_schema['properties'])
            else:
                # Unpaginated lists should just be a list
                self.assertEqual(
                    response_schema['type'], 'list',
                    f"Endpoint {endpoint} response schema {schema_name} looks "
                    f"unpaginated but is not a list"
                )

    @responses.activate
    def test_schema_has_docs_with_rbac(self):
        TEST_RBAC_URL = 'http://docs-rbac.svc'
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json={'data': [{'permission': 'advisor:*:*'}]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            # Need to have authentication information, but not internal_user,
            # so we actually make a request to RBAC...
            response = self.client.get(
                reverse(self.schema_path_name), HTTP_ACCEPT=constants.json_mime,
                **auth_header_for_testing()
            )
            swagger = response.json()
            self.assertIn('info', swagger)
            self.assertIn('title', swagger['info'])
            self.assertNotEqual(swagger['info']['title'], '')
            self.assertIn('description', swagger['info'])
            self.assertNotEqual(swagger['info']['description'], '')
            self.assertIn('version', swagger['info'])
            self.assertNotEqual(swagger['info']['version'], '')
            self.assertIn('paths', swagger)
            self.assertIsInstance(swagger['paths'], dict)
            paths = swagger['paths']
            prefix = '/' + settings.API_PATH_PREFIX
            # All paths should be found due to SERVE_PUBLIC=True
            for normal_path in (
                'rule/', 'system/', 'ack/', 'rule/{rule_id}/ack_hosts/',
                'ackcount/', 'rule/{rule_id}/stats/',
                'rating/all_ratings/', 'rating/stats/',
            ):
                self.assertIn(
                    prefix + normal_path, paths.keys(),
                    f'access to {normal_path} should be allowed for a regular user'
                )
        # RBAC hasn't been called here because SERVE_PUBLIC=True bypasses
        # all permissions checks
        self.assertEqual(len(responses.calls), 0)

    @responses.activate
    def test_schema_has_is_internal_views(self):
        TEST_RBAC_URL = 'http://docs-rbac.svc'
        responses.add(
            responses.GET, TEST_RBAC_URL,
            json={'data': [{'permission': 'advisor:*:*'}]}, status=200
        )
        with self.settings(RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True):
            # Need to have authentication information, but not test_user,
            # so we actually make a request to RBAC because permissions
            # caches RBAC responses on username and account...
            response = self.client.get(
                reverse(self.schema_path_name), HTTP_ACCEPT=constants.json_mime,
                **auth_header_for_testing(
                    username='other_test_account', user_opts={'is_internal': True}
                )
            )
            swagger = response.json()
            paths = swagger['paths']
            # We should have paths that only internal users can see:
            for auth_reqd_path in (
                'ackcount/',
                'rule/{rule_id}/ack_hosts/', 'rule/{rule_id}/stats/',
                'rating/all_ratings/', 'rating/stats/',
            ):
                self.assertIn(
                    '/' + settings.API_PATH_PREFIX + auth_reqd_path, paths.keys(),
                    f'{auth_reqd_path} should be seen by an internal user',
                )
            # But we should have got paths we expect to see
            for normal_path in (
                'rule/', 'system/', 'ack/',
            ):
                self.assertIn(
                    '/' + settings.API_PATH_PREFIX + normal_path, paths.keys(),
                    f'access to {normal_path} should be allowed for an internal user'
                )
        # RBAC hasn't been called here because SERVE_PUBLIC=True bypasses
        # all permissions checks
        self.assertEqual(len(responses.calls), 0)


class OpenAPI3SchemaValidation(ApiDocsTestCaseClass):
    def test_openapi_3_schema_validation(self):
        self.assertIsNone(validate_spec(self.swagger))
        # Test that URL is where and what we expect:
        # DRF Spectacular does not fill this in automatically, and I'm not
        # sure that we want to fill this in for local tests...
        # self.assertIn('servers', self.swagger)
        # self.assertIsInstance(self.swagger['servers'], list)
        # for server in self.swagger['servers']:
        #     self.assertIn('url', server)
        #     self.assertEqual(server['url'], 'http://testserver/api/insights/v1')


class PlatformPathTestCase(TestCase):
    """
    While the API should only advertise the standard API prefix
    (api/insights/v1), we also want to make sure it responsed to the platform
    prefix paths (r/insights/platform/insights/v1).
    """
    fixtures = ['rulesets']

    def test_paths(self):
        # We should be able to get a range of data, with credentials, via
        # the platform path
        for suffix in ('', 'rule/', 'stats/rules/', 'system/'):
            response = self.client.get(
                '/' + settings.PLATFORM_PATH_PREFIX + suffix,
                **auth_header_for_testing(user_opts={'is_internal': True})
            )
            self.assertEqual(response.status_code, 200)
