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

import responses
from uuid import UUID

from project_settings import kafka_settings as kafka_settings
from django.test import TestCase, override_settings

from api.permissions import auth_header_for_testing
from tasks.management.commands.tasks_service import handle_sources_event
from tasks.models import SatelliteRhc


def rhc_source_message():
    return {
        "id": "1",
        "rhc_id": "52321130-c0d6-11ec-a1f5-abea1b2200b3",
        "extra": None,
        "availability_status": None,
        "last_checked_at": None,
        "last_available_at": None,
        "availability_status_error": "",
        "source_ids": [147],
        "created_at": "2022-04-20 13:18:47 UTC",
        "updated_at": "2022-04-20 13:18:47 UTC"
    }


def satellite_source_message():
    return {
        "availability_status": None,
        "last_checked_at": None,
        "last_available_at": None,
        "id": 147,
        "created_at": "2022-04-20 13:17:59 CDT",
        "updated_at": "2022-04-20 13:17:59 CDT",
        "paused_at": None,
        "name": "demo test2",
        "uid": "f243386e-d59d-4f24-bad8-04e24d0c4b14",
        "version": None,
        "imported": None,
        "source_ref": "357b7360-c0d6-11ec-a1f5-abea1b2200b3",
        "app_creation_workflow": "manual_configuration",
        "source_type_id": 13,
        "tenant": ""
    }


def source_types_reply():
    return {
        "data": [
            {
                "id": "13",
                "created_at": "2020-01-29T14:54:12Z",
                "updated_at": "2022-06-15T17:41:08Z",
                "category": "Red Hat",
                "name": "satellite",
                "product_name": "Red Hat Satellite",
                "vendor": "Red Hat",
                "schema": {
                    "endpoint": {
                        "title": "Red Hat Satellite endpoint",
                        "fields": [
                            {
                                "name": "endpoint.receptor_node",
                                "label": "Receptor ID",
                                "component": "text-field"
                            },
                            {
                                "name": "endpoint.role",
                                "component": "text-field",
                                "hideField": True,
                                "initialValue": "satellite",
                                "initializeOnMount": True
                            }
                        ]
                    },
                    "authentication": [
                        {
                            "name": "Receptor node",
                            "type": "receptor_node",
                            "fields": [
                                {
                                    "name": "authentication.authtype",
                                    "component": "text-field",
                                    "hideField": True,
                                    "initialValue": "receptor_node",
                                    "initializeOnMount": True
                                },
                                {
                                    "name": "source.source_ref",
                                    "label": "Satellite ID",
                                    "validate": [
                                        {
                                            "type": "required"
                                        }
                                    ],
                                    "component": "text-field",
                                    "isRequired": True
                                }
                            ]
                        }
                    ]
                },
                "icon_url": "/apps/frontend-assets/platform-logos/satellite.svg"
            }
        ],
        "meta": {
            "count": 1,
            "limit": 100,
            "offset": 0
        },
        "links": {
            "first": "/api/sources/v3.1/source_types?filter[name]=satellite&limit=100&offset=0",
            "last": "/api/sources/v3.1/source_types?filter[name]=satellite&limit=100&offset=100"
        }
    }


@override_settings(SOURCES_API_URL='http://localhost')
class TaskSatTrackingTestCase(TestCase):
    fixtures = ['basic_task_test_data']
    std_auth = auth_header_for_testing()

    def mock_sources_api(self, api_reponse):
        responses.get(
            'http://localhost/api/sources/v3.1/source_types?filter[name]=satellite', status=200,
            json=api_reponse
        )

    def setUp(self):
        self.mock_sources_api(source_types_reply())

    @responses.activate
    def test_correlate_satellite_to_rhc(self):
        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, satellite_source_message())
        sr = SatelliteRhc.objects.get(instance_id='357b7360-c0d6-11ec-a1f5-abea1b2200b3')
        self.assertEqual(sr.instance_id, UUID('357b7360-c0d6-11ec-a1f5-abea1b2200b3'))
        self.assertEqual(sr.source_id, 147)
        self.assertIsNone(sr.rhc_client_id)

        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, rhc_source_message())
        sr = SatelliteRhc.objects.get(instance_id='357b7360-c0d6-11ec-a1f5-abea1b2200b3')
        self.assertEqual(sr.instance_id, UUID('357b7360-c0d6-11ec-a1f5-abea1b2200b3'))
        self.assertEqual(sr.source_id, 147)
        self.assertEqual(sr.rhc_client_id, UUID('52321130-c0d6-11ec-a1f5-abea1b2200b3'))

    @responses.activate
    def test_skip_non_uuid_satellite(self):
        """ A lot of people put test data in the sources service that do not correlate to real satellites.
        This ensures we skip sources with non uuid source refs, instead of generating thousands of error logs."""
        message = satellite_source_message()
        message['source_ref'] = 'bogus non uuid'
        # The test is that no exception is raised - so no error is generated.
        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, message)

    @responses.activate
    def test_update_satellite_source_id(self):
        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, satellite_source_message())
        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, rhc_source_message())

        sr = SatelliteRhc.objects.get(instance_id='357b7360-c0d6-11ec-a1f5-abea1b2200b3')
        self.assertEqual(sr.source_id, 147)
        self.assertEqual(sr.rhc_client_id, UUID('52321130-c0d6-11ec-a1f5-abea1b2200b3'))

        message_new_id = satellite_source_message()
        message_new_id['id'] = 1337

        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, message_new_id)
        sr = SatelliteRhc.objects.get(instance_id='357b7360-c0d6-11ec-a1f5-abea1b2200b3')
        self.assertEqual(sr.source_id, 1337)
        self.assertEqual(sr.rhc_client_id, UUID('52321130-c0d6-11ec-a1f5-abea1b2200b3'))

    @responses.activate
    def test_non_satellite_source_type(self):
        message_new_source_id = satellite_source_message()
        message_new_source_id['source_type_id'] = -1
        handle_sources_event(kafka_settings.WEBHOOKS_TOPIC, message_new_source_id)

        sr_count = SatelliteRhc.objects.filter(instance_id='357b7360-c0d6-11ec-a1f5-abea1b2200b3').count()
        self.assertEqual(sr_count, 0)
