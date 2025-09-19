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

from dataclasses import dataclass
import grpc
import time
from types import SimpleNamespace
from typing import Tuple

from kessel.inventory.v1beta2 import (
    inventory_service_pb2_grpc,
    check_request_pb2,
    representation_type_pb2,
    resource_reference_pb2,
    reporter_reference_pb2,
    subject_reference_pb2,
)

from django.conf import settings

type Relation = str


# Is this needed?
host_object_type = representation_type_pb2.RepresentationType(
    resource_type="host",
    reporter_type="hbi",
)


@dataclass
class ResourceRef:
    resource_id: str
    resource_type: str

    def as_pb2(self):
        return resource_reference_pb2.ResourceReference(
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            reporter=reporter_reference_pb2.ReporterReference(type='rbac')
        )

    def __repr__(self):
        return f"ResourceRef({self.resource_id}, {self.resource_type})"


@dataclass
class SubjectRef:
    resource_id: str
    resource_type: str

    def as_pb2(self):
        return subject_reference_pb2.SubjectReference(
            resource=ResourceRef(self.resource_id, self.resource_type).as_pb2()
        )

    def __repr__(self):
        return f"SubjectRef({self.resource_id}, {self.resource_type})"


@dataclass(frozen=True)
class Workspace:
    value: str

    def to_ref(self) -> ResourceRef:
        return ResourceRef(self.value, "rbac.workspace")


@dataclass(frozen=True)
class Host:
    value: str

    def to_ref(self) -> ResourceRef:
        return ResourceRef(self.value, "hbi.host")


@dataclass(frozen=True)
class LookupResourcesRequest:
    subject: SubjectRef
    relation: Relation
    resource: ResourceRef


type Resource = Workspace | Host
type UserId = str


def identity_to_subject(identity: dict) -> SubjectRef:
    user_id = identity['user']['user_id']
    return SubjectRef(user_id, 'rbac/principal')


class add_kessel_response(object):
    """
    A context manager that inserts specific test data for permission checks
    and resource lookups into the test server, then remove them on exit.
    This also operates as a function or method decorator, thanks to the
    __call__ method.  Thanks, granite LLM, for teaching me this trick!
    """
    def __init__(self, permission_checks=[], resource_lookups=[]):
        """
        Each entry in these lists should be a tuple of (request, response).
        """
        self.temporary_permission_checks = permission_checks
        self.temporary_resource_lookups = resource_lookups

    def __enter__(self):
        # The client here is the Kessel object, its client is the
        # gRPC Client interface.
        for check, response in self.temporary_permission_checks:
            client.client.add_permission_check_response(check, response)
        for request, response in self.temporary_resource_lookups:
            client.client.add_lookup_resources_response(request, response)

    def __exit__(self, exc_type, exc_val, exc_tb):
        for check, _ in self.temporary_permission_checks:
            client.client.del_permission_check_response(check)
        for request, _ in self.temporary_resource_lookups:
            client.client.del_lookup_resources_response(request)
        return False  # or context manager raises exception

    def __call__(self, fn):
        def wrapper(*args, **kwargs):
            with self:
                fn(*args, **kwargs)
        return wrapper


class TestClient(object):
    """
    A gRPC client that can store up and then send responses to permission
    and resource lookup requests.  Based, very roughly, on the `responses`
    library for handling tests whose code uses `requests`.
    """

    def __init__(self) -> None:
        self.permission_check_responses = dict()
        self.lookup_resources_responses = dict()

    def add_permission_check_response(
        self, check: check_request_pb2.CheckRequest, response_int: int
    ) -> str:
        """
        When this permission is requested, send this response.
        The response integer is put in an object as the `permissionship`
        property, as a shortcut.
        """
        check_str = str(check)
        response_obj = SimpleNamespace(allowed=response_int)
        self.permission_check_responses[check_str] = response_obj
        return check_str

    def add_lookup_resources_response(
        self, lookup: LookupResourcesRequest, response_ids: list[int]
    ) -> None:
        """
        When this resource is looked up, send this response.
        The list of response integers is converted into a list of objects that
        have these as the `resource_object_id` property, as a shortcut.
        """
        lookup_str = str(lookup)
        response_objs = [
            SimpleNamespace(resource_object_id=response_id)
            for response_id in response_ids
        ]
        self.lookup_resources_responses[lookup_str] = response_objs

    def del_permission_check_response(self, check: check_request_pb2.CheckRequest):
        """
        Delete the associated response for this permission
        """
        check_str = str(check)
        del self.permission_check_responses[check_str]

    def del_lookup_resources_response(self, lookup: LookupResourcesRequest):
        """
        Delete the associated response for this permission
        """
        lookup_str = str(lookup)
        del self.lookup_resources_responses[lookup_str]

    def Check(self, check: check_request_pb2.CheckRequest) -> object:
        """
        Attempt the permission check, or raise a failure?
        """
        check_str = str(check)
        # this is faster for empty case than pure 'in' or try/except
        if self.permission_check_responses and check_str in self.permission_check_responses:
            # print(f"... Recognised test request, returning {self.permission_check_responses[request_str]}")
            return self.permission_check_responses[check_str]
        else:
            raise NotImplementedError(f"Response for request {check_str} not implemented")

    def LookupResources(self, request: LookupResourcesRequest) -> list:
        """
        Attempt the resource lookup, or raise a failure?
        """
        request_str = str(request)
        # print(f"LookupResources ({request})")
        if self.lookup_resources_responses and request_str in self.lookup_resources_responses:
            return self.lookup_resources_responses[request_str]
        else:
            raise NotImplementedError(f"Response for lookup {request_str} not implemented")


class Kessel:
    """
    A wrapper around the gRPC Kessel Inventory service.
    """

    def __init__(self) -> None:
        """
        Use the TestClient to allow 'interception' of requests during
        testing.
        """
        self.reporter = reporter_reference_pb2.ReporterReference(type="rbac")
        # We assume here that the host name 'device under test' means that we
        # only allow access via the TestClient.
        if settings.KESSEL_SERVER_NAME == 'device under test':
            self.client = TestClient()
        else:
            self.client = inventory_service_pb2_grpc.KesselInventoryServiceStub(
                grpc.insecure_channel(
                    f"{settings.KESSEL_SERVER_NAME}:{settings.KESSEL_SERVER_PORT}",
                    settings.KESSEL_SERVER_PASSWORD
                )
            )

    def check(
        self, resource: ResourceRef, relation: Relation, subject: SubjectRef
    ) -> Tuple[bool, float]:
        start = time.time()
        response = self.client.Check(
            check_request_pb2.CheckRequest(
                subject=subject.as_pb2(),
                relation=relation,
                object=resource.as_pb2(),
            )
        )
        result = response.allowed
        return result, time.time() - start

    def lookupResources(
        self, resource: ResourceRef, relation: Relation, subject: SubjectRef
    ) -> Tuple[bool, float]:
        start = time.time()
        responses = self.client.LookupResources(LookupResourcesRequest(
            subject=subject.as_pb2(),
            relation=relation,
            object=resource.as_pb2(),
        ))
        result = [response.resource_object_id for response in responses]
        return result, time.time() - start


client = Kessel()
