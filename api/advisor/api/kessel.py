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
    resource_reference_pb2,
    reporter_reference_pb2,
    subject_reference_pb2,
)

from django.conf import settings

from api.permissions import RBACPermission

type Relation = str


@dataclass
class ObjectType:
    namespace: str
    name: str

    def to_zed(self):
        return f"{self.namespace}/{self.name}"


@dataclass
class ObjectRef:
    type: ObjectType
    id: str

    def as_subject(self, relation: Relation | None = None):
        return SubjectRef(self, subject_relation=relation)

    def to_zed(self):
        return zed.ObjectReference(
            object_type=self.type.to_zed(),
            object_id=self.id
        )


@dataclass
class SubjectRef:
    object: ObjectRef
    subject_relation: Relation | None = None

    def to_zed(self):
        return zed.SubjectReference(
            object=self.object.to_zed(),
            optional_relation=self.subject_relation if self.subject_relation is not None else ""
        )


@dataclass(frozen=True)
class WorkspaceId:
    value: str

    def to_ref(self) -> ObjectRef:
        return ObjectRef(ObjectType("rbac", "workspace"), self.value)


@dataclass(frozen=True)
class OrgId:
    value: str

    def to_ref(self) -> ObjectRef:
        return ObjectRef(ObjectType("rbac", "tenant"), f"localhost/{self.value}")


@dataclass(frozen=True)
class HostId:
    value: str

    def to_ref(self) -> ObjectRef:
        return ObjectRef(ObjectType("hbi", "host"), self.value)


type Resource = WorkspaceId | OrgId | HostId
type UserId = str
type Permission = str


class add_zed_response(object):
    """
    A context manager that inserts specific test data for permission checks
    and resource lookups into the test Zed server, then remove them on exit.
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
        # TestZedClient interface.
        for request, response in self.temporary_permission_checks:
            client.client.add_permission_check_response(request, response)
        for request, response in self.temporary_resource_lookups:
            client.client.add_lookup_resources_response(request, response)

    def __exit__(self, exc_type, exc_val, exc_tb):
        for request, _ in self.temporary_permission_checks:
            client.client.del_permission_check_response(request)
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
    An gRPC client that can store up and then send responses to permission
    and resource lookup requests.  Based, very roughly, on the `responses`
    library for handling tests whose code uses `requests`.
    """

    def __init__(self) -> None:
        self.permission_check_responses = dict()
        self.lookup_resources_responses = dict()

    def add_permission_check_response(
        self, permission: check_request_pb2.CheckRequest, response_int: int
    ) -> None:
        """
        When this permission is requested, send this response.
        The response integer is put in an object as the `permissionship`
        property, as a shortcut.
        """
        request_str = str(permission)
        response_obj = SimpleNamespace(permissionship=response_int)
        self.permission_check_responses[request_str] = response_obj
        return request_str

    def add_lookup_resources_response(
        self, lookup: zed.LookupResourcesRequest, response_ids: list[int]
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

    def del_permission_check_response(self, permission: check_request_pb2.CheckRequest):
        """
        Delete the associated response for this permission
        """
        request_str = str(permission)
        del self.permission_check_responses[request_str]

    def del_lookup_resources_response(self, lookup: zed.LookupResourcesRequest):
        """
        Delete the associated response for this permission
        """
        lookup_str = str(lookup)
        del self.lookup_resources_responses[lookup_str]

    def Check(self, request: check_request_pb2.CheckRequest) -> object:
        """
        Attempt the permission check, or raise a failure?
        """
        request_str = str(request)
        # print(f"CheckPermission ({request})")
        # this is faster for empty case than pure 'in' or try/except
        if self.permission_check_responses and request_str in self.permission_check_responses:
            # print(f"... Recognised test request, returning {self.permission_check_responses[request_str]}")
            return self.permission_check_responses[request_str]
        else:
            raise NotImplementedError(f"Response for request {request_str} not implemented")

    def LookupResources(self, request: zed.LookupResourcesRequest) -> list:
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

    PERMISSIONSHIP_HAS_PERMISSION = zed.CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION

    def __init__(self) -> None:
        """
        Use the TestClient to allow 'interception' of requests during
        testing.
        """
        self.reporter = reporter_reference_pb2.ReporterReference(type="rbac")
        # We assume here that the host name 'device under test' means that we
        # only allow access via the TestZedClient.
        if settings.KESSEL_SERVER_NAME == 'device under test':
            self.client = TestClient()
        else:
            self.client = inventory_service_pb2_grpc.KesselInventoryServiceStub(
                grpc.insecure_channel(
                    f"{settings.KESSEL_SERVER_NAME}:{settings.KESSEL_SERVER_PORT}",
                    settings.KESSEL_SERVER_PASSWORD
                )
            )

    def check(self, resource: ObjectRef, relation: Relation, subject: SubjectRef) -> Tuple[bool, float]:
        start = time.time()
        subject_ref = subject_reference_pb2.SubjectReference(
            resource=resource_reference_pb2.ResourceReference(
                reporter=self.reporter,
                resource_id=subject.identity.user_id,
                resource_type="principal"
            ),
        )
        resource_ref = resource_reference_pb2.ResourceReference(
            reporter=self.reporter,
            resource_id=resource,
            resource_type="workspace"
        )
        response = self.client.Check(
            check_request_pb2.CheckRequest(
                subject=subject_ref,
                relation=relation,
                object=resource_ref,
            )
        )
        result = response.allowed
        return result, time.time() - start

    def lookupResources(self, resource_type: ObjectType, relation: Relation, subject: SubjectRef):
        start = time.time()
        zed_r_type = resource_type.to_zed()
        zed_subject = subject.to_zed()
        responses = self.client.LookupResources(zed.LookupResourcesRequest(
            resource_object_type=zed_r_type,
            permission=relation,
            subject=zed_subject,
        ))
        result = [response.resource_object_id for response in responses]
        return result, time.time() - start

    def put_workspace(self, workspace: WorkspaceId, parent: WorkspaceId | OrgId):
        self._write_tuple(workspace.to_ref(), "parent", parent.to_ref().as_subject())

    def put_host_in_workspace(self, host: HostId, workspace: WorkspaceId):
        self._write_tuple(host.to_ref(), "workspace", workspace.to_ref().as_subject())

    def grant_access_to_org(self, user: UserId, permission: Permission, orgs: list[str]):
        # Create a dummy role for the permission
        perm_model = RBACPermission(permission)
        perm_relation = rbac_permission_to_relation(perm_model)
        self._write_tuple(
            # Reuse the relation as the role id for simplicity
            ObjectRef(type=ObjectType("rbac", "role"), id=perm_relation),
            perm_relation,
            SubjectRef(ObjectRef(type=ObjectType("rbac", "principal"), id="*"))
        )

        # Create a role binding for the role and user
        self._write_tuple(
            ObjectRef(type=ObjectType("rbac", "role_binding"), id=f"{perm_relation}/{user}"),
            "subject",
            SubjectRef(ObjectRef(type=ObjectType("rbac", "principal"), id=user))
        )
        self._write_tuple(
            ObjectRef(type=ObjectType("rbac", "role_binding"), id=f"{perm_relation}/{user}"),
            "role",
            SubjectRef(ObjectRef(type=ObjectType("rbac", "role"), id=perm_relation))
        )

        # Bind it to orgs
        for org in orgs:
            self._write_tuple(
                OrgId(org).to_ref(),
                "binding",
                SubjectRef(ObjectRef(type=ObjectType("rbac", "role_binding"), id=f"{perm_relation}/{user}"))
            )

    def grant_access_to_workspace(self, user: UserId, permission: Permission, workspaces: list[str] = []):
        # Create a dummy role for the permission
        perm_model = RBACPermission(permission)
        perm_relation = rbac_permission_to_relation(perm_model)
        self._write_tuple(
            # Reuse the relation as the role id for simplicity
            ObjectRef(type=ObjectType("rbac", "role"), id=perm_relation),
            perm_relation,
            SubjectRef(ObjectRef(type=ObjectType("rbac", "principal"), id="*"))
        )

        # Create a role binding for the role and user
        self._write_tuple(
            ObjectRef(type=ObjectType("rbac", "role_binding"), id=f"{perm_relation}/{user}"),
            "subject",
            SubjectRef(ObjectRef(type=ObjectType("rbac", "principal"), id=user))
        )
        self._write_tuple(
            ObjectRef(type=ObjectType("rbac", "role_binding"), id=f"{perm_relation}/{user}"),
            "role",
            SubjectRef(ObjectRef(type=ObjectType("rbac", "role"), id=perm_relation))
        )

        # Bind it to workspaces
        for workspace in workspaces:
            self._write_tuple(
                WorkspaceId(workspace).to_ref(),
                "binding",
                SubjectRef(ObjectRef(type=ObjectType("rbac", "role_binding"), id=f"{perm_relation}/{user}"))
            )
        # todo: if no workspace, bind to default ws

    def _write_tuple(self, resource: ObjectRef, relation: Relation, subject: SubjectRef):
        self.client.WriteRelationships(zed.WriteRelationshipsRequest(
            updates=[
                zed.RelationshipUpdate(
                    operation=zed.RelationshipUpdate.Operation.OPERATION_TOUCH,
                    relationship=zed.Relationship(
                        resource=resource.to_zed(),
                        relation=f't_{relation}',
                        subject=subject.to_zed()
                    )
                ),
                # TOOD: also need to remove other relationship if moving,
                # but this wouldn't be needed with kessel
            ]
        ))


def rbac_permission_to_relation(permission: RBACPermission) -> Relation:
    return f"{permission.app}_{permission.resource}_{permission.method}".replace("*", "all").replace('-', '_')


def identity_to_subject(identity: dict) -> SubjectRef:
    user_id = identity['user']['user_id']
    return SubjectRef(ObjectRef(ObjectType("rbac", "principal"), user_id))


client = Kessel()
