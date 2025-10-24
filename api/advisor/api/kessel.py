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
import time
from types import SimpleNamespace
from typing import Generator, Optional, Tuple
from uuid import UUID

from kessel.auth import fetch_oidc_discovery, OAuth2ClientCredentials
from kessel.inventory.v1beta2 import (
    ClientBuilder,
    allowed_pb2,
    check_request_pb2,
    inventory_service_pb2_grpc,
    representation_type_pb2,
    request_pagination_pb2,
    resource_reference_pb2,
    reporter_reference_pb2,
    streamed_list_objects_request_pb2,
    streamed_list_objects_response_pb2,
    subject_reference_pb2
)

from django.conf import settings

from advisor_logging import logger

#############################################################################
# Data classes and definitions
#############################################################################

ALLOWED = allowed_pb2.ALLOWED_TRUE
DENIED = allowed_pb2.ALLOWED_FALSE
# Unspecified is treated as denied here.

type Relation = str

# Is this needed?
host_object_type = representation_type_pb2.RepresentationType(
    resource_type="host",
    reporter_type="hbi",
)
workspace_object_type = representation_type_pb2.RepresentationType(
    resource_type="workspace",
    reporter_type="rbac",
)


@dataclass
class ResourceRef:
    resource_id: str
    resource_type: str
    reporter_type: str

    def as_pb2(self):
        return resource_reference_pb2.ResourceReference(
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            reporter=reporter_reference_pb2.ReporterReference(type=self.reporter_type)
        )

    def __repr__(self):
        return f"ResourceRef({self.resource_id}, {self.resource_type})"


@dataclass
class SubjectRef:
    resource_id: str
    resource_type: str

    def as_pb2(self):
        return subject_reference_pb2.SubjectReference(
            resource=ResourceRef(self.resource_id, self.resource_type, "rbac").as_pb2()
        )

    def __repr__(self):
        return f"SubjectRef({self.resource_id}, {self.resource_type})"


@dataclass(frozen=True)
class Workspace:
    value: str

    def to_ref(self) -> ResourceRef:
        return ResourceRef(self.value, "workspace", "rbac")


@dataclass(frozen=True)
class Host:
    value: str

    def to_ref(self) -> ResourceRef:
        return ResourceRef(self.value, "host", "hbi")


#############################################################################
# Streaming resource request/response handling
#############################################################################

# Hopefully at some stage we can just import these from the Kessel SDK.
def get_resources(
    client_stub: inventory_service_pb2_grpc.KesselInventoryServiceStub,
    object_type: representation_type_pb2.RepresentationType,
    relation: str,
    subject: subject_reference_pb2.SubjectReference,
    limit: int = 20,
    fetch_all=True
) -> Generator[
    resource_reference_pb2.ResourceReference, None, None
]:
    """
    Get a continuous stream of the object type this subject has this relation
    to.  Works around the inherent pagination and continuation token handling.

    Object type and subject are the PB2 representations, so your code can
    translate from your own internal representation.

    E.g.:

    >>> get_resources(
            client, Workspace('default').as_pb2(), 'member', this_user.as_pb2()
        )
    generator object (...)

    """
    # logger.debug(f"Get resources({object_type}, {relation}, {subject})")
    continuation_token = None
    while (response := _get_resource_page(
        client_stub, object_type, relation, subject, limit, continuation_token
    )) is not None:
        logger.debug("Got resource page response %s", response)
        last_data = None
        for data in response:
            yield data.object
            last_data = data
        if not fetch_all:
            # We only want the first page
            break
        # Extract continuation token from the last item in the response
        # If response was empty, there's no next page
        if last_data is None:
            break
        continuation_token = last_data.pagination.continuation_token
        if not continuation_token:
            # Could just make another request and then get told no more pages,
            # but it's neater this way...
            break


def _get_resource_page(
    client_stub: inventory_service_pb2_grpc.KesselInventoryServiceStub,
    object_type: representation_type_pb2.RepresentationType,
    relation: str,
    subject: subject_reference_pb2.SubjectReference,
    limit: int,
    continuation_token: Optional[str] = None
) -> streamed_list_objects_response_pb2.StreamedListObjectsResponse:
    """
    Get a single page, of at most limit size, from continuation_token (or
    start if None).
    """
    logger.debug(f"Get resource page({object_type}, {relation}, {subject}, {limit})")
    request = streamed_list_objects_request_pb2.StreamedListObjectsRequest(
        object_type=object_type,  # already a PB2 object
        relation=relation,
        subject=subject,
        pagination=request_pagination_pb2.RequestPagination(
            limit=limit,
            continuation_token=continuation_token
        )
    )

    return client_stub.StreamedListObjects(request)


#############################################################################
# Test decorator
#############################################################################

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
            # logger.debug(f"Adding permission check response for {check} = {response}")
            client.client.add_permission_check_response(check, response)
        for resource, response in self.temporary_resource_lookups:
            # logger.debug(f"Adding resource lookup response for {resource} = {response}")
            client.client.add_lookup_resources_response(resource, response)

    def __exit__(self, exc_type, exc_val, exc_tb):
        for check, _ in self.temporary_permission_checks:
            client.client.del_permission_check_response(check)
        for resource, _ in self.temporary_resource_lookups:
            client.client.del_lookup_resources_response(resource)
        return False  # or context manager raises exception

    def __call__(self, fn):
        def wrapper(*args, **kwargs):
            with self:
                fn(*args, **kwargs)
        return wrapper


#############################################################################
# The test client
#############################################################################

class TestClient(inventory_service_pb2_grpc.KesselInventoryServiceStub):
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
        self, subject: SubjectRef, response_ids: list[UUID]
    ) -> None:
        """
        When the host groups this user subject can access is requested, return
        this list of host groups by UUID.  At this stage we only look up
        the workspaces the user has the 'member' relationship to, so we treat
        the 'relation' and 'object type' being searched for here as static.
        If we need to more lookups, the things handed in here will need to be
        more complex.
        """
        lookup_str = str(subject)
        response_objs = [
            SimpleNamespace(
                object=SimpleNamespace(resource_id=response_id),
                pagination=SimpleNamespace(
                    continuation_token=None
                )
            )
            for response_id in response_ids
        ]
        self.lookup_resources_responses[lookup_str] = response_objs

    def del_permission_check_response(self, check: check_request_pb2.CheckRequest):
        """
        Delete the associated response for this permission
        """
        check_str = str(check)
        del self.permission_check_responses[check_str]

    def del_lookup_resources_response(self, subject: SubjectRef):
        """
        Delete the associated response for this permission
        """
        lookup_str = str(subject)
        del self.lookup_resources_responses[lookup_str]

    def Check(self, check: check_request_pb2.CheckRequest) -> object:
        """
        Attempt the permission check, or raise a failure?
        """
        check_str = str(check)
        # We should be checking this when we've been given an override, so
        # permission_check_responses should not be empty.
        # logger.info(f"Check faked for {check_str}")
        if check_str in self.permission_check_responses:
            return self.permission_check_responses[check_str]
        else:
            raise NotImplementedError(f"Response for request {check_str} not implemented")

    def StreamedListObjects(
        self, request: streamed_list_objects_request_pb2.StreamedListObjectsRequest
    ) -> list[UUID]:
        """
        Find all resources for the given request.  Because at the moment we
        don't really search for anything other than 'which workspaces is a
        given user a member of?' we just use the subject of the request.
        """
        subject = request.subject  # (type coversion?)
        subject_str = str(subject)
        if subject_str in self.lookup_resources_responses:
            return self.lookup_resources_responses[subject_str]
        else:
            raise NotImplementedError(f"Response for lookup {subject_str} not implemented")


#############################################################################
# The interface we provide to the rest of our code.
#############################################################################


class Kessel:
    """
    A wrapper around the gRPC Kessel Inventory service.
    """

    def __init__(self) -> None:
        """
        Use the TestClient to allow 'interception' of requests during
        testing.
        """
        # We assume here that the host name 'device under test' means that we
        # only allow access via the TestClient.
        if settings.KESSEL_URL == 'device under test':
            self.client = TestClient()
        else:
            logger.info(
                "Connecting to Kessel via server url %s",
                settings.KESSEL_URL
            )
            builder = ClientBuilder(settings.KESSEL_URL)
            if settings.KESSEL_INSECURE:
                builder.insecure()
            elif settings.KESSEL_AUTH_ENABLED:
                discovery = fetch_oidc_discovery(settings.KESSEL_AUTH_OIDC_ISSUER)
                credentials = OAuth2ClientCredentials(
                    client_id=settings.KESSEL_AUTH_CLIENT_ID,
                    client_secret=settings.KESSEL_AUTH_CLIENT_SECRET,
                    token_endpoint=discovery.token_endpoint
                )
                builder.oauth2_client_authenticated(credentials)
            else:
                builder.unauthenticated()

            self.client, _ = builder.build()

            logger.info("Connected to Kessel, client %s", self.client)

    def check(
        self, resource: ResourceRef, relation: Relation, subject: SubjectRef
    ) -> Tuple[bool, float]:
        start = time.time()
        logger.info(
            "Checking resource %s with relation %s for subject %s",
            resource, relation, subject
        )
        response = self.client.Check(
            check_request_pb2.CheckRequest(
                subject=subject.as_pb2(),
                relation=relation,
                object=resource.as_pb2(),
            )
        )
        # Note: we treat 'UNSPECIFIED' as 'DENIED' for security.
        result = (response.allowed == ALLOWED)
        return result, time.time() - start

    def host_groups_for(
        self, subject: SubjectRef
    ) -> Tuple[bool, float]:
        """
        There may be other uses of get_resources, but at the moment the only
        one we care about is the host groups for this user.
        """
        start = time.time()
        logger.info(
            "Getting host groups for subject %s", subject
        )
        result = [
            response_object.resource_id
            for response_object in get_resources(
                self.client, workspace_object_type,
                'inventory_host_view', subject.as_pb2()
                # , limit=100?
            )
        ]

        logger.debug(
            "Getting host groups for subject - Result %s", result
        )

        return result, time.time() - start


client = Kessel()
