from .._model import ConsumerGroupState as ConsumerGroupState, ConsumerGroupType as ConsumerGroupType
from .._util import ConversionUtil as ConversionUtil
from ._acl import AclOperation as AclOperation
from _typeshed import Incomplete

class ConsumerGroupListing:
    group_id: Incomplete
    is_simple_consumer_group: Incomplete
    state: Incomplete
    type: Incomplete
    def __init__(self, group_id, is_simple_consumer_group, state=None, type=None) -> None: ...

class ListConsumerGroupsResult:
    valid: Incomplete
    errors: Incomplete
    def __init__(self, valid=None, errors=None) -> None: ...

class MemberAssignment:
    topic_partitions: Incomplete
    def __init__(self, topic_partitions=[]) -> None: ...

class MemberDescription:
    member_id: Incomplete
    client_id: Incomplete
    host: Incomplete
    assignment: Incomplete
    target_assignment: Incomplete
    group_instance_id: Incomplete
    def __init__(self, member_id, client_id, host, assignment, group_instance_id=None, target_assignment=None) -> None: ...

class ConsumerGroupDescription:
    group_id: Incomplete
    is_simple_consumer_group: Incomplete
    members: Incomplete
    authorized_operations: Incomplete
    partition_assignor: Incomplete
    state: Incomplete
    type: Incomplete
    coordinator: Incomplete
    def __init__(self, group_id, is_simple_consumer_group, members, partition_assignor, state, coordinator, authorized_operations=None, type=...) -> None: ...
