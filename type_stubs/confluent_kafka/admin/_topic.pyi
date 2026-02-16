from .._util import ConversionUtil as ConversionUtil
from ._acl import AclOperation as AclOperation
from _typeshed import Incomplete

class TopicDescription:
    name: Incomplete
    topic_id: Incomplete
    is_internal: Incomplete
    partitions: Incomplete
    authorized_operations: Incomplete
    def __init__(self, name, topic_id, is_internal, partitions, authorized_operations=None) -> None: ...
