from .._util import ConversionUtil as ConversionUtil
from ._acl import AclOperation as AclOperation
from _typeshed import Incomplete

class DescribeClusterResult:
    cluster_id: Incomplete
    controller: Incomplete
    nodes: Incomplete
    authorized_operations: Incomplete
    def __init__(self, controller, nodes, cluster_id=None, authorized_operations=None) -> None: ...
