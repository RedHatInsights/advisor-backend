from _typeshed import Incomplete

class ClusterMetadata:
    cluster_id: Incomplete
    controller_id: int
    brokers: Incomplete
    topics: Incomplete
    orig_broker_id: int
    orig_broker_name: Incomplete
    def __init__(self) -> None: ...

class BrokerMetadata:
    id: int
    host: Incomplete
    port: int
    def __init__(self) -> None: ...

class TopicMetadata:
    topic: Incomplete
    partitions: Incomplete
    error: Incomplete
    def __init__(self) -> None: ...

class PartitionMetadata:
    id: int
    leader: int
    replicas: Incomplete
    isrs: Incomplete
    error: Incomplete
    def __init__(self) -> None: ...

class GroupMember:
    id: Incomplete
    client_id: Incomplete
    client_host: Incomplete
    metadata: Incomplete
    assignment: Incomplete
    def __init__(self) -> None: ...

class GroupMetadata:
    broker: Incomplete
    id: Incomplete
    error: Incomplete
    state: Incomplete
    protocol_type: Incomplete
    protocol: Incomplete
    members: Incomplete
    def __init__(self) -> None: ...
