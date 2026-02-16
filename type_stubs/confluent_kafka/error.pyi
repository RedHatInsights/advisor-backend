from _typeshed import Incomplete
from confluent_kafka.cimpl import KafkaError as KafkaError, KafkaException as KafkaException
from confluent_kafka.serialization import SerializationError as SerializationError

class _KafkaClientError(KafkaException):
    exception: Incomplete
    kafka_message: Incomplete
    def __init__(self, kafka_error, exception=None, kafka_message=None) -> None: ...
    @property
    def code(self): ...
    @property
    def name(self): ...

class ConsumeError(_KafkaClientError):
    def __init__(self, kafka_error, exception=None, kafka_message=None) -> None: ...

class KeyDeserializationError(ConsumeError, SerializationError):
    def __init__(self, exception=None, kafka_message=None) -> None: ...

class ValueDeserializationError(ConsumeError, SerializationError):
    def __init__(self, exception=None, kafka_message=None) -> None: ...

class ProduceError(_KafkaClientError):
    def __init__(self, kafka_error, exception=None) -> None: ...

class KeySerializationError(ProduceError, SerializationError):
    def __init__(self, exception=None) -> None: ...

class ValueSerializationError(ProduceError, SerializationError):
    def __init__(self, exception=None) -> None: ...
