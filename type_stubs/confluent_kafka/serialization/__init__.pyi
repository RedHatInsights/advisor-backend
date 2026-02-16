from _typeshed import Incomplete
from confluent_kafka.error import KafkaException
from enum import Enum

__all__ = ['Deserializer', 'IntegerDeserializer', 'IntegerSerializer', 'DoubleDeserializer', 'DoubleSerializer', 'StringDeserializer', 'StringSerializer', 'MessageField', 'SerializationContext', 'SerializationError', 'Serializer']

class MessageField(str, Enum):
    NONE = 'none'
    KEY = 'key'
    VALUE = 'value'

class SerializationContext:
    topic: Incomplete
    field: Incomplete
    headers: Incomplete
    def __init__(self, topic, field, headers=None) -> None: ...

class SerializationError(KafkaException): ...

class Serializer:
    def __call__(self, obj, ctx=None) -> None: ...

class Deserializer:
    def __call__(self, value, ctx=None) -> None: ...

class DoubleSerializer(Serializer):
    def __call__(self, obj, ctx=None): ...

class DoubleDeserializer(Deserializer):
    def __call__(self, value, ctx=None): ...

class IntegerSerializer(Serializer):
    def __call__(self, obj, ctx=None): ...

class IntegerDeserializer(Deserializer):
    def __call__(self, value, ctx=None): ...

class StringSerializer(Serializer):
    codec: Incomplete
    def __init__(self, codec: str = 'utf_8') -> None: ...
    def __call__(self, obj, ctx=None): ...

class StringDeserializer(Deserializer):
    codec: Incomplete
    def __init__(self, codec: str = 'utf_8') -> None: ...
    def __call__(self, value, ctx=None): ...
