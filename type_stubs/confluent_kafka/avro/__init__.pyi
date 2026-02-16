from confluent_kafka import Consumer as Consumer, Producer as Producer
from confluent_kafka.avro.cached_schema_registry_client import CachedSchemaRegistryClient as CachedSchemaRegistryClient
from confluent_kafka.avro.error import ClientError as ClientError
from confluent_kafka.avro.load import load as load, loads as loads
from confluent_kafka.avro.serializer import KeySerializerError as KeySerializerError, SerializerError as SerializerError, ValueSerializerError as ValueSerializerError
from confluent_kafka.avro.serializer.message_serializer import MessageSerializer as MessageSerializer

class AvroProducer(Producer):
    def __init__(self, config, default_key_schema=None, default_value_schema=None, schema_registry=None, **kwargs) -> None: ...
    def produce(self, **kwargs) -> None: ...

class AvroConsumer(Consumer):
    def __init__(self, config, schema_registry=None, reader_key_schema=None, reader_value_schema=None, **kwargs) -> None: ...
    def poll(self, timeout=None): ...
