from .error import KeySerializationError as KeySerializationError, ValueSerializationError as ValueSerializationError
from .serialization import MessageField as MessageField, SerializationContext as SerializationContext
from confluent_kafka.cimpl import Producer as _ProducerImpl

class SerializingProducer(_ProducerImpl):
    def __init__(self, conf) -> None: ...
    def produce(self, topic, key=None, value=None, partition: int = -1, on_delivery=None, timestamp: int = 0, headers=None) -> None: ...
