from _typeshed import Incomplete
from confluent_kafka import KafkaException as KafkaException, Producer as Producer
from verifiable_client import VerifiableClient

class VerifiableProducer(VerifiableClient):
    producer: Incomplete
    num_acked: int
    num_sent: int
    num_err: int
    def __init__(self, conf) -> None: ...
    def dr_cb(self, err, msg) -> None: ...
