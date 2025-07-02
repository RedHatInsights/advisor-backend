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

from confluent_kafka import Consumer, Producer
from datetime import datetime
import json
from uuid import uuid4

from django.conf import settings
from django.core.signals import request_started, request_finished
from project_settings import kafka_settings as kafka_settings
kafka_settings.KAFKA_SETTINGS.update({'group.id': settings.GROUP_ID})

from advisor_logging import logger


class DummyProducer(object):
    """
    A dummy Kafka producer for use during testing
    """
    def __init__(self, *args, **kwargs):
        self.poll_calls = 0
        self.produce_calls = []
        self.flush_calls = 0

    def poll(self, time):
        self.poll_calls += 1

    def produce(self, topic, message, callback=None):
        self.produce_calls.append({
            'topic': topic,
            'message': message,
            'callback': callback,
        })

    def flush(self):
        self.flush_calls += 1


if not kafka_settings.KAFKA_SETTINGS:
    # This means that we've been misconfigured
    logger.error("Tasks views require Kafka producer settings to send messages")
elif not kafka_settings.KAFKA_SETTINGS['bootstrap.servers']:
    # This means that we've been configured but from the Dev environment,
    # which doesn't include a default bootstrap server.  So we use the dummy
    # class above to just pretend to do stuff.
    logger.warning("Using dummy Kakfa producer")
    producer = DummyProducer()
else:
    producer = Producer(kafka_settings.KAFKA_SETTINGS)


# Message delivery callback

def msg_delivery_callback(err, msg):
    """
    Called once for each message produced to indicate delivery result.
    Triggered by poll() or flush().
    Reused from the Advisor service reporting, with a view to the Tasks app
    being self-contained in the future.
    """
    if err is not None:
        logger.error('Message delivery failed: {}'.format(err))
    else:
        logger.debug('Message delivered to {} [{}]'.format(
            msg.topic(), msg.partition())
        )


def send_kakfa_message(topic, message):
    producer.poll(0)
    encoded_message = json.dumps(message).encode('utf8')
    producer.produce(topic, encoded_message, callback=msg_delivery_callback)
    producer.flush()


def send_event_message(event_type, account=None, org_id=None, context={}, event_payloads=[]):
    """
    Messages on the Notifications topic need to be of this form:

    {
        "version": "v1.2.0",  **[1]**
        "bundle": "rhel",  **[2]**
        "application": "policies",  **[3]**
        "event_type": "policy-triggered",  **[4]**
        "timestamp": "2020-12-08T09:31:39Z",  **[5]**
        "account_id": "000000",  **[6]**
        "org_id": "54321",  **[15]**
        "context": {  **[7]**
            "any" : "thing",
            "you": 1,
            "want" : "here"
        },
        "events": [
        {
            "metadata": {},  **[8]**
            "payload": {  **[9]**
                "any" : "thing",
                "you": 1,
                "want" : "here"
            }
        }
        ],
        "recipients": [  **[10]**
        {
          "only_admins": false,  **[11]**
          "ignore_user_preferences": false,  **[12]**
          "users": [  **[13]**
            "user1",
            "user2"
          ]
        }
        ],
        "id": "uuid of the message"  **[14]**
    }

    Notes:

    [1] - version of the notification message; set to '1.2.0' currently.
    [2] - bundle name, set during application registration
    [3] - application name, set during application registration
    [4] - event type, set during application registration
    [5] - ISO-8601 formatted date - we set that.
    [6] - Account ID.  From request?
    [7] - Extra information common to all events - see the events list.
    [8] - Future-proofing, not used for now but needs to be there.
    [9] - Payload for each event.  All the information needed to generate
          your content elsewhere, in addition to the message context.
    [10] - Recipient settings; extends the list set by the org admins.  We
           don't set this.
    [11] - Send to only the admins (True), or all the users (False).  We don't
           set this.
           set this.
    [12] - Ignore user preferences for whether they receive email.  We don't
           set this.
    [13] - List of users; doesn't override notification administrator's
           settings.  We don't set this
    [14] - ID of the message as a UUID.  Currently optional.  We generate
           one for you.
    [15] - Organisation ID.  From request?
    """
    # If no payloads, don't send a message
    if not event_payloads:
        return
    logger.info("Sending %s event on topic %s", event_type, kafka_settings.WEBHOOKS_TOPIC)
    send_msg = {
        "version": "v1.2.0",
        "bundle": "rhel",
        "application": "tasks",
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        "account_id": account,
        "org_id": org_id,
        "context": context,
        "events": [
            {"metadata": {}, "payload": payload}
            for payload in event_payloads
        ],
        "recipients": [],
        "id": str(uuid4()),
    }
    try:
        send_kakfa_message(kafka_settings.WEBHOOKS_TOPIC, send_msg)
    except Exception as e:
        logger.exception('Could not send event of type %s (%s)', event_type, e)


class KafkaDispatcher(object):
    """
    Dispatches messages from Kafka to handlers based on their topic.  This
    handles the necessary boilerplate around receiving the message from Kafka,
    checking that it's valid, decoding it from JSON into a structure, and
    then processing that structure.

    Usage:

    >>> def topic_handler_fn(topic, body):
    ...     print(f"Received {body['name']} message from {topic}")
    ...
    >>> dispatcher = KafkaDispatcher()
    >>> dispatcher.register_handler("this topic", topic_handler_fn)
    >>> dispatcher.receive()

    A topic handler function can do anything, including setting the object's
    `quit` property to True which will cause the receive loop to exit at the
    next timeout of the wait for Kafka (defaults to 10 seconds).  Any return
    value from the topic handler function is ignored.

    Only one message handler can be registered to any topic.  If you need to
    do two or more things with a message, then give this a single handler
    function that then calls your other handlers.  This makes sure they're
    called in the order _you_ want, rather than the arbitrary order we might
    call them here.  Calling `register_handler` more than once will generate
    a warning and ignore the new handler function given.
    """
    def __init__(self):
        self.registered_handlers = dict()
        self.quit = False
        self.loop_timeout = 1
        # Own consumer for own set of topics
        self.consumer = Consumer(kafka_settings.KAFKA_SETTINGS)

    def register_handler(self, topic, handler_fn, **kwargs):
        if topic in self.registered_handlers:
            logger.warn(
                f"Warning: topic {topic} already has function "
                f"{self.registered_handlers[topic]['handler'].__name__} "
                f"registered when trying to register function "
                f"{handler_fn.__name__}.  Ignoring this new handler."
            )
        self.registered_handlers[topic] = {
            'handler': handler_fn,
            'filters': kwargs
        }

    def _handle_message(self, message):
        """
        Receive a message, find the handler for this topic, and run the
        message handler for this topic.
        """
        if message is None:
            return
        if message.error():
            logger.error(message.error())
            return

        topic = message.topic()
        if topic not in self.registered_handlers:
            return

        # It is important we filter by headers so that we don't json.loads every upload that is sent to CRC
        # The headers come in as a list of tuples.  The filters is a dictionary.
        # Example Filters: {'service': 'tasks'}
        # Example Headers: [('service', b'tasks')]
        headers = message.headers()
        if headers is None:
            headers = []
        header_filters = self.registered_handlers[topic]['filters']

        filters_matched = all(
            any(header[0] == k and header[1].decode('utf-8') == v for header in headers)
            for k, v in header_filters.items()
        )

        if not filters_matched:
            return

        # Decode JSON
        try:
            body = json.loads(message.value().decode('utf-8').strip('"'))
        except:
            logger.exception(f"Malformed JSON when handling {topic}")
            return
        # Tell Django we're starting a 'request' (db connection restarts...)
        request_started.send(sender=self.__class__)
        # Call handler with JSON
        try:
            self.registered_handlers[topic]['handler'](topic, body)
        except:
            logger.exception({
                'message': "Error processing kafka message",
                'topic': topic,
                'payload': body
            })
        # and we're finishing the 'request'
        request_finished.send(sender=self.__class__)

    def receive(self):
        """
        Run the receive loop continuously until told to stop.
        """
        self.consumer.subscribe(list(self.registered_handlers.keys()))

        while not self.quit:
            # longer polling timeouts mean fewer iterations through this loop,
            # but a longer time to respond to SIGTERM.  Here's the compromise:
            self._handle_message(self.consumer.poll(self.loop_timeout))
        self.consumer.close()
