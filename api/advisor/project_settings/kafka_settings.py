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

import os
from app_common_python import LoadedConfig, KafkaTopics, KafkaServers


def topic(requestedName):
    kafka_topic = KafkaTopics.get(requestedName)
    return kafka_topic.name if kafka_topic else requestedName


CLOWDER_ENABLED = os.getenv('CLOWDER_ENABLED', '').lower() == 'true'
if CLOWDER_ENABLED:
    ENGINE_RESULTS_TOPIC = topic('platform.engine.results')
    INVENTORY_EVENTS_TOPIC = topic('platform.inventory.events')
    RULE_HITS_TOPIC = topic('platform.insights.rule-hits')
    PAYLOAD_TRACKER_TOPIC = topic('platform.payload-status')
    REMEDIATIONS_HOOK_TOPIC = topic('platform.remediation-updates.advisor')
    WEBHOOKS_TOPIC = topic('platform.notifications.ingress')
    TASKS_UPDATES_TOPIC = topic('platform.playbook-dispatcher.runs')
    TASKS_SOURCES_TOPIC = topic('platform.sources.event-stream')
    TASKS_UPLOAD_TOPIC = topic('platform.upload.announce')

    kafka_broker = LoadedConfig.kafka.brokers[0]
    BOOTSTRAP_SERVERS = ",".join(KafkaServers)
    ENABLE_KAFKA_SSL = False
    KAFKA_SSL_CERT = None
    if kafka_broker.cacert:
        with open('/tmp/cacert', 'w') as f:
            f.write(kafka_broker.cacert)
        KAFKA_SSL_CERT = '/tmp/cacert'
    if kafka_broker.sasl and kafka_broker.sasl.securityProtocol and \
            'SSL' in kafka_broker.sasl.securityProtocol:
        ENABLE_KAFKA_SSL = True
    if kafka_broker.sasl and kafka_broker.sasl.username:
        ENABLE_KAFKA_SSL = True
        KAFKA_SASL_USERNAME = kafka_broker.sasl.username
        KAFKA_SASL_PASSWORD = kafka_broker.sasl.password
        KAFKA_SECURITY_PROTOCOL = kafka_broker.sasl.securityProtocol
        KAFKA_SASL_MECHANISMS = kafka_broker.sasl.saslMechanism
else:
    ENGINE_RESULTS_TOPIC = os.environ.get('ENGINE_RESULTS_TOPIC', 'platform.engine.results')
    INVENTORY_EVENTS_TOPIC = os.environ.get('INVENTORY_EVENTS_TOPIC', 'platform.inventory.events')
    RULE_HITS_TOPIC = os.environ.get('RULE_HITS_TOPIC', 'platform.insights.rule-hits')
    PAYLOAD_TRACKER_TOPIC = os.environ.get('PAYLOAD_TRACKER_TOPIC')
    REMEDIATIONS_HOOK_TOPIC = os.environ.get('REMEDIATIONS_HOOK_TOPIC',
                                             'platform.remediation-updates.advisor')
    WEBHOOKS_TOPIC = os.environ.get('WEBHOOKS_TOPIC')
    TASKS_UPDATES_TOPIC = os.environ.get('TASKS_UPDATES_TOPIC', 'platform.playbook-dispatcher.runs')
    TASKS_SOURCES_TOPIC = os.environ.get('TASKS_SOURCES_TOPIC', 'platform.sources.event-stream')
    TASKS_UPLOAD_TOPIC = os.environ.get('TASKS_UPLOAD_TOPIC', 'platform.upload.announce')
    BOOTSTRAP_SERVERS = os.environ.get('BOOTSTRAP_SERVERS')
    ENABLE_KAFKA_SSL = os.environ.get('ENABLE_KAFKA_SSL', '').lower() == "true"
    KAFKA_SSL_CERT = os.environ.get('KAFKA_SSL_CERT', '/opt/certs/kafka-cacert')
    KAFKA_SECURITY_PROTOCOL = os.environ.get('KAFKA_SECURITY_PROTOCOL', 'SASL_SSL')
    KAFKA_SASL_MECHANISMS = os.environ.get('KAFKA_SASL_MECHANISMS', 'SCRAM-SHA-512')
    KAFKA_SASL_USERNAME = os.environ.get('KAFKA_SASL_USERNAME')
    KAFKA_SASL_PASSWORD = os.environ.get('KAFKA_SASL_PASSWORD')

KAFKA_SETTINGS = {
    'bootstrap.servers': BOOTSTRAP_SERVERS,
    'auto.offset.reset': 'latest',
    'enable.auto.commit': True,
    'enable.auto.offset.store': True,
}
if ENABLE_KAFKA_SSL:
    KAFKA_SETTINGS.update({
        'security.protocol': KAFKA_SECURITY_PROTOCOL,
        'sasl.mechanisms': KAFKA_SASL_MECHANISMS,
        'sasl.username': KAFKA_SASL_USERNAME,
        'sasl.password': KAFKA_SASL_PASSWORD,
        #  'group.id' is defined in api/tasks/service instantation for consumer group and in respective settings
    })
if KAFKA_SSL_CERT:
    KAFKA_SETTINGS.update({
        'ssl.ca.location': KAFKA_SSL_CERT,
    })
