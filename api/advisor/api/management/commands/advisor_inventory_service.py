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

from django.conf import settings
from project_settings import kafka_settings
from django.core.management.base import BaseCommand

from advisor_logging import logger

from tasks.kafka_utils import send_event_message, KafkaDispatcher, send_kakfa_message


def handle_inventory_event(topic, message):
    """
    Handle inventory events.

    Message is of the form:
    {
        "event_type": "create",
    """


# Main command


class Command(BaseCommand):
    help = "Updates the job and executed task states based on Kafka messages"

    def handle(self, *args, **options):
        """
        Run the handler loop continuously until interrupted by SIGTERM.
        """
        logger.info('Tasks service starting up')

        receiver = KafkaDispatcher()
        receiver.register_handler(kafka_settings.INVENTORY_TOPIC, handle_inventory_event)

        def terminate(signum, frame):
            logger.info("SIGTERM received, triggering shutdown")
            receiver.quit = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)

        # Loops until receiver.quit is set
        receiver.receive()
        logger.info('Tasks service shutting down')
