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

from datetime import datetime
from uuid import uuid4

from django.conf import settings
from project_settings import kafka_settings as kafka_settings
kafka_settings.KAFKA_SETTINGS.update({'group.id': settings.GROUP_ID})

from advisor_logging import logger
from kafka_utils import send_kafka_message


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
        send_kafka_message(kafka_settings.WEBHOOKS_TOPIC, send_msg)
    except Exception as e:
        logger.exception('Could not send event of type %s (%s)', event_type, e)
