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

import logging
import json
import sys
import time
import traceback
from base64 import b64decode
from logstash_formatter import LogstashFormatterV1
import thread_storage
import project_settings.settings as settings
from os import getenv
LOG_LEVEL = getenv('LOG_LEVEL', 'INFO').upper()
LOG_HTTP_HEADER_FIELDS = {'CONTENT_LENGTH', 'CONTENT_TYPE', 'HTTP_ACCEPT',
                          'HTTP_USER_AGENT', 'HTTP_X_RH_IDENTITY', 'HTTP_X_FORWARDED_FOR',
                          'HTTP_X_FORWARDED_HOST', 'REMOTE_ADDR', 'REMOTE_HOST', 'HTTP_HOST'}


class AdvisorStreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(sys.stdout)
        self.setFormatter(
            OurFormatter(fmt=json.dumps({"extra": {"component": settings.APP_NAME}}))
        )


class OurFormatter(LogstashFormatterV1):

    def format(self, record):
        request = thread_storage.get_value('request')
        if request is not None:
            headers = {k[5:].replace('_', '-') if 'HTTP_' in k else k.replace('_', '-'): v
                       for (k, v) in request.META.items() if k in LOG_HTTP_HEADER_FIELDS}
            setattr(record, "headers", headers)
            if headers.get('X-RH-IDENTITY'):
                identity_header = json.loads(b64decode(headers['X-RH-IDENTITY']))
                if 'account_number' in identity_header['identity']:
                    setattr(record, 'account_number', identity_header['identity']['account_number'])
                if 'org_id' in identity_header['identity']:
                    setattr(record, 'org_id', identity_header['identity']['org_id'])
                username = identity_header['identity'].get('user', {}).get('username', '')
                if username:
                    setattr(record, 'username', username)

            if 'HTTP_X_RH_INSIGHTS_REQUEST_ID' in request.META:
                setattr(record, "request_id", request.META['HTTP_X_RH_INSIGHTS_REQUEST_ID'])
            duration = (time.time() - request.start_time) * 1000
            setattr(record, 'duration', int(duration))
            # Time spent waiting for RBAC:
            if hasattr(request, 'rbac_elapsed_time_millis'):
                setattr(record, 'rbac_elapsed_time_millis', request.rbac_elapsed_time_millis)

            if hasattr(request, 'data'):
                setattr(record, 'request_data', request.data)

            # RBAC Permissions
            if hasattr(request, 'rbac_sought_permission'):
                setattr(record, 'rbac_sought_permission', request.rbac_sought_permission)
            if hasattr(request, 'rbac_matched_permission'):
                setattr(record, 'rbac_matched_permission', request.rbac_matched_permission)
            if hasattr(request, 'rbac_match_type'):
                setattr(record, 'rbac_match_type', request.rbac_match_type)

            record_name = getattr(record, "name")
            record_args = getattr(record, "args")
            if record_name in ('django.request', 'django.server') and record_args:
                args = record_args[0].split()
                if len(args) > 1 and args[0] in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'):
                    setattr(record, 'method', args[0])
                    setattr(record, 'url', args[1])
            elif record_name == 'gunicorn.access' and record_args:
                setattr(record, 'method', record_args.get('m'))
                setattr(record, 'url', record_args.get('U'))
                setattr(record, 'status_code', int(record_args.get('s', '0')))

        post = thread_storage.get_value('post')
        if post is not None:
            setattr(record, 'post', post)

        exc = getattr(record, "exc_info")
        if exc:
            setattr(record, "exception", "".join(traceback.format_exception(*exc)))
            setattr(record, "exc_info", None)

        if LOG_LEVEL != 'DEBUG':
            # Remove unneeded fields to reduce log record size
            for attr in ("pathname", "filename", "lineno", "module", "funcName", "request",
                         "thread", "threadName", "process", "processName", "server_time",
                         "stack_info", "msecs", "relativeCreated"):
                if hasattr(record, attr):
                    delattr(record, attr)

            # Reduce size of gunicorn's message field
            if record.name == 'gunicorn.access' and hasattr(record, 'message'):
                # Not sure why we're splitting this and only selecting
                # the fifth through tenth words here.
                messages = record.message.split()
                if len(messages) >= 10:
                    record.message = ' '.join(messages[5:10])

        return super(OurFormatter, self).format(record)


# singleton for the whole application
logger = logging.getLogger("advisor-log")
