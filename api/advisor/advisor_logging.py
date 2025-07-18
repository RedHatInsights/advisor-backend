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


def modify_gunicorn_logs_record(record, record_args):
    """
    The gunicorn 'args' attribute seems to be a dict with LOTS of information.
    Some of them are in the form of single-letter names; some are duplicated
    in the headers attribute (set from the request, see in `format` below);
    some are also in the form "{"name"}"[eio].  We want to pull the things
    we need into standard names similar to those already kept in the logs.

    Headers include: ACCEPT, HOST, REMOTE-ADDR, USER-AGENT, X-FORWARDED-FOR,
    X-FORWARDED-HOST and X-RH-IDENTITY.

    After this we delete the 'args' attribute entirely so we don't need to
    delete things in here.
    """
    # Only list the fields that aren't also in the long fields below
    gunicorn_record_arg_renames = {
        # 'a': {'long name': 'user agent'},
        'B': {'long name': 'bytes', 'as': 'int'},
        # 'b': {'long name': 'bytes', 'as': 'str'},
        'D': {'long name': 'microseconds'},
        'f': {'long name': 'url'},
        'H': {'long name': 'http_version'},
        # 'h': {'long name': 'host'},
        'L': {'long name': 'seconds', 'as': 'string float'},
        # 'l': {},
        # 'M': {'long name': 'milliseconds'},
        'm': {'long name': 'method'},
        # 'p': {'long name': 'process ID?', '=': '"<19945>"'},
        # 'q': {'long name': 'query args'},
        # 'r': {'long name': 'request line'},
        's': {
            'long name': 'status_code', 'default': '0', 'transform': int
        },
        # 'T': {'long name': 'time taken?'},
        't': {'long name': 'timestamp'},
        # 'U': {'long name': 'url with no query string'},
        # 'u': {},
    }
    for short_name, rename in gunicorn_record_arg_renames.items():
        value = record_args.get(short_name, rename.get('default'))
        if 'transform' in rename:
            value = rename['transform'](value)
        setattr(record, rename['method'], value)

    # Now transform the args that look like {name}[ioe] that we care about
    # and discard the rest.
    long_fields_to_keep = {
        'accept', 'accept-encoding', 'accept-language', 'akamai-origin-hop',
        'allow', 'cache-control', 'content-length', 'content-type', 'cookie',
        'cross-origin-opener-policy', 'csrf_cookie', 'forwarded', 'host',
        'referer', 'referrer-policy', 'remote_addr', 'remote_port',
        'request_method', 'server_software', 'strict-transport-security',
        'true-client-ip', 'user-agent', 'vary', 'via', 'wsgi.errors',
        'x-content-type-options', 'x-forwarded-for', 'x-forwarded-host',
        'x-forwarded-port', 'x-frame-options', 'x-real-ip',
        'x-rh-edge-reference-id', 'x-rh-edge-request-id',
        'x-rh-frontend-origin', 'x-rh-identity', 'x-rh-insights-request-id'
    }
    for arg_name, arg_value in record_args.items():
        if arg_name[0] == '{' and arg_name[-2] == '}' and arg_name[-1] in "eio":
            true_arg_name = arg_name[1:-2]
            if true_arg_name in long_fields_to_keep:
                setattr(record, true_arg_name, arg_value)
            del record_args[arg_name]


def copy_attr_to_record(record, request, name, new_name=None):
    if new_name is None:
        new_name = name
    value = getattr(request, name)
    if value:
        setattr(record, new_name, value)


def update_record_from_request(record, request):
    headers = {k[5:].replace('_', '-') if 'HTTP_' in k else k.replace('_', '-'): v
               for (k, v) in request.META.items() if k in LOG_HTTP_HEADER_FIELDS}
    setattr(record, "headers", headers)
    if headers.get('X-RH-IDENTITY'):
        try:
            identity_header = json.loads(b64decode(headers['X-RH-IDENTITY']))
            if 'account_number' in identity_header['identity']:
                setattr(record, 'account_number', identity_header['identity']['account_number'])
            if 'org_id' in identity_header['identity']:
                setattr(record, 'org_id', identity_header['identity']['org_id'])
            username = identity_header['identity'].get('user', {}).get('username', '')
            if username:
                setattr(record, 'username', username)
        except:
            pass  # ignore broken decode and JSON just in case

    if 'HTTP_X_RH_INSIGHTS_REQUEST_ID' in request.META:
        setattr(record, "request_id", request.META['HTTP_X_RH_INSIGHTS_REQUEST_ID'])
    duration = (time.time() - request.start_time) * 1000
    setattr(record, 'duration', int(duration))

    # Time spent waiting for RBAC:
    copy_attr_to_record(record, request, 'rbac_elapsed_time_millis')
    # RBAC Permissions
    copy_attr_to_record(record, request, 'rbac_sought_permission')
    copy_attr_to_record(record, request, 'rbac_matched_permission')
    copy_attr_to_record(record, request, 'rbac_match_type')

    record_name = getattr(record, "name")
    record_args = getattr(record, "args")
    if record_name in ('django.request', 'django.server') and record_args:
        args = record_args[0].split()
        if len(args) > 1 and args[0] in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'):
            setattr(record, 'method', args[0])
            setattr(record, 'url', args[1])
    elif record_name == 'gunicorn.access' and record_args:
        modify_gunicorn_logs_record(record, record_args)
        # We've now put everything we want in the record, we can
        # remove the args entirely
        delattr(record, "args")


class OurFormatter(LogstashFormatterV1):

    def format(self, record):
        request = thread_storage.get_value('request')
        if request is not None:
            update_record_from_request(record, request)

        post = thread_storage.get_value('post')
        if post is not None:
            setattr(record, 'post', post)
            # Clear afterward, now that we're long-lived
            thread_storage.set_value('post', dict())

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
