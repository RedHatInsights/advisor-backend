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
LOG_HTTP_HEADER_FIELDS = {
    'CONTENT_LENGTH': 'CONTENT-LENGTH',
    'CONTENT_TYPE': 'CONTENT-TYPE',
    'HTTP_ACCEPT': 'ACCEPT',
    'HTTP_USER_AGENT': 'USER-AGENT',
    'HTTP_X_RH_IDENTITY': 'X-RH-IDENTITY',
    'HTTP_X_FORWARDED_FOR': 'X-FORWARDED-FOR',
    'HTTP_X_FORWARDED_HOST': 'X-FORWARDED-HOST',
    'REMOTE_ADDR': 'REMOTE-ADDR',
    'REMOTE_HOST': 'REMOTE-HOST',
    'HTTP_HOST': 'HOST'
}
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


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
        'f': {'long name': '?', 'is': '-'},
        'H': {'long name': 'http_version'},
        # 'h': {'long name': 'host'},
        'L': {'long name': 'seconds', 'as': 'string float'},
        # 'l': {'long name': 'apache remote host identifier', 'is': '-'},
        # 'M': {'long name': 'milliseconds'},
        'm': {'long name': 'method'},
        # 'p': {'long name': 'process ID?', '=': '"<19945>"'},
        'q': {'long name': 'query_params'},
        # 'r': {'long name': 'request line'},
        's': {
            'long name': 'status_code', 'default': '0', 'transform': int
        },
        # 'T': {'long name': 'time taken?'},
        't': {'long name': 'timestamp'},
        'U': {'long name': 'url'},
        # 'u': {'long name': 'user', 'is': 'not provided, usually "-"'},
    }
    for short_name, rename in gunicorn_record_arg_renames.items():
        if short_name in record_args:
            value = record_args[short_name]
            if 'transform' in rename:
                value = rename['transform'](value)
            setattr(record, rename['long name'], value)
        elif 'default' in rename:
            setattr(record, rename['long name'], rename['default'])

    # Now transform the args that look like {name}[ioe] that we care about
    # and discard the rest.
    long_fields_to_keep = {
        'accept', 'accept-encoding', 'accept-language', 'akamai-origin-hop',
        'allow', 'cache-control', 'content-length', 'content-type', 'cookie',
        'cross-origin-opener-policy', 'csrf_cookie', 'forwarded', 'host',
        'raw_uri', 'referer', 'referrer-policy', 'remote_addr', 'remote_port',
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

    # Last ditch effort to find a URL and method - normally we expect them in
    # the short arguments but maybe those are '-'?
    if record.method == '-':
        record.method = record.request_method
    if record.url == '-':
        if '?' in record.raw_uri:
            record.url, record.query_params = record.raw_uri.split('?', 1)
        else:
            record.url = record.raw_uri


def copy_attr_to_record(record, request, name, new_name=None):
    if new_name is None:
        new_name = name
    value = getattr(request, name, None)
    if value:
        setattr(record, new_name, value)


def update_record_from_request(record, request):
    """
    This adds data from the request structure into the log record.

    Modifies the record object in situ; should leave the request untouched.
    """
    # Substitute nicer field names and only use the ones we want.
    headers = {
        subst: request.META[header]
        for header, subst in LOG_HTTP_HEADER_FIELDS.items()
        if header in request.META
    }
    setattr(record, "headers", headers)
    if headers.get('X-RH-IDENTITY'):
        # For speed and to reduce dependencies we don't use the identity
        # parsing routines in permissions.py
        try:
            identity_header = json.loads(b64decode(headers['X-RH-IDENTITY']))
            if 'account_number' in identity_header['identity']:
                setattr(record, 'account_number', identity_header['identity']['account_number'])
            if 'org_id' in identity_header['identity']:
                setattr(record, 'org_id', identity_header['identity']['org_id'])
            user_record = identity_header['identity'].get('user', {})
            if 'username' in user_record:
                setattr(record, 'username', user_record['username'])
            if 'user_id' in user_record:
                setattr(record, 'user_id', user_record['user_id'])
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


class OurFormatter(LogstashFormatterV1):

    def format(self, record):
        request = thread_storage.get_value('request')
        if request is not None:
            update_record_from_request(record, request)

        record_name = getattr(record, "name")
        record_args = getattr(record, "args")
        if record_name in ('django.request', 'django.server') and record_args:
            # How much should we not trust the string we get?
            # single pull-out of the raw "GET ... HTTP/1.1" string
            raw = record_args[0] if isinstance(record_args, (list, tuple)) else record_args

            parts = raw.split()
            if parts and parts[0] in ALLOWED_METHODS:
                # unpack with defaults
                method = parts.pop(0)
                url = parts.pop(0) if parts else None
                version = parts.pop(0).rstrip(',') if parts else None

                setattr(record, "method", method)
                setattr(record, "url", url)
                setattr(record, "http_version", version)
        elif record_name == 'gunicorn.access' and record_args and isinstance(record_args, dict):
            modify_gunicorn_logs_record(record, record_args)
            # record.args is used in % with the message of:
            # "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"
            # so we need to include those keys and only those keys.
            # This translates roughly to:
            # "127.0.0.1 - - [06/Aug/2025:05:38:55 +0000] \"GET /api/insights/v1/rule/ HTTP/1.1\" 200 26439 \"-\" \"Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0\""
            record.args = {
                key: record_args[key]
                for key in ('h', 'l', 'u', 't', 'r', 's', 'b', 'f', 'a')
            }

        post = thread_storage.get_value('post')
        if post:
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
                if isinstance(record.message, str):
                    # 127.0.0.1 - - [21/Jul/2025:22:57:29 +0000] "GET /api/insights/v1/... HTTP/1.1" 200 419 "<referer>" "<user agent>"
                    messages = record.message.split()
                    if len(messages) >= 10:
                        record.message = ' '.join(messages[5:10])

        return super(OurFormatter, self).format(record)


# singleton for the whole application
logger = logging.getLogger("advisor-log")
