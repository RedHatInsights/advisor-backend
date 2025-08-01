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

from contextlib import contextmanager
import json
from os import environ
import thread_storage
import time
from types import SimpleNamespace

from django.test import TestCase

from api.permissions import request_object_for_testing

import advisor_logging
import logging_conf

gunicorn_args = {
    "h": "10.1.2.3",
    "l": "-",
    "u": "-",
    "t": "[21/Jul/2025:23:04:02 +0000]",
    "r": "GET /api/insights/v1/rule/?category=1 HTTP/1.1",
    "s": "200",
    "m": "GET",
    "U": "/api/insights/v1/rule/",
    "q": "category=1",
    "H": "HTTP/1.1",
    "b": "33509",
    "B": 33509,
    "f": "-",
    "a": "OpenAPI-Generator/1.0.0/python",
    "T": 0,
    "D": 194467,
    "M": 194,
    "L": "0.194467",
    "p": "<73090>",
    "{x-real-ip}i": "127.0.0.1",
    "{host}i": "insights-advisor-api.local:8000",
    "{accept}i": "application/json",
    "{user-agent}i": "OpenAPI-Generator/1.0.0/python",
    "{true-client-ip}i": "1.2.3.4",
    "{pragma}i": "no-cache",
    "{cdn-loop}i": "akamai;v=1.0;c=1",
    "{x-akamai-config-log-detail}i": "true",
    "{accept-encoding}i": "gzip",
    "{akamai-origin-hop}i": "2",
    "{via}i": "1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)",
    "{x-forwarded-for}i": "2.3.4.5",
    "{cache-control}i": "no-cache, max-age=0",
    "{x-rh-edge-request-id}i": "28b2f019",
    "{x-rh-edge-reference-id}i": "0.9368dc17.1753139042.28b2f019",
    "{x-rh-edge-host}i": "edge.local",
    "{x-rh-edge}i": "akamai",
    "{x-forwarded-host}i": "console.local",
    "{x-forwarded-port}i": "443",
    "{x-forwarded-proto}i": "https",
    "{forwarded}i": "for=2.3.4.5;host=insights.local;proto=https",
    "{x-rh-insights-request-id}i": "4f7bd84302004684ba96dd5e8759f64c",
    "{content-type}o": "application/json",
    "{vary}o": "Accept",
    "{allow}o": "GET, HEAD, OPTIONS",
    "{x-frame-options}o": "DENY",
    "{content-length}o": "33509",
    "{strict-transport-security}o": "max-age=31536000; includeSubDomains",
    "{x-content-type-options}o": "nosniff",
    "{referrer-policy}o": "same-origin",
    "{cross-origin-opener-policy}o": "same-origin",
    "{wsgi.errors}e": "<gunicorn.http.wsgi.WSGIErrorsWrapper object at 0x7f64fc2845b0>",
    "{wsgi.version}e": [1, 0],
    "{wsgi.multithread}e": False,
    "{wsgi.multiprocess}e": True,
    "{wsgi.run_once}e": False,
    "{wsgi.file_wrapper}e": "<class 'gunicorn.http.wsgi.FileWrapper'>",
    "{wsgi.input_terminated}e": True,
    "{server_software}e": "gunicorn/23.0.0",
    "{wsgi.input}e": "<gunicorn.http.body.Body object at 0x7f64fc286e70>",
    "{gunicorn.socket}e": "<socket.socket fd=13, family=2, type=1, proto=0, laddr=('10.1.2.3', 8000), raddr=('1.2.3.4', 45722)>",
    "{request_method}e": "GET",
    "{query_string}e": "category=1",
    "{raw_uri}e": "/api/insights/v1/rule/?category=1",
    "{server_protocol}e": "HTTP/1.1",
    "{http_x_real_ip}e": "127.0.0.1",
    "{http_host}e": "insights-advisor-api.local:8000",
    "{http_x_3scale_proxy_secret_token}e": "2999544eb145f9fb3d0de9e16f365950",
    "{http_accept}e": "application/json",
    "{http_user_agent}e": "OpenAPI-Generator/1.0.0/python",
    "{http_true_client_ip}e": "2.3.4.5",
    "{http_pragma}e": "no-cache",
    "{http_cdn_loop}e": "akamai;v=1.0;c=1",
    "{http_x_akamai_config_log_detail}e": "true",
    "{http_accept_encoding}e": "gzip",
    "{http_akamai_origin_hop}e": "2",
    "{http_via}e": "1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)",
    "{http_x_forwarded_for}e": "2.3.4.5",
    "{http_cache_control}e": "no-cache, max-age=0",
    "{http_x_rh_edge_request_id}e": "28b2f019",
    "{http_x_rh_edge_reference_id}e": "0.9368dc17.1753139042.28b2f019",
    "{http_x_rh_edge_host}e": "edge.local",
    "{http_x_rh_edge}e": "akamai",
    "{http_x_forwarded_host}e": "edge.local",
    "{http_x_forwarded_port}e": "443",
    "{http_x_forwarded_proto}e": "https",
    "{http_forwarded}e": "for=2.3.4.5;host=insights.local;proto=https",
    "{http_x_rh_insights_request_id}e": "4f7bd84302004684ba96dd5e8759f64c",
    "{wsgi.url_scheme}e": "http",
    "{remote_addr}e": "10.1.2.3",
    "{remote_port}e": "45722",
    "{server_name}e": "0.0.0.0",
    "{server_port}e": "8000",
    "{path_info}e": "/api/insights/v1/rule/",
    "{script_name}e": ""
}


@contextmanager
def override_environment(**kwargs):
    original_values = dict()
    for key, new_val in kwargs.items():
        original_values[key] = environ.get(key)
        environ[key] = new_val

    try:
        yield
    finally:
        for key, orig_val in original_values.items():
            if orig_val is None:
                del environ[key]
            else:
                environ[key] = orig_val


class AdvisorLoggingTestCase(TestCase):

    def test_modify_gunicorn_logs(self):
        """
        Testing with mildly modified, anonymised real-world data.
        """
        record = SimpleNamespace()
        advisor_logging.modify_gunicorn_logs_record(record, gunicorn_args)
        # Attributes from the short arguments
        self.assertEqual(getattr(record, 'bytes'), 33509)
        self.assertEqual(getattr(record, 'microseconds'), 194467)
        self.assertEqual(getattr(record, 'url'), '/api/insights/v1/rule/')
        self.assertEqual(getattr(record, 'http_version'), 'HTTP/1.1')
        self.assertEqual(getattr(record, 'seconds'), '0.194467')
        self.assertEqual(getattr(record, 'method'), 'GET')
        self.assertEqual(getattr(record, 'status_code'), 200)
        self.assertEqual(getattr(record, 'timestamp'), "[21/Jul/2025:23:04:02 +0000]")
        # Attributes from the long arguments - note that setattr/getattr allow
        # attributes with dashes in their names, even though these would be
        # impossible to normally refer to using dot syntax.
        # Is it considered cheating here to basically recreate the name
        # transform in advisor_logging here?
        long_args = {
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
        for field, value in gunicorn_args.items():
            if len(field) == 1:
                self.assertFalse(
                    hasattr(record, field),
                    f"Field '{field}' should not be in record"
                )
                continue
            field_name = field[1:-2]
            if field_name not in long_args:
                self.assertFalse(
                    hasattr(record, field),
                    f"Field '{field}' should not be in record"
                )
                continue
            self.assertEqual(
                getattr(record, field_name), gunicorn_args.get(field),
                f"Field {field_name} didn't get copied from {field} to record attribute"
            )

    def test_update_record_from_request(self):
        request = request_object_for_testing()
        # Make sure the identity header has been set by the helper
        self.assertIn('HTTP_X_RH_IDENTITY', request.META)
        request.META['HTTP_X_RH_INSIGHTS_REQUEST_ID'] = 'request_id'
        request.META['NOT_FOUND'] = 'yes'
        request.start_time = time.time()
        request.rbac_elapsed_time_millis = 123
        record = SimpleNamespace()
        advisor_logging.update_record_from_request(record, request)

        self.assertEqual(record.headers['REMOTE-ADDR'], 'test')
        self.assertEqual(record.headers['X-RH-IDENTITY'], request.META['HTTP_X_RH_IDENTITY'])
        self.assertEqual(record.account_number, '1234567')
        self.assertEqual(record.org_id, '9876543')
        self.assertEqual(record.username, 'testing')
        self.assertEqual(record.user_id, '123')
        self.assertEqual(record.request_id, 'request_id')
        self.assertEqual(record.rbac_elapsed_time_millis, 123)

        request.META['HTTP_X_RH_IDENTITY'] = b'Not a Base64 string'
        advisor_logging.update_record_from_request(record, request)
        self.assertEqual(
            record.headers['X-RH-IDENTITY'], b'Not a Base64 string'
        )

    def test_format_method_django_server(self):
        """
        This is going to be a bit of a hack as actually getting to format a
        log line in normal operation is hard to set up AFAICS.
        """
        fmtr = advisor_logging.OurFormatter()
        # No request or post data in thread storage yet.
        thread_storage.set_value('request', None)
        thread_storage.set_value('post', None)
        record = SimpleNamespace()
        record.name = 'django.server'
        record.args = "GET /api/insights/v1/... HTTP/1.1, 200, 603"
        record.exc_info = None

        formatted = fmtr.format(record)
        self.assertIsInstance(formatted, str)
        formatted_rec = json.loads(formatted)
        self.assertIn('@timestamp', formatted_rec)
        self.assertEqual(formatted_rec["@version"], 1)
        self.assertIn('source_host', formatted_rec)
        self.assertEqual(formatted_rec["name"], record.name)
        self.assertEqual(formatted_rec["args"], record.args)
        self.assertEqual(formatted_rec['method'], 'GET')
        self.assertEqual(formatted_rec['url'], '/api/insights/v1/...')
        self.assertEqual(formatted_rec['http_version'], 'HTTP/1.1')
        # Check that other fields are not here because they haven't been
        # set in e.g. the request or post data
        self.assertNotIn('headers', formatted_rec)
        self.assertNotIn('post', formatted_rec)

        # Now set some thread storage data
        request = request_object_for_testing()
        self.assertIn('HTTP_X_RH_IDENTITY', request.META)
        request.META['HTTP_X_RH_INSIGHTS_REQUEST_ID'] = 'request_id'
        request.META['NOT_FOUND'] = 'yes'
        request.start_time = time.time()
        request.rbac_elapsed_time_millis = 123
        thread_storage.set_value('request', request)
        post_data = {
            'justification': 'Test system disabled rules',
            'rule': 'test|Active_rule'
        }
        thread_storage.set_value('post', post_data)
        # Fields to be deleted by unneeded field pruning
        record.filename = __file__
        record.lineno = 246
        # Do we really want to womp up an exception structure?
        # Run the formatting
        formatted = fmtr.format(record)
        self.assertIsInstance(formatted, str)
        formatted_rec = json.loads(formatted)
        self.assertIn('headers', formatted_rec)
        self.assertEqual(formatted_rec['headers']['REMOTE-ADDR'], 'test')
        # The identity header is bytes, formatted as a b'' string...
        self.assertEqual(
            formatted_rec['headers']['X-RH-IDENTITY'],
            str(request.META['HTTP_X_RH_IDENTITY'])
        )
        # Fields derived from that:
        self.assertEqual(formatted_rec['account_number'], '1234567')
        self.assertEqual(formatted_rec['org_id'], '9876543')
        self.assertEqual(formatted_rec['username'], 'testing')
        self.assertEqual(formatted_rec['user_id'], '123')
        self.assertEqual(formatted_rec['request_id'], 'request_id')
        self.assertEqual(formatted_rec['rbac_elapsed_time_millis'], 123)
        self.assertEqual(formatted_rec['post'], post_data)
        self.assertNotIn('filename', formatted_rec)
        self.assertNotIn('lineno', formatted_rec)

    def test_format_method_gunicorn(self):
        """
        This is going to be a bit of a hack as actually getting to format a
        log line in normal operation is hard to set up AFAICS.
        """
        fmtr = advisor_logging.OurFormatter()
        # No request or post data in thread storage yet.
        thread_storage.set_value('request', None)
        thread_storage.set_value('post', None)
        record = SimpleNamespace()
        record.name = 'gunicorn.access'
        record.args = gunicorn_args
        record.exc_info = None
        # Message should be pruned:
        record.message = (
            '127.0.0.1 - - [21/Jul/2025:22:57:29 +0000] "GET '
            '/api/insights/v1/... HTTP/1.1" 200 419 "<referer>" "<user agent>"'
        )

        formatted = fmtr.format(record)
        self.assertIsInstance(formatted, str)
        formatted_rec = json.loads(formatted)
        self.assertIsInstance(formatted_rec, dict)
        self.assertIn('@timestamp', formatted_rec)
        self.assertEqual(formatted_rec['@version'], 1)
        self.assertIn('source_host', formatted_rec)
        self.assertEqual(formatted_rec['name'], record.name)
        for gunicorn_arg_key in gunicorn_args.keys():
            # We modify all of these, should find no originals remaining
            self.assertNotIn(gunicorn_arg_key, formatted_rec)
        # Testing by pure value here
        self.assertEqual(formatted_rec['bytes'], 33509)
        self.assertEqual(formatted_rec['microseconds'], 194467)
        self.assertEqual(formatted_rec['http_version'], 'HTTP/1.1')
        self.assertEqual(formatted_rec['seconds'], "0.194467")
        self.assertEqual(formatted_rec['method'], 'GET')
        self.assertEqual(formatted_rec['query_params'], 'category=1')
        self.assertEqual(formatted_rec['status_code'], 200)
        self.assertEqual(formatted_rec['timestamp'], "[21/Jul/2025:23:04:02 +0000]")
        self.assertEqual(formatted_rec['url'], '/api/insights/v1/rule/')
        self.assertEqual(formatted_rec['x-real-ip'], '127.0.0.1')
        self.assertEqual(formatted_rec['host'], 'insights-advisor-api.local:8000')
        self.assertEqual(formatted_rec['accept'], 'application/json')
        self.assertEqual(formatted_rec['user-agent'], 'OpenAPI-Generator/1.0.0/python')
        self.assertEqual(formatted_rec['true-client-ip'], '1.2.3.4')
        self.assertEqual(formatted_rec['accept-encoding'], 'gzip')
        self.assertEqual(formatted_rec['akamai-origin-hop'], "2")
        self.assertEqual(
            formatted_rec['via'],
            '1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)'
        )
        self.assertEqual(formatted_rec['x-forwarded-for'], '2.3.4.5')
        self.assertEqual(formatted_rec['cache-control'], 'no-cache, max-age=0')
        self.assertEqual(formatted_rec['x-rh-edge-request-id'], '28b2f019')
        self.assertEqual(
            formatted_rec['x-rh-edge-reference-id'], "0.9368dc17.1753139042.28b2f019"
        )
        self.assertEqual(formatted_rec['x-forwarded-host'], 'console.local')
        self.assertEqual(formatted_rec['x-forwarded-port'], '443')
        self.assertEqual(
            formatted_rec['forwarded'], 'for=2.3.4.5;host=insights.local;proto=https'
        )
        self.assertEqual(
            formatted_rec['x-rh-insights-request-id'], "4f7bd84302004684ba96dd5e8759f64c"
        )
        self.assertEqual(formatted_rec['content-type'], 'application/json')
        self.assertEqual(formatted_rec['vary'], 'Accept')
        self.assertEqual(formatted_rec['allow'], 'GET, HEAD, OPTIONS')
        self.assertEqual(formatted_rec['x-frame-options'], 'DENY')
        self.assertEqual(formatted_rec['content-length'], '33509')
        self.assertEqual(
            formatted_rec['strict-transport-security'], 'max-age=31536000; includeSubDomains'
        )
        self.assertEqual(formatted_rec['x-content-type-options'], 'nosniff')
        self.assertEqual(formatted_rec['referrer-policy'], 'same-origin')
        self.assertEqual(formatted_rec['cross-origin-opener-policy'], 'same-origin')
        self.assertEqual(
            formatted_rec['wsgi.errors'],
            '<gunicorn.http.wsgi.WSGIErrorsWrapper object at 0x7f64fc2845b0>'
        )
        self.assertEqual(formatted_rec['request_method'], 'GET')
        self.assertEqual(formatted_rec['server_software'], 'gunicorn/23.0.0')
        self.assertEqual(formatted_rec['raw_uri'], '/api/insights/v1/rule/?category=1')
        self.assertEqual(formatted_rec['remote_addr'], '10.1.2.3')
        self.assertEqual(formatted_rec['remote_port'], '45722')
        self.assertEqual(
            formatted_rec['message'], '"GET /api/insights/v1/... HTTP/1.1" 200 419'
        )

    def test_logging_conf_cloudwatch_enabled(self):
        """
        The 'logging_conf' module defines USE_CLOUDWATCH_LOGGING at the
        module level, and the code that relies on it also at the module level.
        importlib.reimport doesn't cause the code to be re-evaluated though?
        So we've put the code we want to test into a function we can call.
        """
        with override_environment(
            AWS_ACCESS_KEY_ID='test access key id',
            AWS_SECRET_ACCESS_KEY='test secret access key',
            HOSTNAME='test host'
        ):
            logging_conf.USE_CLOUDWATCH_LOGGING = 'true'
            logging_conf.load_cloudwatch_logging()

            # The only effect is if we get to installing a cloudwatch handler.
            self.assertIn('cloudwatch', logging_conf.LOGGING['handlers'])
            self.assertEqual(
                logging_conf.LOGGING['handlers']['cloudwatch']['log_group'],
                'platform-dev'
            )
            self.assertEqual(
                logging_conf.LOGGING['handlers']['cloudwatch']['stream_name'],
                'test host'
            )
            self.assertEqual(
                logging_conf.LOGGING['handlers']['cloudwatch']['formatter'],
                'json'
            )

    def test_hide_metrics(self):
        """
        Test all the code paths through hide_metrics, including failure modes.
        """
        record = SimpleNamespace()

        # No properties at all, should be True.
        self.assertTrue(logging_conf.hide_metrics(record))

        # Random record name should return True.
        record.name = "Foo"
        self.assertTrue(logging_conf.hide_metrics(record))

        # Django record with no args should return True.
        record.name = "django.request"
        self.assertTrue(logging_conf.hide_metrics(record))

        # Django record with args as not a string should return True.
        record.args = {'args': "GET /api/insights/v1/... HTTP/1.1, 200, 603"}
        self.assertTrue(logging_conf.hide_metrics(record))

        # Django record with args but not a GET of /metrics should return True.
        record.args = "GET /api/insights/v1/... HTTP/1.1, 200, 603"
        self.assertTrue(logging_conf.hide_metrics(record))

        # Django record with args but not a GET of /metrics should return False.
        record.args = "GET /metrics HTTP/1.1, 200, 603"
        self.assertFalse(logging_conf.hide_metrics(record))

        # GUnicorn with no args should return True.
        record.name = "gunicorn.access"
        delattr(record, 'args')
        self.assertTrue(logging_conf.hide_metrics(record))

        # GUnicorn record with args but not a dict should return True.
        record.args = "GET /metrics HTTP/1.1, 200, 603"
        self.assertTrue(logging_conf.hide_metrics(record))

        # GUnicorn record with args as dict but not of /metrics should return True.
        record.args = {'U': '/api/insights/v1/rule/'}
        self.assertTrue(logging_conf.hide_metrics(record))

        # GUnicorn record with args dict U=/metrics should return False.
        record.args = {'U': '/metrics'}
        self.assertFalse(logging_conf.hide_metrics(record))

        # LOG_LEVEL=DEBUG should always return true
        prev_level = logging_conf.LOG_LEVEL
        logging_conf.LOG_LEVEL = 'DEBUG'
        # Only test the paths that would return False
        record.name = "django.request"
        record.args = "GET /metrics HTTP/1.1, 200, 603"
        self.assertTrue(logging_conf.hide_metrics(record))
        record.name = "gunicorn.access"
        record.args = {'U': '/metrics'}
        self.assertTrue(logging_conf.hide_metrics(record))

        # Set debug level back
        logging_conf.LOG_LEVEL = prev_level
