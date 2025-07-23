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

import time
from types import SimpleNamespace

from django.test import TestCase

from api.permissions import request_object_for_testing

import advisor_logging

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
        self.assertEqual(record.account_number, '1234567')
        self.assertEqual(record.org_id, '9876543')
        self.assertEqual(record.username, 'testing')
        self.assertEqual(record.request_id, 'request_id')
        self.assertEqual(record.rbac_elapsed_time_millis, 123)

        request.META['HTTP_X_RH_IDENTITY'] = 'Not a Base64 string'
        advisor_logging.update_record_from_request(record, request)
        self.assertEqual(
            record.headers['X-RH-IDENTITY'], 'Not a Base64 string'
        )
