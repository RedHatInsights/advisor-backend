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

import requests
from os import getenv
from django.core.management.base import BaseCommand

from api.permissions import auth_header_for_testing

ADVISOR_HOST = getenv("ADVISOR_HOST", "127.0.0.1:8000")
PATHS_TO_TEST = [
    'stats/systems/',
    'stats/rules/',
    'rule/?impacting=true&sort=-total_risk',
    'rule/?impacting=true&sort=-impacted_count',
    'hostack/',
    'topic/',
    'system/?sort=-last_seen',
    'system/?sort=display_name',
    'system/?sort=-hits'
]
PATHS_MAX_LEN = max(len(p) for p in PATHS_TO_TEST)


class Command(BaseCommand):
    """
    Example: ./advisor/manage.py benchmark 729650
    This allows a quick sanity check of performance on several of
    the most common API paths for a given account
    """
    def add_arguments(self, parser):
        parser.add_argument('account', nargs='+', type=str)

    def handle(self, *args, **options):
        self.account = options['account'][0]

        for path in PATHS_TO_TEST:
            res = self.get_http_request(path)
            self.print_response_duration(res, path)

        res = self.get_http_request('rule/?sort=-impacted_count&limit=1')
        try:
            biggest_rule = res.json()['data'][0]['rule_id']
        except IndexError:
            self.stdout.write("No rules in API response")
            biggest_rule = None

        res = self.get_http_request('system/?sort=-hits&limit=1')
        try:
            biggest_system = res.json()['data'][0]['system_uuid']
        except IndexError:
            self.stdout.write("No systems in API response")
            biggest_system = None

        if biggest_rule:
            res = self.get_http_request(f'rule/{biggest_rule}/')
            self.print_response_duration(res, 'rule/{id}/')
            res = self.get_http_request(f'rule/{biggest_rule}/systems/')
            self.print_response_duration(res, 'rule/{id}/systems/')

        if biggest_system:
            res = self.get_http_request(f'system/{biggest_system}/reports/')
            self.print_response_duration(res, 'system/{id}/reports/')

    def print_response_duration(self, res, path):
        duration = int(res.elapsed.total_seconds() * 1000)
        self.stdout.write(f'{path:{PATHS_MAX_LEN}} {duration:6} ms')

    def get_http_request(self, path):
        auth_header = auth_header_for_testing(account=self.account, supply_http_header=True)
        res = requests.get(f'http://{ADVISOR_HOST}/api/insights/v1/{path}',
                           headers=auth_header)
        res.raise_for_status()
        return res
