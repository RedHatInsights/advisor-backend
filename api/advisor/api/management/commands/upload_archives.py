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
import requests

from django.core.management.base import BaseCommand

from advisor_logging import logger
from api.permissions import auth_header_for_testing


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('archive', type=str)
        parser.add_argument('account', type=str)

    def handle(self, *args, **options):
        UPLOAD_URL = os.environ.get(
            'UPLOAD_URL',
            'http://upload-service.platform-prod.svc:8080/api/ingress/v1/upload'
        )
        archive_dir = options['archive']
        account = options['account']

        logger.info(f'Recieved archive directory from location: {archive_dir}')
        for subdir, dirs, files in os.walk(archive_dir):
            for f in files:
                if f.endswith('.tar.gz'):
                    with open(f'{archive_dir}/{f}', 'rb') as tarfile:
                        archive = tarfile.read()
                        self.upload_archives(UPLOAD_URL, account, (
                            f, archive, 'application/vnd.redhat.advisor.payload+tgz'
                        ))

    def upload_archives(self, url, account, archive_field):
        headers = auth_header_for_testing(account, username='advisor-api')
        logger.info(f'POSTing request to {url} with account {account}')
        response = requests.request(
            'POST', url,
            files={'upload': archive_field},
            headers=headers
        )

        assert response.status_code == 202, \
            f'Response status {response.status_code} is not 202, ' \
            f'raised error: {response.content.decode()}'
        logger.info(f'Successfully POSTed Archive to {url}')
