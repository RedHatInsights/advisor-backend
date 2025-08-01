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

from re import sub
from urllib.parse import urlparse
from django.conf import settings
from advisor_logging import logger


link_styling = bytes('style="text-decoration: underline; color: blue;"', 'utf-8')


def linkify(url: bytes, link: bytes = b''):
    # can't combine f and b strings...
    if link == b'':
        link = url
    return b''.join([
        b'<a style="text-decoration: underline; color: blue;" href="',
        url, b'">', link, b'</a>'
    ])


def rewrite_urls(get_response):
    """
    Rewrites URLs, CSS & Javascript links in internal.console.* HTML pages
    * Removes /internal/ path from URLs.
    * Rewrites stylesheet links from internal.console.* to console.*
    * Obtains jQuery-3.5.1 from Google coz it's missing from console.*
    """
    def middleware(request):
        response = get_response(request)
        if not ('text/html' in response.get('Content-Type', '')
                and settings.TASKS_REWRITE_INTERNAL_URLS):
            return response

        full_url = request.build_absolute_uri()
        if "/api/tasks/v1/" not in full_url:
            return response

        logger.info(f'Rewriting internal URLs in html document: {full_url}')
        url_components = urlparse(full_url)
        url_location = url_components.scheme + '://' + url_components.netloc
        is_internal = url_components.netloc.startswith('internal.')
        is_dev = settings.ENVIRONMENT == 'dev'

        response.content = sub(
            b'&quot;(?P<path>/api/tasks/v1/.*?)&quot;',
            lambda match: b'&quot;' + linkify(match.group('path')) + b'&quot;',
            response.content
        )

        # Surround the slug name with an <a href> tag to make it clickable - is there a better way!?
        # But only rewrite the instance where the slug name is displayed, not when its part of form data to be submitted
        slug_url_prefix = url_location + ('/internal' if is_internal else '') + '/api/tasks/v1/task/'
        response.content = sub(
            b'(?P<misc> +{\n +?)&quot;slug&quot;: &quot;(?P<slug>.*?)&quot;',
            lambda match: (match.group('misc') + b'"slug": "'
                           + linkify(slug_url_prefix.encode('utf-8') + match.group('slug'), match.group('slug'))
                           + b'"'),
            response.content
        )

        # The links in the page reference cloud.*redhat.com instead of console.*redhat.com, gotta fix that up
        response.content = sub(b'://cloud\\.', b'://console.', response.content)

        # The rest of the changes only apply to the internal editing pages
        if not is_internal:
            return response

        # Surround the pagination links with <a href> tags to make them clickable
        response.content = sub(
            b'&quot;: &quot;(?P<path>\\/internal\\/api\\/tasks\\/v1\\/task\\?limit=.*)&quot;',
            lambda match: b'": "' + linkify(match.group('path')) + b'"',
            response.content
        )

        # The rest of the changes don't apply to dev environment, ie localhost
        if is_dev:
            return response

        # Allow URLs to work when clicked by removing 'internal' from the URL path (but ignore for localhost)
        response.content = sub(b'/internal/api/tasks/v1/task', b'/api/tasks/v1/task', response.content)

        # Get the .css and .js files from console.* because they don't seem to be on internal.console.*
        # Remove 'internal' from the url netloc component
        non_internal_url_prefix = url_components.scheme + '://' + '.'.join(url_components.netloc.split('.')[1:])
        response.content = sub(b'/apps/insights/rest_framework/',
                               bytes(non_internal_url_prefix + '/apps/insights/rest_framework/', 'utf-8'),
                               response.content)

        return response

    return middleware
