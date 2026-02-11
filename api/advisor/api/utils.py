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

from app_common_python import LoadedConfig
from os import path
import requests
import thread_storage
import time

from django.conf import settings

from django.core.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.utils.urls import replace_query_param

from advisor_logging import logger


# Note: we don't import from api.models here because of possible circular
# dependencies.

##############################################################################
# File system navigation
##############################################################################

def resolve_path(*paths):
    """
    Resolve the path given relative to the module calling this function.
    """
    # Resolve all paths relative to repository root, which is three
    # directories up.
    base_repo_path = path.normpath(path.join(path.dirname(__file__), "../../../"))
    return path.join(base_repo_path, *paths)


##############################################################################
# Pagination
##############################################################################


class CustomPageNumberPagination(LimitOffsetPagination):
    """Create standard paginiation class with page size."""

    default_limit = 10
    max_limit = 1000

    @staticmethod
    def link_rewrite(request, link):
        """Rewrite the link based on the path header to only provide partial url."""
        url = link
        version = 'v{}/'.format(settings.API_VERSION)
        if 'PATH_INFO' in request.META:
            try:
                local_api_index = link.index(version)
                path = request.META.get('PATH_INFO')
                path_api_index = path.index(version)
                path_link = '{}{}'
                url = path_link.format(path[:path_api_index],
                                       link[local_api_index:])
            except ValueError:
                logger.warning('Unable to rewrite link as "{}" was not found.'.format(version))
        return url

    def get_first_link(self):
        """Create first link with partial url rewrite."""
        url = self.request.build_absolute_uri()
        offset = 0
        first_link = replace_query_param(url, self.offset_query_param, offset)
        first_link = replace_query_param(first_link, self.limit_query_param, self.limit)
        return CustomPageNumberPagination.link_rewrite(self.request, first_link)

    def get_next_link(self):
        """Create next link with partial url rewrite."""
        next_link = super().get_next_link()
        if next_link is None:
            return self.get_last_link()
        return CustomPageNumberPagination.link_rewrite(self.request, next_link)

    def get_previous_link(self):
        """Create previous link with partial url rewrite."""
        previous_link = super().get_previous_link()
        if previous_link is None:
            return self.get_first_link()
        return CustomPageNumberPagination.link_rewrite(self.request, previous_link)

    def get_last_link(self):
        """Create last link with partial url rewrite."""
        url = self.request.build_absolute_uri()
        offset = self.count - self.limit if (self.count - self.limit) >= 0 else 0
        last_link = replace_query_param(url, self.offset_query_param, offset)
        last_link = replace_query_param(last_link, self.limit_query_param, self.limit)
        return CustomPageNumberPagination.link_rewrite(self.request, last_link)

    def get_paginated_response(self, data):
        """Override pagination output."""
        return Response({
            'meta': {
                'count': self.count,
            },
            'links': {
                'first': self.get_first_link(),
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'last': self.get_last_link()
            },
            'data': data
        })

    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object',
            'properties': {
                'meta': {
                    'type': 'object',
                    'properties': {
                        'count': {
                            'type': 'integer',
                            'example': 169
                        },
                    },
                    'required': ['count'],
                },
                'links': {
                    'type': 'object',
                    'properties': {
                        "first": {
                            "type": "string",
                            "format": "uri",
                            "nullable": True
                        },
                        "previous": {
                            "type": "string",
                            "format": "uri",
                            "nullable": True
                        },
                        "next": {
                            "type": "string",
                            "format": "uri",
                            "nullable": True
                        },
                        "last": {
                            "type": "string",
                            "format": "uri",
                            "nullable": True
                        }
                    },
                },
                'data': schema
            }
        }


class PaginateMixin(object):
    """
    Adds a helper method to paginate a queryset

    For pagination, we could use rest_framework.mixins.ListModelMixin on a ViewSet
    but since we tend to need a customized 'list' method, this can be used to get a paginated
    response

    Expects that the ViewSet has a 'serializer_class' and 'pagination_class' defined.
    """
    def _paginated_response(
        self, queryset, request=None, serializer_class=None, page_annotator_fn=None
    ):
        serializer_class = serializer_class or self.serializer_class
        page = self.paginate_queryset(queryset)
        if page_annotator_fn:
            assert request is not None, "Request must be passed when using an annotator function"

        if page is not None:
            # Allow the page to have (costly, non-DB) annotations added
            if page_annotator_fn is not None:
                page = page_annotator_fn(request, page)
            serializer = serializer_class(page, many=True, context={'request': request})
            data = serializer.data
            response = self.get_paginated_response(data)
        else:
            # Fall back to standard serialization if pagination is not configured/fails
            data = serializer_class(queryset, many=True, context={'request': request}).data
            response = Response(data)

        return response


##############################################################################
# Standardised request retry interface
##############################################################################


def retry_request(
    service: str, url: str,
    mode: str = 'get', max_retries: int = 3, time_exponent: float = 5.0,
    retry_timeouts: bool = False, **kwargs
) -> tuple[requests.Response, float]:
    """
    Requests the given URL, by GET or `mode` if set, up to `max_retries` (3)
    times, with an exponential timeout (of `time_exponent ** (retry - 2)`
    seconds).  Default time out for any request is 10 seconds. Server failures
    of status 500 and above, and connection errors, are caught and logged.
    Extra arguments such as headers and data can be passed to the request
    method via kwargs.

    Returns (response object, monotonic time taken for total request).  If the
    request failed because of a connection error, the 'response object' is
    False.
    """
    req_start = time.monotonic()
    retry = 0
    request_succeeded = False
    # Set up a valid but failed response object to let type checking get the
    # return value right.  We always get to the `response = requests.request`
    # lines, so we should always have a valid Response object in `response`.
    response = requests.Response()
    response.status_code = 599
    response._content = b'No connection made'
    # request_succeeded = true breaks out later
    while retry < max_retries:
        retry += 1
        # Exponential back-off - 0.2, 1, 5 seconds - need to stay under
        # ten seconds total to prevent OpenShift timing us out.
        sleep_time = time_exponent ** (retry - 2) if settings.ENVIRONMENT != 'dev' else 0.01
        try:
            if "verify" in kwargs:
                response = requests.request(mode.upper(), url, **kwargs)
            else:
                response = requests.request(mode.upper(), url, verify=LoadedConfig.tlsCAPath, **kwargs)
            request_succeeded = (response.status_code < 500)
            if not request_succeeded:
                logger.warning(
                    f"Warning: got {response.status_code} status from {service}: '{response.content.decode()}' - retry {retry} in {sleep_time} seconds"
                )
        except ConnectionError as e:
            # PJW: A bit too broad for my tastes but we'll see how it goes...
            logger.warning(
                f"Warning: got exception from {service}: '{e}' - retry {retry} in {sleep_time} seconds"
            )
        except requests.ConnectionError as e:
            logger.warning(
                f"Warning: got requests exception from {service}: '{e}' - retry {retry} in {sleep_time} seconds"
            )
        except requests.exceptions.Timeout as e:
            logger.error(
                f"Error: Timed out reached for {service}: '{e}'"
            )
            if not retry_timeouts:
                return (response, time.monotonic() - req_start)
        if request_succeeded:
            break
        time.sleep(sleep_time)
    if not request_succeeded:
        logger.error(
            f"Request to {service} failed after {retry} tries."
        )
    return (response, time.monotonic() - req_start)


##############################################################################
# Middleware interface
##############################################################################


def user_account_details(username):
    """
    Request the user account details from the middleware API.
    """
    if not settings.MIDDLEWARE_HOST_URL:
        raise ValidationError("Request for account details with Middleware host URL not defined")
    users = username if isinstance(username, list) else [username]
    logger.debug("Retrieving account details for users %s for weekly report emails", users)
    response, elapsed = retry_request(
        'middleware',
        settings.MIDDLEWARE_HOST_URL + '/users?include_permissions=false',
        mode='post',
        json={'users': users},
        verify=settings.MIDDLEWARE_CERT_FILE,
        headers={
            'x-rh-apitoken': settings.MIDDLEWARE_API_TOKEN,
            'x-rh-clientid': settings.MIDDLEWARE_CLIENT_ID,
        },
        timeout=10,
        retry_timeouts=True,
    )
    if response and response.status_code == 200:
        # The response is a list of dicts, with at least the 'username' key
        # in each dict.
        return response.json()
    else:
        if response:
            err_msg = (
                f"Problem retrieving account details: "
                f"{response.status_code} - {response.content.decode()}"
            )
        else:
            err_msg = "Connection error retrieving account details"
        logger.error(err_msg)
        raise ValidationError(err_msg)


#######################################################
# POST data storage helper
#######################################################

def store_post_data(request, serializer_class=None, **kwargs):
    post_data = {'data': request.data}
    if serializer_class is not None:
        serdata = serializer_class(data=request.data, **kwargs)
        if serdata.is_valid():
            post_data['validity'] = 'valid'
            post_data['validated_data'] = serdata.validated_data
        else:
            post_data['validity'] = 'invalid'
            post_data['errors'] = serdata.errors
    thread_storage.set_value('post', post_data)
