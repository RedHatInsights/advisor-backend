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

from datetime import datetime, timezone
from urllib.parse import quote

from django.db.models import Q
from django.http import HttpRequest
from django.test import TestCase
from django.utils.datastructures import MultiValueDict

from rest_framework.serializers import ValidationError
from drf_spectacular.types import OpenApiTypes

from api.filters import (
    OpenApiParameter, value_of_param, filter_on_param, filter_multi_param,
    incident_query_param, filter_on_host_tags
)


def make_request_obj(**kwargs):
    rq = HttpRequest()
    rq.query_params = MultiValueDict({k: [v] for k, v in kwargs.items()})
    return rq


class ParameterParsingTestCase(TestCase):
    def test_bad_array_collection_format(self):
        # Missing collection format
        p = OpenApiParameter(
            name='p', location=OpenApiParameter.QUERY,
            many=True, type=OpenApiTypes.INT,
        )
        r = make_request_obj(p=3)
        with self.assertRaisesRegex(
            ValidationError, r"Coding error: parameter has many=True but no 'style' set"
        ):
            value_of_param(p, r)
        # No idea how to split header parameters
        p = OpenApiParameter(
            name='p', location=OpenApiParameter.HEADER,
            many=True, type=OpenApiTypes.INT, style='form',
        )
        with self.assertRaisesRegex(
            ValidationError, r"Coding error: We do not know how to split parameters in the 'header'"
        ):
            value_of_param(p, r)
        # Unknown collection format
        p = OpenApiParameter(
            name='p', location=OpenApiParameter.QUERY,
            many=True, type=OpenApiTypes.INT, style='spooled',
        )
        with self.assertRaisesRegex(
            ValidationError, r"Coding error: Invalid query array parameter style 'spooled'"
        ):
            value_of_param(p, r)
        # Not an array but has the style set
        p2 = OpenApiParameter(
            name='p', location=OpenApiParameter.QUERY,
            type=OpenApiTypes.INT, style='spooled',
        )
        with self.assertRaisesRegex(
            ValidationError, r"Coding error: parameter has many=False but style=spooled"
        ):
            value_of_param(p2, r)

    def test_array_on_single_param(self):
        # Bug ADVISOR-3047 - query of the form:
        # GET https://console.redhat.com/api/insights/v1/system/?\
        # sort=-last_seen&limit=20&offset=0&hits=all&incident=false&incident=true
        # - i.e. two `incident` parameters given on a parameter that does not
        # take multiple parameters.  This should preferably return a 400, as
        # a bad request; the bug causes the `flatten` function in utils to
        # try to iterate across a boolean and causes a 500.
        single = OpenApiParameter(
            name='single', location=OpenApiParameter.QUERY, type=OpenApiTypes.INT,
        )
        r1 = make_request_obj(single=1)
        r1.query_params.appendlist('single', 2)
        with self.assertRaises(ValidationError):
            value_of_param(single, r1)
        # But in the special case of the incident parameter, where it's a
        # boolean and both 'true' and 'false' have been given, we want to just
        # pretend that the parameter wasn't given
        r2 = make_request_obj(incident=False)
        r2.query_params.appendlist('incident', True)
        with self.assertRaises(ValidationError):
            value_of_param(incident_query_param, r2)
        # Should also occur if both values are the same
        r3 = make_request_obj(incident=False)
        r3.query_params.appendlist('incident', False)
        with self.assertRaises(ValidationError):
            value_of_param(incident_query_param, r3)

    def test_array_already_supplied(self):
        # If the request has already broken down the parameter's value into
        # a list, e.g. because it's been supplied as key=value1,key=value2,
        # then don't try to split the value further.
        p1 = OpenApiParameter(
            name='p1', location=OpenApiParameter.QUERY,
            many=True, type=OpenApiTypes.INT, style='form',
        )
        r1 = make_request_obj(p1=1)
        # Supply parameters in the list format that QueryParams will use.
        r1.query_params.appendlist('p1', 2)
        v1 = value_of_param(p1, r1)
        self.assertEqual(v1, [1, 2])
        # Supply multiple parameters, and parameters as CSV:
        r2 = make_request_obj(p1=1)
        # Supply parameters in the list format that QueryParams will use.
        r2.query_params.appendlist('p1', '2,3')
        v2 = value_of_param(p1, r2)
        self.assertEqual(v2, [1, 2, 3])
        # For some reason we can't trigger the 'elif isinstance(value, list):'
        # code here, probably because we're invoking MultiValueDict directly
        # rather than using the DRF code to pick up the values.  But other
        # tests check that 'p=1,2,3' works correctly.

    def test_array_not_supplied(self):
        # List parameters need to accept single values
        p1 = OpenApiParameter(
            name='p1', location=OpenApiParameter.QUERY,
            many=True, type=OpenApiTypes.INT, style='form',
        )
        r1 = make_request_obj(p1=1)
        v1 = value_of_param(p1, r1)
        self.assertEqual(v1, [1])

    def test_numeric_parameter(self):
        # Correct parameter parsing
        p1 = OpenApiParameter(
            name='p1', location=OpenApiParameter.QUERY,
            type=OpenApiTypes.NUMBER
        )
        r1 = make_request_obj(p1='12.345')
        self.assertEqual(value_of_param(p1, r1), 12.345)
        # Check filtering on this parameter to test non-array parameters.
        q = filter_on_param('p1', p1, r1)
        self.assertIsInstance(q, Q)
        # Failure
        p2 = OpenApiParameter(
            name='p2', location=OpenApiParameter.QUERY,
            type=OpenApiTypes.NUMBER
        )
        r2 = make_request_obj(p2='foo')
        with self.assertRaisesRegex(
            ValidationError, r"The value must be a floating point number"
        ):
            value_of_param(p2, r2)

    def test_datetime_parameter(self):
        # Correct parameter parsing - naive datetime
        p1 = OpenApiParameter(
            name='p1', location=OpenApiParameter.QUERY,
            type=OpenApiTypes.DATETIME
        )
        r1 = make_request_obj(p1='2018-01-02T03:04:05')
        self.assertEqual(value_of_param(p1, r1), datetime(2018, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

        # Correct parameter parsing - aware datetime
        p2 = OpenApiParameter(
            name='p2', location=OpenApiParameter.QUERY,
            type=OpenApiTypes.DATETIME
        )
        r2 = make_request_obj(p2='2018-01-02T03:04:05Z')
        self.assertEqual(value_of_param(p2, r2), datetime(2018, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

        # Invalid parameter parsing
        p3 = OpenApiParameter(
            name='p3', location=OpenApiParameter.QUERY,
            type=OpenApiTypes.DATETIME
        )
        r3 = make_request_obj(p3='When Mohandas Ghandi was born')
        with self.assertRaisesRegex(
            ValidationError, r"The value did not look like a datetime"
        ):
            value_of_param(p3, r3)


class HostTagsParameterParsingTestCase(TestCase):
    """
    Tests for parsing of one or more host tags query parameters.  The rules are:

    * Each parameter has a namespace, key, and value.
    * All three segments must have slashes and equals signs URI encoded
    * Other unicode characters are allowed but URI encoding is OK as well.

    The function returns a Django Q object - we're not going to test if that
    actually does what we asked it to.  We're just going to check that valid
    parameters are OK and invalid parameters get rejected.  We can also make
    sure it returned a Q object with some conditions, as Q() evaluates to empty.
    """
    def test_single_tag_parameter(self):
        q = filter_on_host_tags(make_request_obj(
            tags='namespace/key=value'
        ))
        self.assertIsInstance(q, Q)
        self.assertTrue(q)

        # Caught by parameter regular expression
        with self.assertRaisesRegex(
            ValidationError, r"The value did not match the pattern"
        ):
            filter_on_host_tags(make_request_obj(
                tags=''
            ))

    def test_invalid_tags(self):
        with self.assertRaises(ValidationError):
            filter_on_host_tags(make_request_obj(
                tags='key=value'
            ))

        with self.assertRaises(ValidationError):
            filter_on_host_tags(make_request_obj(
                tags='key'
            ))

        with self.assertRaises(ValidationError):
            filter_on_host_tags(make_request_obj(
                tags='namespace/key'
            ))

    def test_multiple_tags_in_parameter(self):
        q = filter_on_host_tags(make_request_obj(
            tags='namespace/key=value,Sat/env=prod'
        ))
        self.assertIsInstance(q, Q)
        self.assertTrue(q)

    def test_quoted_parameters(self):
        def make_param_value(namespace, key, value):
            ns = quote(namespace, safe='') + '/' if namespace else ''
            val = '=' + quote(value, safe='') if value else ''
            return ns + quote(key, safe='') + val

        q = filter_on_host_tags(make_request_obj(
            tags=make_param_value('AWS', '#any/old=characters', 'true')
        ))
        self.assertIsInstance(q, Q)
        self.assertTrue(q)
        q = filter_on_host_tags(make_request_obj(
            tags=make_param_value('огурцы', 'пугают', 'кошек')
        ))
        self.assertIsInstance(q, Q)
        self.assertTrue(q)


class MultiParamParsingTestCase(TestCase):
    """
    Test the 'filter_multi_param' parsing.
    """
    def _make_request_obj(self, param_name, value=None):
        # Set the query param directly, because these parameter names can't
        # be expressed as kwargs.
        rq = HttpRequest()
        rq.query_params = MultiValueDict()
        rq.query_params[param_name] = value
        return rq

    def test_parameter_syntax_bad(self):
        # Only badly formed parameters after the actual filter keyword should
        # cause a 400.
        with self.assertRaises(ValidationError):
            filter_multi_param(self._make_request_obj(
                'filter[fail][word@here]', 'yes'
            ), 'fail')
        with self.assertRaises(ValidationError):
            filter_multi_param(self._make_request_obj(
                'filter[fail][after[initial_keyword]]',
            ), 'fail')
        # Everything that doesn't start with filter[{filter_param}][ is ignored
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[missing_close[complete_close]', 'ok'
            ), 'missing'), Q()
        )
        # If it's not the 'filter' parameter, then ignore.
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[fail', 'true'
            ), 'fail'), Q()
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'nonmatch[test]', 'ok'
            ), 'test'), Q()
        )
        # If it's not the filter prefix, then ignore.
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[something_else]', 'ok'
            ), 'test'), Q()
        )

    def test_basic_string_matching(self):
        # No operator or value conversions
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][start]', 'ok'
            ), 'system_profile'),
            Q(system_profile__start='ok')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][service_status][chrony]', 'started'
            ), 'system_profile'),
            Q(system_profile__service_status__chrony='started')
        )
        # Values don't have to be words...
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][installed_packages][contains]', "python3-libs-0:3.6.8-23.el8.x86_64"
            ), 'system_profile'),
            Q(system_profile__installed_packages__contains="python3-libs-0:3.6.8-23.el8.x86_64")
        )
        # No conversion on numbers not given 'eq' as operator
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][account]', '1234567'
            ), 'system_profile'),
            Q(system_profile__account='1234567')
        )

    def test_value_conversion(self):
        # Boolean conversions
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][started]', 'true'
            ), 'system_profile'),
            Q(system_profile__started=True)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][started]', 'True'
            ), 'system_profile'),
            Q(system_profile__started=True)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][started]', 'false'
            ), 'system_profile'),
            Q(system_profile__started=False)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][started]', 'False'
            ), 'system_profile'),
            Q(system_profile__started=False)
        )
        # Numeric conversions - parameter as string as if from query string
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][gt]', '2'
            ), 'system_profile'),
            Q(system_profile__num_cpus__gt=2)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][gte]', '2'
            ), 'system_profile'),
            Q(system_profile__num_cpus__gte=2)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][lt]', '2'
            ), 'system_profile'),
            Q(system_profile__num_cpus__lt=2)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][lte]', '2'
            ), 'system_profile'),
            Q(system_profile__num_cpus__lte=2)
        )
        # 'eq' operator forces numeric conversion
        # Old eq method
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][eq]', '2'
            ), 'system_profile', use_contains_for_eq=False),
            Q(system_profile__num_cpus=2)
        )
        # New eq-as-contains method
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][eq]', '2'
            ), 'system_profile'),
            Q(system_profile__contains={'num_cpus': 2})
        )
        # Numeric conversions - parameter must be an integer
        with self.assertRaises(ValidationError):
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][gt]', 'a lot'
            ), 'system_profile')
        with self.assertRaises(ValidationError):
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][gte]', 'a lot'
            ), 'system_profile')
        with self.assertRaises(ValidationError):
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][lt]', 'a lot'
            ), 'system_profile')
        with self.assertRaises(ValidationError):
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][lte]', 'a lot'
            ), 'system_profile')
        # 'eq' and 'ne' will not convert value if it isn't digits.

    def test_comparators_as_given(self):
        # 'eq' and 'contains'
        # New eq=contains method
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][arch][eq]', 'x86_64'
            ), 'system_profile'),
            Q(system_profile__contains={'arch': 'x86_64'})
        )
        # Old eq method
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][arch][eq]', 'x86_64'
            ), 'system_profile', use_contains_for_eq=False),
            Q(system_profile__arch='x86_64')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][installed_services][contains]', 'microcode'
            ), 'system_profile'),
            Q(system_profile__installed_services__contains='microcode')
        )

    def test_multi_contains_operators(self):
        # Have to put the first and append the second for this test case
        rq = self._make_request_obj(
            'filter[system_profile][cpu_flags][contains][]', 'fpu'
        )
        rq.query_params.appendlist('filter[system_profile][cpu_flags][contains][]', 'mtrr')
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__cpu_flags__contains='fpu') & Q(system_profile__cpu_flags__contains='mtrr')
        )
        # Also support without final empty brackets
        rq = self._make_request_obj(
            'filter[system_profile][sap_sids][contains]', 'E24'
        )
        rq.query_params.appendlist('filter[system_profile][sap_sids][contains]', 'E04')
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__sap_sids__contains='E24') & Q(system_profile__sap_sids__contains='E04')
        )

    def test_multi_in_operators(self):
        rq = self._make_request_obj(
            'filter[system_profile][system_update_method][in]', 'dnf'
        )
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__system_update_method__in=['dnf'])
        )
        rq.query_params.appendlist('filter[system_profile][system_update_method][in]', 'yum')
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__system_update_method__in=['dnf', 'yum'])
        )
        # Comma separated works as well
        rq = self._make_request_obj(
            'filter[system_profile][system_update_method][in]', 'yum,dnf'
        )
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__system_update_method__in=['yum', 'dnf'])
        )

    def test_comparator_conversion(self):
        # 'ne' changes sense for both integer and string comparisons
        # Old style eq comparison
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][ne]', '8'
            ), 'system_profile', use_contains_for_eq=False),
            ~Q(system_profile__num_cpus=8)
        )
        # New style eq=contains comparison
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][num_cpus][ne]', '8'
            ), 'system_profile'),
            ~Q(system_profile__contains={'num_cpus': 8})
        )
        # Old style eq comparison
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][arch][ne]', 'ppc64le'
            ), 'system_profile', use_contains_for_eq=False),
            ~Q(system_profile__arch='ppc64le')
        )
        # New style eq=contains comparison
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][arch][ne]', 'ppc64le'
            ), 'system_profile'),
            ~Q(system_profile__contains={'arch': 'ppc64le'})
        )
        # 'starts_with', 'ends_with', and the case insensitive comparators
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][arch][starts_with]', 'ppc'
            ), 'system_profile'),
            Q(system_profile__arch__startswith='ppc')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][arch][ends_with]', '64'
            ), 'system_profile'),
            Q(system_profile__arch__endswith='64')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][infrastructure_vendor][eq_i]', 'KVM'
            ), 'system_profile'),
            Q(system_profile__infrastructure_vendor__iexact='KVM')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][contains_i]', 'ABI'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__icontains='ABI')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][starts_with_i]', 'SEA'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__istartswith='SEA')
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][ends_with_i]', 'BIOS'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__iendswith='BIOS')
        )

    def test_nil_not_nil(self):
        # No value is acceptable
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][nil]',
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=True)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][not_nil]',
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=False)
        )
        # we also accept 'true', 'True', 'false' and 'False'.
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][nil]', 'true'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=True)
        )
        # Any other string is treated as True
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][nil]', 'very yes'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=True)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][nil]', 'False'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=False)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][not_nil]', 'True'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=False)
        )
        self.assertEqual(
            filter_multi_param(self._make_request_obj(
                'filter[system_profile][bios_vendor][not_nil]', 'false'
            ), 'system_profile'),
            Q(system_profile__bios_vendor__isnull=True)
        )

    def test_field_prefix(self):
        self.assertEqual(
            filter_multi_param(
                self._make_request_obj(
                    'filter[system_profile][bios_vendor][nil]', 'true'
                ),
                'system_profile', field_prefix='inventory_host'
            ), Q(inventory_host__system_profile__bios_vendor__isnull=True)
        )
        # Old ne method
        self.assertEqual(
            filter_multi_param(
                self._make_request_obj(
                    'filter[system_profile][num_cpus][ne]', '8'
                ),
                'system_profile', field_prefix='inventory_host',
                use_contains_for_eq=False
            ), ~Q(inventory_host__system_profile__num_cpus=8)
        )
        # New ne-as-contains method
        self.assertEqual(
            filter_multi_param(
                self._make_request_obj(
                    'filter[system_profile][num_cpus][ne]', '8'
                ),
                'system_profile', field_prefix='inventory_host'
            ), ~Q(inventory_host__system_profile__contains={'num_cpus': 8})
        )

    def test_multiple_parameters(self):
        # Both parameters match the filter prefix
        rq = self._make_request_obj('filter[system_profile][sap_system]', 'true')
        rq.query_params['filter[system_profile][bios_vendor][nil]'] = 'true'
        # Note that AND comparisons on Q objects are order dependent.
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__sap_system=True) & Q(system_profile__bios_vendor__isnull=True)
        )
        # One parameter doesn't match the filter prefix, the other does
        rq = self._make_request_obj('filter[system_profile][sap_system]', 'true')
        rq.query_params['filter[facts][bios_vendor][nil]'] = 'true'
        # Note that AND comparisons on Q objects are order dependent.
        self.assertEqual(
            filter_multi_param(rq, 'system_profile'),
            Q(system_profile__sap_system=True)
        )
