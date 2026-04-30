# The Advisor API in Django

This is an implementation of the Insights API in Django 5.2, which
requires Python 3.12 or above.

See the main [README](../README.md) document for more information about
Advisor's purpose and structure.

# Advisor API overview

The Advisor API actually covers three APIs:

- The main Advisor API, handling URLs starting with `/api/insights/v1/`, is
  in `api/advisor/api/`.
- The Satellite Compatibility API, handling URLs starting with `/r/insights/`,
  is in `api/advisor/sat_compat/`.  The [README](advisor/sat_compat/README.md)
  there gives more information about what that is for.
- The Tasks API, handling URLs starting with `/api/tasks/v1/`, is in
  `api/advisor/tasks/`.  The [README](advisor/tasks/README.md) there gives
  more information about the Tasks app.

## Install instructions

- Get the code:

    `git clone https://github.com/RedHatInsights/insights-advisor`

- Setup virtualenv dev environment

    ```
    cd insights-advisor
    pip install pipenv
    pipenv install --dev
    pipenv shell
    ````

- Running Advisor

    You can run advisor manually on the host, or you can run it via podman
    containers controlled by podman-compose.  You can also do both if you
    wish.

### Running Advisor via podman-compose

You can run Advisor as a series of podman containers controlled by
podman-compose.  You will need to have podman and podman-compose installed on
your development machine.

- To build the advisor-api container run `podman-compose build advisor-api`

- Start the containers with `podman-compose up`

- Point a browser at `http://localhost:8000/api/insights/v1` to browse the api.

- Use `podman-compose stop/start` to control the containers.

Note, the advisor-db/postgresql container is non-persistent so its data is
lost when the container is deleted, for example if you run `podman-compose
down`.  `podman-compose up` will re-initialize the data.


### Running Advisor manually on the host

You can also run Advisor from the host.  Here's how ...

- Install the Django database

    The application uses a PostgreSQL database by default.  You can install
    PostgreSQL using the `postgresql-*` packages and use `psql` to configure
    it according the settings in `settings.py`.

    Or you can use a postgresql container, eg PostgreSQL 12 from the Red Hat
    Container Catalog:
    ```
    $ podman run -d --name db -p 5432:5432 -e POSTGRESQL_USER=insightsapi \
        -e POSTGRESQL_PASSWORD=InsightsData -e POSTGRESQL_DATABASE=insightsapi \
        registry.access.redhat.com/rhscl/postgresql-12-rhel7
    ```

- Start gunicorn to serve the API

    ```
    $ ./app.sh
    [2018-06-21 14:30:23 -0400] [31722] [INFO] Starting gunicorn 19.8.1
    [2018-06-21 14:30:23 -0400] [31722] [INFO] Listening at: http://0.0.0.0:8000 (31722)
    ...
    ```

- Populating the database

    You will need to populate the database in order to test the API.  To
    create and populate the tables run:

    ```
    $ api/advisor/manage.py migrate
    $ api/advisor/manage.py loaddata rulesets rule_categories system_types \
                            basic_test_data
    $ api/advisor/manage.py freshen_hosts
    ````

    Then point a browser at `http://localhost:8000/api/insights/v1` and you
    should be able to browse the api.

# Updating

If you've already got this project checked out and running, and want to see
the latest work, then you really just need to do:

```
$ git pull
$ api/advisor/manage.py migrate
```

If you are using podman-compose, run `podman-compose build` to rebuild the
advisor-api container image and then restart the advisor-api container.

# Mechanisms within the API

## Host staleness and reporters

Hosts report into the Hybrid Cloud Console in a variety of ways.  Originally
the only way was via the `insights-client` program uploading a snapshot of
the system every night.  Then other ways of tracking a system's status were
added - using `subscription-manager` reporting, and via Satellites reporting
their host inventory.

In order for the Inventory to not get cluttered with systems that had uploaded
once and were then forgotten, systems over three weeks old are hidden from view.
Then after another week they are removed from the database; this allows a
bit of grace time for a sysadmin to get the host reporting again after they
realise it's disappeared from their view.

Inventory controls host staleness and culling using two sets of fields:

  * the `stale_timestamp`, `stale_warning_timestamp` and `culled_timestamp`
    fields, set by any reporter.
  * the `per_reporter_staleness` field, which relies on the `puptoo` object
    having a `stale_timestamp` field.

Advisor only cares about one reporter - puptoo (which is the service that
receives uploads from the `insights-client`).  The `updated` and `last_check_in`
fields are updated by any reporter; it is therefore possible for a system
that hasn't been turned on in a week to have its Satellite report it as still
up to date in Inventory.  So Advisor only uses the `stale_warning_timestamp`
field from the `per_reporter_staleness.puptoo` object.

The system's `last_seen` date is drawn from Advisor's own `Upload` model,
which stores the `checked_on` date from when this system last actually
performed an upload that went into Advisor.

The InventoryHost model controls this using a filter applied in the
`for_account` manager method.  This makes sure that hosts that are currently
stale according to Puptoo are always filtered out.

The basic test data by default has these dates in the past, and these dates
may elapse as you work.  To freshen the test data you can use the command:

`api/advisor/manage.py freshen_hosts`

This will update all the host timestamps according to the following rules:

  * Hosts whose name starts with `stale-warn` have their `stale_timestamp`
    timeset one day in the past.
  * Hosts whose name starts with `stale-hide` have their `stale_timestamp`
    set three days in the past and their `stale_warning_timestamp` set one
    day in the past.
  * Hosts whose name starts with `culled` have their `stale_timestamp`
    set three days in the past, their `stale_warning_timestamp` set three
    days in the past, and their `culled_timestamp` set one day in the past.
  * All other timestamps are set to sixty days in the future.

## Authentication and permissions

The Advisor API is primarily designed to sit behind the 3Scale API Management
platform.  The 3Scales provide a HTTP header with a Base64-encoded JSON payload
containing the user's identity information.  The payload is expected to be a JSON
object with the following structure:

```json
{
  "identity": {
    "account_number": "1234567",
    "org_id": "9876543",
    "type": "User",
    "auth_type": "jwt",
    "user": {
      "username": "testing",
      "is_internal": true
    }
  }
}
```

This is stored in the `HTTP_X_RH_IDENTITY` header within the request.

This data is checked by the Django REST Framework's Authentication and
Permissions classes to allow or deny access to the API endpoints.  The
Authentication classes are responsible for verifying the user's identity and
permissions, while the Permissions classes are responsible for checking whether
the user has the necessary permissions to access a particular endpoint.

These classes and associated functions are in `api/advisor/api/permissions.py`.

### Authentication

The default Authentication class used is `RHIdentityAuthentication`. This is set
in `api/project_settings/settings.py` in the DEFAULT_AUTHENTICATION_CLASSES
list. Authentication classes will return success, or raise an
AuthenticationFailed exception.

`RHIdentityAuthentication` does the following checks:

- The HTTP_X_RH_IDENTITY header has to be provided, and has to Base64 decode
  into a JSON object with the following structure (via `get_identity_header()`):
  - It has to have an 'identity' key, which has to contain a dict.
- The identity has to have an `org_id` field which mut be a string; integers
  are converted to strings.
- The identity must have a `type` field.

The `org_id` field the sets the scope of queries on systems for the user. This
is primarily checked in the `get_reports_subquery()` and
`get_systems_queryset()` functions in `models.py` but is used in all queries
that need to limit their responses to data in the user's organisation.

The alternative authentication class is `TurnpikeIdentityAuthentication`, which
is used when authenticating internal requests.  This checks more parts of the
identity:

- The HTTP_X_RH_IDENTITY header has to be provided, and has to Base64 decode
  into a JSON object with the following structure (via `get_identity_header()`):
  - It has to have an 'identity' key, which has to contain a dict.
- The identity has to have an `auth_type` field, as a string, which must have
  the value 'saml-auth'.
- The identity has to have a `type` field, as a string, which must have the
  value 'Associate'.
- The identity has to have an `associate` field, as a dict.

### Permissions

The two default Permission classes are `InsightsRBACPermission` and
`CertAuthPermission`.  These apply to almost all viewsets.  These are usually
'or'ed together so that as long as either one matches, permission is granted.

Django REST Framework permission classes normally only return `True` or `False`
to indicate whether the request is allowed or not.  This means there is no
standard way of indicating why the request was denied - the standard DRF
message of 'You do not have permission to perform this action.' is supplied.
Internal messaging is stored and reported in logs for debugging.

#### InsightsRBACPermission

`InsightsRBACPermission` applies to both user and service account checks.
The user identity as decoded by `RHIdentityAuthentication` is further checked:

- The `request_to_user_data()` function gets the user data related to the user
  or service account.  This must have a `username` field as a string.
- If RBAC is not enabled at this point (the `RBAC_ENABLED` setting), permission
  is granted.
- Otherwise, we map the request to a permission of the form `app:resource:action`,
  where 'app' is 'advisor', 'resource' is set by the view or viewset class (
  see the `resource_name` property on the viewset classes), and 'action' is
  either 'read' or 'write'.
- If Kessel is enabled, we ask the SpiceDB server via gRPC (see `kessel.py`)
  whether the user is allowed access.  This requires the `user_id` field in the
  user data to be set.
- Otherwise, we ask the RBACv1 server for user's list of permissions (see
  `has_rbac_permission()`).

#### CertAuthPermission

`CertAuthPermission` applies to systems that have authenticated with a
certificate:

- the identity must have a `system` field which must be a dictionary.
- the system field must have a 'cn' field which must be a UUID in string form.
  The actual UUID is not checked.

### Other permissions classes.

We also have other permissions classes that are used for specific use cases.

- `AssociatePermission` simply checks that the request's identity has an
  'associate' field.
- `IsRedHatInternalUser` checks that the user data has an 'is_internal' field
  and that field evaluates to `True`.
- `OrgPermission` simply checks that request's identity data has an 'org_id' field.
- `TasksRBACPermission`, defined in `api/advisor/tasks/permissions.py`, is
  functionally identical to `InsightsRBACPermission` and simply changes the app
  name used in the RBAC permissions check from 'advisor' to 'tasks'.

### Views without permissions

- KCS, rule categories, rule ratings, playbook listings, application status, and
  system types are all able to be viewed with no permissions checks in Advisor.
  They're still only available through the 3Scale gateway.
- For the Satellite compatibility layer, articles, branch_info, CVEs,
  evaluation status, groups, application status (ping), and plugins are all
  viewable with no permissions.  This in general means that their data does not
  change for different users; they're really only there because the 

## Query filtering

The Advisor API tries to follow a consistent pattern in filtering queries.
To explain this, let's imagine you want to filter on a new keyword in the
URL's query section (i.e. everything after the `?` in the URL).

- This is the 'role' parameter.  It can be one of 'database', 'webserver',
  'storage' or 'other'.
- This is stored within the 'display_name' field of the server - if the name
  starts with 'db-', it's a database server; if it starts with 'web-' then
  it's a webserver' 's3-' denotes a storage server; and if it doesn't match
  any of those then it's an 'other' server.
- This should be applied to all queries that filter servers.

Within the API, query filtering is primarily defined in the `filters.py` file.
Filters that are applied in many places, such as our example `role` query
filter, have their definitions stored in the `filter.py` file.  Filters that
are applied only in one set of views are usually defined in the view file.

### The parameter definition

First, we need to define an `OpenApiParameter` object for this new parameter.
The query parameters are arranged roughly in alphabetical order for the
convenience of humans reading the code.  So we'd define this new parameter as:

```py
system_role_query_param = OpenApiParameter(
    name='role', location=OpenApiParameter.QUERY, required=False,
    description='Filter servers by their role',
    enum=('database', 'webserver', 'storage', 'other'),
)
```

### The filter function

We also need a filter function that takes the request object and returns a
Django `Q()` object that can be applied to the query being generated.

In many cases, the Django queryset being filtered is simple enough that we
can use the `filter_on_param(value, parameter, request)` function (within
`filters.py`) to generate a `Q()` object.  Examples are given in the next
section.

In the case of system-specific filters, there are actually two types of
underlying Django query that we use to display lists of systems.  The obvious
one is via the `InventoryHost` model, where we can build queries based on
the system fields directly.  The queryset for these views will be based on
either the `InventoryHost.objects.for_account(request)` manager method, which
implements basic org_id and other filtering, or the 
`get_systems_queryset(request)` function in `api.models`, which implements a
lot more filtering.

But the other less obvious one is via the `CurrentReport` model; this is used
when we want to build counts of the number of systems affected by a specific
rule.  These querysets mostly come via the `get_reports_subquery(request, ...)` 
function in `api.models`.  This will be important later :-)

This means that it's good practice for our 'role' filter function to take a
`relation` argument, which allows the caller to specify the relation to the
`InventoryHost` model.  This is the purpose of the `base_parameter` variable
and the kwargs manipulation in the `Q()` object creation:

```py
def filter_on_system_role(request, relation: Optional[str] = None):
    """
    Filter on the system's role.
    """
    role = value_of_param(system_role_query_param, request)
    if role is None:  # 'role' parameter not present in query
        return Q()
    base_parameter = 'display_name'
    if relation:
        base_parameter = f"{relation}__{base_parameter}"
    match role:
        case 'database':
            return Q(**{f"{base_parameter}__startswith": 'db-'})
        case 'webserver':
            return Q(**{f"{base_parameter}__startswith": 'web-'})
        case 'storage':
            return Q(**{f"{base_parameter}__startswith": 's3-'})
    # enum prevents other values from being possible here.
```

You can see how the `value_of_param(query_param, request)` function takes
care of finding the 'role' keyword in the request's query.  It will raise a
`ValidationError()` if the value given for the parameter does not match the
expected type (a string) or one of the enumerated values.  Django REST
Framework catches this and returns the correct `400` error.  The purpose of
`value_of_param()` is to take care of that validation step.

Note here that Django lets us leave it to finding the best way of constructing
the query for a string starting with a given static value.

### Applying the filter

We now need to apply the filter to a query.

For other queries, this would be done within the view, with code like this
(taken from within `/api/advisor/api/views/rules.py`, edited for clarity):

```py
acct_rules = self.get_queryset()
if request.query_params:
    acct_rules = acct_rules.filter(
        filter_on_param('category_id', category_query_param, request),
        filter_on_impacting(request),
        ...
```

Here we also see the use of `filter_on_param(query_key, parameter, request)`
to generate `Q()` objects for the `filter()` method.  In the case of the
`category_query_param` parameter, if it is found within the request's
query parameters then the `category_id` field is searched for that value.

However, for our `role` query parameter, this should be added to the list
of filters applied within `get_systems_queryset()` and `get_reports_subquery()`.
For example, within `get_systems_queryset()`:

```py
return systems.filter(
    filter_on_display_name(request),
    filter_on_hits(request),
    filter_on_incident(request),
    filter_on_rhel_version(request),
    filter_on_system_role(request),
    filter_on_has_disabled_recommendation(request)
)
```

and within `get_reports_subquery()`:

```py
return CurrentReport.objects.filter(
    Q(
        host_tags_q, system_type_q, system_profile_filter,
        category_filter,
        cert_auth_q(request, relation='inventory'),
        branch_id_filter,
        filter_on_update_method(request, relation='inventory'),
        get_host_group_filter(request, relation='inventory'),
        filter_on_system_role(request, relation='inventory'),
        stale_systems_filter,
    ) if exclude_ineligible_hosts else Q(),
    **outer_table_join
).filter(
```

These additions mean that wherever a system is queried - and there are quite
a few places - the `role` parameter will be filtered for if it is set.

### Advertising the query parameter

The OpenAPI schema must also be augmented to advertise our new `role` query
parameter.  This is done by adding the query parameter object to the list
in the `@extend_schema(parameters=[...])` decorator on the view methods that
accept the `role` filter.  Note that this does (somewhat) break the Django
principle of 'Don't Repeat Yourself', but it's necessary because the filters
applied to the query are completely separate from the eventual result as a
serialised output of data.

So for example in the `SystemViewSet()` class in `api/advisor/api/views/systems.py`
we should add it to this schema extension:

```py
@extend_schema(
    parameters=[
        sort_query_param, display_name_query_param, host_tags_query_param,
        hits_query_param, filter_system_profile_sap_system_query_param,
        filter_system_profile_sap_sids_contains_query_param,
        incident_query_param, rhel_version_query_param, pathway_query_param,
        host_group_name_query_param, update_method_query_param,
        filter_system_profile_mssql_query_param,
        filter_system_profile_ansible_query_param,
        has_disabled_recommendation_query_param,
        system_type_query_param, system_role_query_param,  # <-- here
    ],
)
def list(self, request, format=None):
```

However, in keeping with the 'Don't Repeat Yourself' philosophy, the
`OpenApiParameter()` object being supplied is the same one that is used in
the `value_of_param()` function.  This makes sure that if that parameter has
to change both its effect on the query and its schema definition are also
changed.

### Query parameters that take multiple values

Oops, it turns out that the product manager has decided that actually the
user should be able to select one **or more** roles, with a query string
such as `role=database,webserver` - or, `role=database&role=webserver`, they
haven't made up their mind.

It turns out that this is quite easy to implement.  First we change our
parameter to accept multiple values:

```py
system_role_query_param = OpenApiParameter(
    name='role', location=OpenApiParameter.QUERY, required=False,
    description='Filter servers by their role',
    enum=('database', 'webserver', 'storage', 'other'),
    many=True, style='form'
)
```

Here `style='form'` is part of the OpenAPI parameter standard, and is the
way to specify comma-separated values.

We then need to modify the logic within our filter function:

```py
def filter_on_system_role(request, relation: Optional[str] = None):
    """
    Filter on the system's role.
    """
    roles = value_of_param(system_role_query_param, request)
    if not roles:  # 'role' parameter not present in query
        return Q()
    base_parameter = 'display_name'
    if relation:
        base_parameter = f"{relation}__{base_parameter}"
    role_query = Q()
    for role in roles:
        match role:
            case 'database':
                role_query |= Q(**{f"{base_parameter}__startswith": 'db-'})
            case 'webserver':
                role_query |= Q(**{f"{base_parameter}__startswith": 'web-'})
            case 'storage':
                role_query |= Q(**{f"{base_parameter}__startswith": 's3-'})
    return role_query
    # enum prevents other values from being possible here.
```

Note that `value_of_param` here now returns a list of zero or more values.
It searches the entire query parameter list, so it handles a query with both
`role=database` and `role=storage` defined.  It also handles taking apart the
comma-separated value list in `role=database,storage`.

Thanks to Django's ability to use symbolic logical operators (`|` and `&`) on
`Q()` objects, we combine the individual role values into conditions that are
ORed together.  This overall condition is then `AND`ed into the generated
SQL query.

### Query parameters that use the `filter[]` syntax

Some other API frameworks allow defining query filters within the query string
itself, using a syntax that isolates keys and operators using square brackets,
such as:

- `filter[system_profile][operating_system][name][eq_i]=centos`
- `filter[system_profile][bios_vendor][ne]=SeaBIOS`
- `filter[system_profile][number_of_cpus][gt]=8`

These are handled by the `filter_multi_param(request, prefix, ...)` function
in `filters.py`.  This also handles:

- generating the correct Django queryset operators for filter query operators
  (e.g. `eq_i` translates to `iexact`)
- type conversion from (`true`, `True`, `false`, or `False`) into boolean,
  and integers when the operator is (`gt`, `gte`, `lt` or `lte`).
- joining multiple instances of this parameter in the query into one `Q()`
  object with each individual condition `AND`ed together.

The `system_profile` parameter in particular is already filtered in many
queries, and `filter_multi_param()` handles all those queries.  A new
`OpenApiParameter` object should be defined if you're handling a new query,
because OpenAPI does not understand (and certainly does not expect to
comprehensively define) the open-ended nature of the `filter[]` syntax.
However, in most cases you do not need to call `filter_multi_param()` because
it is already in place.

## Testing

Test files go in `advisor/api/tests` and to run all the test files in there run either of these commands:
```
$ api/advisor/manage.py test advisor
```
... or ...
```
$ cd api/advisor
$ ./manage.py test
```

These can also be run via
```sh
$ pipenv run testapi
```

### Code coverage and test writing

In general, we try to cover as much of the code as we can in our tests.

- We write tests that check that things operate correctly, but we also write
  tests for things that fail to check that they fail in the expected way.
- We write tests for the important details, not for every single detail.
  For example, we may test all the values of one host in a list of hosts,
  but then we only test the values that are important to the query in the
  other hosts.
- We try to follow a 'test-driven development' model, of writing the test
  code to trigger a bug or explore a new feature and then writing the code
  that causes the test to pass.
- We should write tests both of the operations of specific functions, to
  make sure all their corner cases are checked, and the overall operation of
  the systems using those functions.
- Sometimes it makes sense to cover tests of specific code by testing it in
  a specific file, not related

Likewise, the tools we use in testing are:

- The Django unit test module and TestCase class provide all tests.
  - Fixtures are loaded from the `api/advisor/*/fixtures/` directory via
    the standard TestCase `fixtures` property.
  - Requests to the API uses the `self.client` 'requests' client and the
    Django `reverse()` function to map a URL name to a path.
  - Tests involving systems should use the `update_stale_dates()` function
    imported from `api.tests` to update the staleness timestamps on all
    systems prior to any tests.
  - Exceptions
- External systems and API calls are not 'mocked' out.
  - Requests to other APIs are provided by the `responses` module.
  - Settings are overridden through the `override_settings` decorator.
  - Kafka message producers and consumers can be handled via the `DummyMessage`,
    `DummyConsumer` and `DummyProducer` classes in `api/advisor/kafka_utils.py`.

Most of the tests in the `api/advisor/*/tests/` directories use a 'constants'
class defined in `api/advisor/api/tests/__init__.py` and imported via
`from api.tests import constants`.  This defines a wide variety of constant
values for host details, rule details, accounts and organisations, pathways,
rule categories, content types, and Kessel data.  In general, we should avoid
direct string comparisons in tests - e.g.:

```py
    self.assertEqual(systems[0]['system_uuid'], '00112233-4455-6677-8899-012345678903')
    self.assertEqual(systems[0]['display_name'], 'system03.example.com')
```

Instead these should use constants.

```py
    self.assertEqual(systems[0]['system_uuid'], constants.host_03_uuid)
    self.assertEqual(systems[0]['display_name'], constants.host_03_name)
```

System last seen dates are probably the main exception to this at the moment -
they should probably be made unique to each system and added to the constants
in the future.

Tests of specific features of the API code are broken out into `_views.py` test
files, and (minimal) tests of the models are in the `_models.py` files. Commands
and services are also tested. Other notable test suites in the Advisor API are:

- `test_advisor_logging.py` - Testing that logs generated actually contain
  all the fields we expect.
- `test_api_docs.py` - Test the OpenAPI schema generation.
- `test_cert_auth.py` - Tests authentication via system certificate.
- `test_floorist.py` - Tests that the Floorist queries defined in our
  `clowdapp.yml` (internal) are valid SQL.
- `test_host_groups.py` - Tests when the user is limited to only viewing
  hosts in certain groups.
- `test_kafka_utils.py` - Tests that our Kafka handlers work.
- `test_middleware.py` - Not tests of Django's middleware - tests that the
  Hybrid Cloud Console middleware interface for getting use details work.
- `test_parameter_parsing.py` - Tests our utility functions for handling
  query parameters.
- `test_rbac.py` - Tests views when RBAC is enabled.
- `test_view_auth.py` - Tests all the ways view authentication and permission
  checks work and can fail.
- `test_workloads_field_redirection.py` - Tests that queries that use the old
  'sap_system', 'sap_sids', 'ansible' and 'mssql' fields in the system profile
  translate correctly into use of the new 'workload' structure.

## Auto-Generating API Client

You can generate an API client automatically by downloading the swagger spec file. Example:

Assuming you have insights-advisor-api running on localhost, you can generate a python client using swagger-codegen with:
```
$ podman run --net=host --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli generate \
    -i 'http://127.0.0.1/api/insights/v1/swagger?format=openapi' \
    -l python \
    -o /local/out/python
$ cd out/python
$ python3 -m venv ./api-client-venv
$ . api-client-venv/bin/activate
(api-client-venv) $ pip install -e .
```

Then you can use the client like so (by default the client uses 'localhost'):
```
>>> import swagger_client
>>> ra = swagger_client.RuleApi()
>>> r = ra.rule_list(account='1234567', _preload_content=False)
>>> import json
>>> from pprint import pprint
>>> pprint(json.loads(r.data))
[{'active': True,
  'created_at': '2018-05-22T02:06:47-04:00',
  'deleted_at': None,
  'description': 'Acked rule',
  'generic_html': '',
  'id': 3,

...
```

`_preload_content=False` is used to return the raw data. By default, the
client tries to deserialize the data into an object. However, if the spec
does not yet have a model defined along with a proper return-type defined for
the API request, the client will simply return `None`

## Debugging

To view the SQL produced by the ORM, set the environment variable `LOG_LEVEL=DEBUG`
