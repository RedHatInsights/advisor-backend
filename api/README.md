# The Advisor API in Django

This is an implementation of the new Insights API in Django 5.2, which
requires Python 3.12 or above.

See the main [Read Me](../README.md) document for more information about
Advisor's purpose and structure.

## Install instructions

- Get the code:

    `git clone https://github.com/RedHatInsights/insights-advisor`

- Setup virtualenv dev environment

    ```
    cd insights-advisor
    pip install pipenv
    (optional) pipenv run pip install --upgrade pip
    pipenv install --dev
    pipenv shell
    ````

    The `pipenv run pip install --upgrade pip` command is only necessary if you
    encounter an error running `pipenv install` related to pip and
    `no such option: --require-hashes`.

- Running Advisor

    You can run advisor manually on the host, or you can run it via podman
    containers controlled by podman-compose.  You can also do both if you
    wish.

### Running Advisor via podman-compose

You can run Advisor as a series of podman containers controlled by
podman-compose.  You will need to have podman and podman-compose installed on
you development machine.

- To build the advisor-api container run `podman-compose build`

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

# Host staleness

Inventory controls host staleness and culling using two sets of fields:

  * the `stale_timestamp`, `stale_warning_timestamp` and `culled_timestamp`
    fields
  * the `per_reporter_staleness` field, which relies on the `puptoo` object
    having a `stale_timestamp` field

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

## Authentication

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

## Permissions

The two default Permission classes are `InsightsRBACPermission` and
`CertAuthPermission`.  These apply to almost all viewsets.  These are usually
'or'ed together so that as long as either one matches, permission is granted.

Django REST Framework permission classes normally only return `True` or `False`
to indicate whether the request is allowed or not.  This means there is no
standard way of indicating why the request was denied - the standard DRF
message of 'You do not have permission to perform this action.' is supplied.
Internal messaging is stored and reported in logs for debugging.

## InsightsRBACPermission

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

## CertAuthPermission

`CertAuthPermission` applies to systems that have authenticated with a
certificate:

- the identity must have a `system` field which must be a dictionary.
- the system field must have a 'cn' field which must be a UUID in string form.
  The actual UUID is not checked.

## Other permissions classes.

We also have other permissions classes that are used for specific use cases.

- `AssociatePermission` simply checks that the request's identity has an
  'associate' field.
- `IsRedHatInternalUser` checks that the user data has an 'is_internal' field
  and that field evaluates to `True`.
- `OrgPermission` simply checks that request's identity data has an 'org_id' field.
- `TasksRBACPermission`, defined in `api/advisor/tasks/permissions.py`, is
  functionally identical to `InsightsRBACPermission` and simply changes the app
  name used in the RBAC permissions check from 'advisor' to 'tasks'.

## Views without permissions

- KCS, rule categories, rule ratings, playbook listings, application status, and
  system types are all able to be viewed with no permissions checks in Advisor.
  They're still only available through the 3Scale gateway.
- For the Satellite compatibility layer, articles, branch_info, CVEs,
  evaluation status, groups, application status (ping), and plugins are all
  viewable with no permissions.  This in general means that their data does not
  change for different users; they're really only there because the 

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
