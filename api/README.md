The Advisor API in Django
=========================

This is an implementation of the new Insights API in Django 5.1, which
requires Python 3.10 or above.

See the main [Read Me|../README.md] document for more information about
Advisor's purpose and structure.

Install instructions
--------------------

- Get the code:

    `git clone https://github.com/RedHatInsights/insights-advisor-api`

- Setup virtualenv dev environment

    ```
    cd insights-advisor-api
    pip install pipenv
    (optional) pipenv run pip install --upgrade pip
    pipenv install --dev
    pipenv shell
    ````

    The `pipenv run pip install --upgrade pip` command is only necessary if you
    encounter an error running `pipenv install` related to pip and
    `no such option: --require-hashes`.

- Running Advisor

    You can run advisor manually on the host, or you can run it via docker
    containers controlled by docker-compose.  You can also do both if you
    wish.


### Running Advisor via docker-compose

You can run Advisor as a series of docker containers controlled by
docker-compose.  You will need to have docker and docker-compose installed on
you development machine as well as being able to [run docker containers as a
normal user](https://docs.docker.com/install/linux/linux-postinstall/).

- To build the advisor-api container run `docker-compose build`

- Start the containers with `docker-compose up`

- Point a browser at `http://localhost:8000/api/insights/v1` to browse the api.

- Use `docker-compose stop/start` to control the containers.

Note, the advisor-db/postgresql container is non-persistent so its data is
lost when the container is deleted, for example if you run `docker-compose
down`.  `docker-compose up` will re-initialize the data.


### Running Advisor manually on the host

You can also run Advisor from the host.  Here's how ...

- Install the Django database

    The application uses a PostgreSQL database by default.  You can install
    PostgreSQL using the `postgresql-*` packages and use `psql` to configure
    it according the settings in `settings.py`.

    Or you can use a postgresql container, eg PostgreSQL 12 from the Red Hat
    Container Catalog:
    ```
    $ docker run -d --name db -p 5432:5432 -e POSTGRESQL_USER=insightsapi \
        -e POSTGRESQL_PASSWORD=InsightsData -e POSTGRESQL_DATABASE=insightsapi \
        registry.access.redhat.com/rhscl/postgresql-12-rhel7
    ```

    To use a different type of database than postgresql, eg sqlite3, create an
    `ADVISOR_DB_ENGINE` environment variable, like so:
    ```
    $ export ADVISOR_DB_ENGINE=django.db.backends.sqlite3
    ```
    ... which will cause a sqlite3 database file called `insightsapi` to be
    created in the current directory after executing the `./manage.py
    migrate` step.

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

Updating
--------

If you've already got this project checked out and running, and want to see
the latest work, then you really just need to do:

```
$ git pull
$ api/advisor/manage.py migrate
```

If you are using docker-compose, run `docker-compose build` to rebuild the
advisor-api container image and then restart the advisor-api container.

Host staleness
--------------

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

Testing
--------

Test files go in `advisor/api/tests` and to run all the test files in there run either of these commands:
```
$ api/advisor/manage.py test advisor
```
... or ...
```
$ cd api/advisor
$ ./manage.py test
```

Auto-Generating API Client
--------------------------

You can generate an API client automatically by downloading the swagger spec file. Example:

Assuming you have insights-advisor-api running on localhost, you can generate a python client using swagger-codegen with:
```
$ docker run --net=host --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli generate \
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

Debugging
--------------------------
To view the SQL produced by the ORM, set the environment variable `LOG_LEVEL=DEBUG`
