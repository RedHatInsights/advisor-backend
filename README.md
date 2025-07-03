# Insights Advisor Backend

This is the Insights Advisor Backend repository. This repository
hosts both the Advisor API and the Advisor Service. This is the top-level README
for both services. To see more detailed information about the API or the
Service look at their respective READMEs in "api" or "service" directories.

# Internal documentation

The [Advisor Architecture Document|https://spaces.redhat.com/pages/viewpage.action?spaceKey=RHIN&title=Advisor+Architecture+Document]

# Installation

## Pre-requisites
--------------
```
python 3.12+
pipenv
podman and podman-compose
```

## Setup Python environment

Setup the Python environment:
```
pipenv shell
pipenv install
pipenv install --dev
```

## Database

To start the database, run required migrations and load required
fixtures you will need to run the following commands:
```
export ADVISOR_DB_HOST=localhost
podman-compose up -d advisor-db
pipenv shell
python api/advisor/manage.py migrate
python api/advisor/manage.py loaddata rulesets rule_categories system_types upload_sources basic_test_data
```

# Advisor overview

## Data structure and flows

The Insights client collects data from a system, and the Insights core is used
to process this data and check it against the Insights production ruleset.
This generates reports which are sent through Kafka to the Advisor service.

The Advisor service organises these into an upload, which contains zero or
more reports.  Each upload relates to a host by its Inventory UUID; each
report therefore links to the host (via the upload) and the rule, and stores
the details that the rule generated (which is basically a JSON object).

The API provides access to the content for the rules, and the reports of
them occurring on systems.  Rules have categories, impact levels, and tags,
as well as content fields that use the `DoT` JavaScript templating language
and MarkDown to render the data actually captured by the rule into meaningful
information to display to the user.

## Staleness

Systems normally upload each day, and there are several types of upload -
`subscription-manager` and `insights-client` are the two most common.  If a
system hasn't uploaded in fourteen days, it is considered stale, and after
twenty-one days it is hidden from display.  After twenty-eight days the
Inventory database deletes the system - this prevents 'ephemeral' systems
which are brought up, run for a limited time, and then shut down (without
sending a 'delete' notification) from cluttering up the database.

## Data syndication

Advisor's database does not have direct access to the Inventory database (yet).
Instead, the 'Cyndi' process syndicates updates to the Inventory 'hosts' table
to Advisor - this also selects the data that Advisor sees about that host.
This data is put into a background table that Advisor cannot change directly;
Advisor instead uses the `inventory.hosts` view to access the data.

## Content load and import

### Fixed data

Some data is more or less fixed, and this is loaded from fixtures; this covers
the `Ruleset`, `RuleCategory`, `SystemType` and `UploadSource` models.  In
production and stage environments the `Pathway` model data is also loaded
from a fixture.

### Imported content

The content in the `Rule` model and its associated `Tag`, `RuleImpact`,
`Resolution`, `ResolutionRisk` and `Playbook` models is loaded from data
written by the rule content team.  This data presents information about the
rules and how they affect a specific system - data from the report is
interpolated into some of these fields.

This data is loaded by the `import_content` Django command.  In the stage and
production environments this command is run in the `container_init.sh`
script during the container environment initialisation process.

The command takes a `-c` option that is given a directory path that contains
the rule and playbook content, either in its direct form of the actual
`insights-content` and `insights-playbooks` Git repositories, or as the
dumped YAML form of those repositories (see below).

The import process is designed to quickly load this data into the data, using
bulk insert and update operations.

During the container build process, the `import_content` command is invoked
(in the `Dockerfile`) using the `--dump` and `--compress` options.  This reads
the Git content and playbook repositories and then writes these out to two
YAML files (compressed using `zlib` to be `gzip` compatible).  This, plus the
content repository's `config.yaml` file, get written into the container image.

### System data

System data is primarily stored in the `InventoryHost` model using the
'Cyndi' process mentioned above.  We also use a `Host` model to keep track of
data that the Inventory table does not, such as Satellite IDs.

Each time a system runs `insights-client` we store each individual result in
the `CurrentReport` model.  Zero or more reports are grouped together into an
`Upload` object; this allows us to track that a report on one day does _not_
appear in a following upload (which means the rule has been resolved on that
system).

### User data

Data in the `Ack` and `HostAck` models tracks if a user does not want to see
particular recommendations, either for all hosts (`Ack`) or only for specific
hosts (`HostAck`).

Users can leave ratings for rules in the `RuleRating` model - positive,
negative, or neutral.

The `WeeklyReportSubscription` model tracks users subscribing to receive
weekly reports.

### Weird anomalies

The `RuleTopic` model allows us to group rules together - for example, rules
related to managing Postgres on a Satellite.  There are only a limited number
of these.  They were created online using the API, and there is no fixture

At one stage product management decided that for all accounts, any new
person that was added to the account would automatically be subscribed to the
weekly report.  However, it was decided that aproximately 310 accounts would
not have this enabled, so the `SubscriptionExcludedAccount` model tracks
those accounts.  The API endpoints that allow the UI to automatically create
a subscription will return a `405 Method Not Allowed` when the UI attempts
to create a user in one of these accounts.

# Notes

## Cyndi Considerations

If advisor is running a real openshift environment, the cyndi table/view are
expected to be created outside of advisor. If you are running advisor
locally, you may need to mock this out. This can be accomplished with the
following command:

```
python api/advisor/manage.py mock_cyndi_table
```

The tests automatically run this command.  It is only applicable if you are
running advisor standalone.

## Updating Host Stale Timestamps

The stale timestamps of the hosts in the DB will need to be updated so they
are in the futures.  The timestamps in the fixtures are well into the past
now and need to be updated in the DB so the hosts will show up in queries:

```bash
python api/advisor/manage.py freshen_hosts
```

## Running the Service with podman-compose

Start the service
```
podman-compose up advisor-service
```
Sending in fake engine results
```
pipenv shell
python service/manual_test/send_fake_engine_results.py
```

## Running the Service manually

Start Service dependencies. We still use podman-compose here
but only for the dependencies. This method is meant for
more rapid development.
```
export ADVISOR_DB_HOST=localhost
podman-compose up -d zookeeper kafka advisor-db
```
Start Service manually
```
BOOTSTRAP_SERVERS=localhost:9092 python service/service.py
```
Sending in engine results for processing.
```
python service/manual_test/send_fake_engine_results.py
```

## Running the API with podman-compose

Start the API
```
podman-compose up advisor-api
```
Verify the API is running
```
curl http://localhost:8000/api/insights/v1/status/ready
curl http://localhost:8000/api/insights/v1/status/live
```
You should see output corresponding to the request from podman
as well as your curl command.

## Running the API manually

Start API dependencies. We still use podman-compose here
but only for the dependencies. This method is meant for
more rapid development.
```
export ADVISOR_DB_HOST=localhost
podman-compose up -d advisor-db
```
Setup the DB (if this is the first time running).
```
pipenv shell
python api/advisor/manage.py migrate
python api/advisor/manage.py mock_cyndi_table
python api/advisor/manage.py loaddata rulesets rule_categories system_types \
       upload_sources basic_test_data basic_task_test_data
```
Start the API manually
```
pipenv shell
python api/advisor/manage.py runserver
```
NOTE: If you are running with a PROMETHEUS_PORT defined other than 8000 then
you will need to run Django differently
```
pipenv shell
python api/advisor/manage.py runserver --noreload
```
NOTE: If you want to enable the Auto-Subscribe endpoint, define the
`ENABLE_AUTOSUB` environment variable to `true` before running the server.

```bash
pipenv shell
ENABLE_AUTOSUB=true python api/advisor/manage.py runserver
```

# Testing Tasks API

Follow the Tasks [README.md](api/advisor/tasks/README.md) file under `tasks` folder.

# Using the Swagger UI

The local APIs can be accessed via OpenAPI Swagger UIs:

- http://localhost:8000/api/insights/v1/openapi/swagger/
- http://localhost:8000/api/tasks/v1/schema/swagger-ui/

Because the OpenAPI schema is generated from the permissions of the user, you
will need to insert the `x-rh-identity` header in your browser to provide the
header that the 3Scales would normally provide.  To do this:

* Install a header modifying plugin in your browser, e.g. "ModHeader" for
  FireFox.
* Set it up to add the `x-rh-identity` header with this value:
  `eyJpZGVudGl0eSI6IHsiYWNjb3VudF9udW1iZXIiOiAiMTIzNDU2NyIsICJvcmdfaWQiOiAiOTg3NjU0MyIsICJ0eXBlIjogIlVzZXIiLCAiYXV0aF90eXBlIjogImp3dCIsICJ1c2VyIjogeyJ1c2VybmFtZSI6ICJ0ZXN0aW5nIiwgImlzX2ludGVybmFsIjogdHJ1ZX19fQo=`

You can generate a similar header using this command:
```
$ echo '{"identity": {"account_number": "1234567", "org_id": "9876543", "type": "User", "auth_type": "jwt", "user": {"username": "testing", "is_internal": true}}}' | base64 -w 0 ; echo
```

If you need to vary the data in the header structure, this is the way to do it.

Likewise, if using `curl` then the header can be provided in this way:
```
$ curl -H 'x-rh-identity: eyJpZGVudGl0eSI6IHsiYWNjb3VudF9udW1iZXIiOiAiMTIzNDU2NyIsICJvcmdfaWQiOiAiOTg3NjU0MyIsICJ0eXBlIjogIlVzZXIiLCAiYXV0aF90eXBlIjogImp3dCIsICJ1c2VyIjogeyJ1c2VybmFtZSI6ICJ0ZXN0aW5nIiwgImlzX2ludGVybmFsIjogdHJ1ZX19fQo=' http://localhost:8000/api/insights/v1/rule/
```

## Running tests

To run lint tests run the following pipenv script.
This will lint both the Service and the API
```
pipenv run linter
```
Before running the tests, make sure the database is running first:
```
export ADVISOR_DB_HOST=localhost
podman-compose up -d advisor-db
```
To run Service Tests
```
podman-compose up -d zookeeper kafka
pipenv run testservice
```

To run API Tests
```
pipenv run testapi
```

![Ingress Pipeline](./ingress-pipeline.png)

Contributing
--------------------
All outstanding issues or feature requests should be filed as Issues on this GitHub
page. MRs should be submitted against the master branch for any new features or changes,
and pass ALL testing above.
