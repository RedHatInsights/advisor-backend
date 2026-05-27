# Insights Advisor Service
This is the Insights Advisor Service. This service listens on
a specific Kafka topic for available engine results payloads to
analyze and generate reports for. This utilizes the shared engine
instances.

# What the service does

The service operates as part of the data ingress pipeline for Advisor and
Insights:

![Ingress Pipeline](./ingress-pipeline.png)

The main code of the service is in `service.py`.  It uses a thread executor
to process messages asynchronously from receiving them.

## Processing engine results.

The service receives rule results via Kafka from the Insights Engine on the
topic `platform.engine.results`, defined in the `ENGINE_RESULTS_TOPIC`
environment variable and Django setting.

When this message is received it generates a call to `handle_engine_results()`.
This function:

- Checks the input data to see if we have all the fields we expect.
- Get the `SystemType` for this system - while we trust the product_code and
  role given in the Kafka message, this should always be RHEL/host.
- Execution is passed to the `create_db_reports()` function.
- Try to find the `Host` object for this system, or create it.
  - If there are no current uploads for this org_id, this organisation must
    be new.  Create the auto-acks for this organisation.
- Start an atomic transaction based on this Host record.
- Find the `CurrentReport`s for this host.  Note: a CurrentReport is a rule hit that is currently active for this host.
- Find the latest `Upload` for this host, or create one.
- If the system has a rule that matches one of the `FILTER_OUT_NON_RHEL_RULE_ID`
  setting list, then ignore all other rules in these reports and just report
  the system is non-RHEL.  (This prevents CentOS and other free systems from
  getting the benefit of Insights).
- Likewise, if the system has a RHEL 6 EOL rule, ignore all other rules.
- Work out three sets:
  - The list of new reports (reports that are not already CurrentReports).
  - The list of reports to update.
  - The list of resolved reports (CurrentReports not in this list of reports).
- Create, update and delete the CurrentReports to match the incoming reports.
- If notifications is configured, send these reports to Notifications.

## Interaction with Cyndi and Kafka

In the ingress pipeline, at the point where the Host Inventory process sends a
Kafka message that it has received an upload for a host, the Cyndi operator is
supposed to then send a message to the Cyndi process within Advisor, which is
then supposed to add this host to the InventoryHost database. However, in some
instances Cyndi's processes can lag - in rare instances up to several hours.
This may mean that the Advisor service receives engine results for a new host
before that host's record appears in the InventoryHost table.

For this reason (and other historic ones), Uploads and CurrentReports use the
Host record, which we control directly, as a foreign key.

# Set up

## Pre-requisites
```
podman
podman-compose
```


## Setup Python environment
Setup the Python environment:
```
pipenv shell
pipenv install
pipenv install --dev
```

# Deploying
This will start Kafka and PostgreSQL.
```
podman-compose up
```

## Installing some plugins
This service assumes you have a shared engine instance running and broadcasting
engine results for consumption. If you do not have a share engine instance
running you may utilize the fake engine broadcast messages in
manual_tests/send_fake_engine_results.

# Running the Service

Once you have deployed the environment and set up the database, you can run the
service and begin engine results analysis.
```
BOOTSTRAP_SERVERS=localhost:9092 pipenv run python service.py
... or ...
podman-compose up advisor-service
```

## Sending mock engine results

You can send in fake results for analysis using two methods.
The first method is sending in fake engine results for direct consumption in this service.
```
pipenv run python manual_test/send_fake_engine_results.py
pipenv run python api/advisor/manage.py freshen_hosts
```

The second method emulates an inventory message and will require a shared engine
instance running. This README does not intend to go through the steps to set up
a shared engine instance. However, if you have one running you can use the
following script which will send a message to the shared engine, then broadcast
its results for consumption in this service.
```
pipenv run python manual_test/send_fake_inventory_engine_message.py
```

# Testing

To run tests, run the following commands:

Start the DB:
```
podman-compose up
```

Then to run tests:
```
pipenv run flake8 .
pipenv run testservice
```

Coverage tests will then be located at `htmlcov/index.html` and must be greater than 80%.

`pytest-django` will run DB migrations and load fixtures for you automatically.

# Contributing

All outstanding issues or feature requests should be filed as Issues on this
Github page. PRs should be submitted against the master branch for any new
features or changes, and pass all testing above.

# Detailed Service Architecture

## Overview

The Service (`service/service.py`) is a **multi-threaded Kafka consumer** that processes incoming system analysis results and inventory lifecycle events, persisting them to the database. It runs as a standalone process separate from the Django API.

## Startup (`start()`, line 737)

1. Initializes logging, Prometheus metrics, and a **BoundedExecutor** thread pool (default 30 threads)
2. Subscribes to **three Kafka topics**:
   - `platform.engine.results` — rule engine analysis results
   - `platform.inventory.events` — inventory events, esp host delete notifications
   - `platform.insights.rule-hits` — third-party rule hit submissions
3. Enters a polling loop (`c.poll(1.0)`) that dispatches messages to handler functions via the thread pool
4. Handles `SIGTERM` gracefully — finishes current work, flushes Kafka, then shuts down

## Message Handlers

### 1. `handle_engine_results()` — Primary workload

Processes results from the Insights rules engine (insights-client uploads):

- **Validates** the payload by checking required key paths (`results.reports`, `results.system`, `input.platform_metadata`, `input.host.id`, `input.platform_metadata.org_id`)
- **Resolves the SystemType** (role + product_code) from the database
- Extracts satellite metadata (managed status, satellite ID, branch ID)
- Delegates to `create_db_reports()` for the actual database work

### 2. `create_db_reports()` — Core database logic

This is the most complex function, running inside a **database transaction with row-level locking**:

1. **Host management**: Finds or creates a `Host` record for the inventory UUID. For brand-new accounts (no existing uploads), it auto-creates `Ack` records for rules tagged with `autoack`
2. **Row locking**: Uses `select_for_update()` on the Host to prevent race conditions from concurrent uploads for the same system
3. **Snapshots existing reports**: Fetches all current `CurrentReport` records for the host before modifications
4. **Creates/updates Upload**: `update_or_create` on the `Upload` record for this host+org+source combination
5. **Content filtering**: Optionally filters rule IDs for non-RHEL systems (e.g., only keeping "other_linux_system" rules) and RHEL6 systems (only upgrade rules)
6. **Report reconciliation** — the key logic:
   - Matches incoming rule IDs against rules in the database
   - Preserves `impacted_date` for rules that already had reports (continuity tracking)
   - Separates reports into **new** (bulk created) and **existing** (individually updated)
   - **Deletes** any `CurrentReport` records whose rule IDs are no longer in the incoming results (rule is resolved)
7. **Webhook/notification triggers** (`reports.py`): After the DB transaction, calls `trigger_report_hooks()` which:
   - Compares new report list against previous DB reports
   - Identifies **new recommendations** (rule hit appeared) and **resolved recommendations** (rule hit disappeared)
   - Filters out acked/host-acked rules from notifications
   - Produces messages to the **webhooks topic** and **remediations hook topic** via Kafka

### 3. `handle_rule_hits()` — Third-party rule hits

Similar to engine results but with a simpler payload format. Validates required keys (`org_id`, `source`, `host_product`, `host_role`, `inventory_id`, `hits`), resolves the system type, then delegates to the same `create_db_reports()` function.

### 4. `handle_inventory_event()` — Host deletion

Handles `delete` events from HBI. When a host is deleted from inventory:
- Deletes the `Upload` records for that host (with DB retry logic, up to 3 attempts)
- Deletes all `CurrentReport` records for that host
- Deletes all `HostAck` records for that host
- Each step retries independently on `OperationalError`/`InterfaceError`, closing stale DB connections between attempts

## Supporting Infrastructure

- **`payload_tracker.py`**: Produces status messages to a Kafka topic for payload lifecycle tracking (received → processing → success/error)
- **`reports.py`**: Produces webhook and remediations events to Kafka when recommendations change
- **`thread_storage.py`**: Thread-local storage for request context (request_id, inventory_id, org_id, timing metrics) used by logging and payload tracker
- **`prometheus.py`**: Prometheus metrics — request counts, timing histograms, error counters, service status
- **`settings.py`**: Configuration via environment variables with Clowder integration for OpenShift deployments

## Error Handling

- DB connection errors trigger `close_old_connections()` and retry
- The entire report-creation flow is wrapped in `transaction.atomic()` — if anything fails, all DB changes roll back
- Webhook/notification failures are caught and logged but **do not** fail the overall upload processing
- Malformed JSON messages are logged and skipped

# Local Testing with Kafka

## Step 1: Start infrastructure and database

```bash
podman-compose up -d advisor-db init-kafka kafka
```
This starts PostgreSQL and Kafka and creates the required topics (including `platform.engine.results`, `platform.inventory.events`, `platform.insights.rule-hits`).

## Step 2: Set up the database and start the service

```bash
export ADVISOR_DB_HOST=localhost
pipenv run migratedb
pipenv run mockcyndi
pipenv run loaddata
pipenv run loadtestdata

export BOOTSTRAP_SERVERS=localhost:9092
export LOG_LEVEL=DEBUG
pipenv run python service/service.py
```
... or ...
```
export ADVISOR_DB_HOST=localhost
podman-compose up advisor-service
```

With `LOG_LEVEL=DEBUG` you'll see it log subscription to topics and every poll cycle.

## Step 4: Send fake messages

In a second terminal, use the pre-built scripts in `service/manual_test/`:

**Send engine results** (simulates an insights-client upload):
```bash
pipenv run python service/manual_test/send_fake_engine_results.py
pipenv run python api/advisor/manage.py freshen_hosts
```
This sends the payload from `fake_engine_result_rhel.json` — a host with 6 rule hits (org_id `9876543`, inventory ID `57c4c38b-...`). The service will log receiving it, resolving the system type, and creating/updating reports.

**Send a host delete event**:
```bash
pipenv run python service/manual_test/send_fake_delete.py
```
This sends a delete event for inventory ID `57c4c38b-a8c6-4289-9897-223681fd804d`. The service will log deleting uploads, reports, and host acks.

**Other fake payloads** available:
- `send_fake_engine_results.py` — supports `ENGINE_RESULTS_FILE` env var to pick a different JSON file:
  - `fake_engine_result_rhel.json` - a RHEL 8 system with 6 rule hits but only 2 are reported, for active/non-acked rules
  - `fake_engine_result_non_rhel.json` - a non-RHEL system with 2 rule hits but only 1 is reported, for OTHER LINUX SYSTEM
  - `fake_engine_result_rhel6.json` - a RHEL 6 system with 3 rule hits but only 1 is reported, for RHEL 6 EOL
  - `fake_engine_result_system01.json` - matches the system01 fixture in the test data, with 1 rule hit
- `send_fake_inventory_engine_message.py` — requires a running shared engine instance
- `send_fake_dispatcher_run.py` — playbook dispatcher run simulation for tasks service
- `send_fake_task_upload.py` — tasks upload simulation for tasks service

To send more messages, edit the `range(1)` on line 48 of the send_fake_engine_results.py script to a higher number.

## What you'll see in the service logs

With `DEBUG` logging, the service will log:
1. `"Received Platform Kafka message at ... from topic platform.engine.results"`
2. `"Processing engine results for Inventory ID ... on account ... and org_id ..."`
3. `"Created new upload for system UUID ..."` or `"Updated existing upload ..."`
4. `"Creating current report object rule_id: ..."` for each rule hit
5. `"Logged N reports for system UUID ..."` on success

For errors (e.g. missing fixtures), you'll see `"Unable to get system type rhel / host from DB - load fixtures!"`.

## Step 5: Verify data in the database

After sending fake engine results, you can query the database to confirm the host, upload, and reports were created. The fake RHEL payload uses inventory_id `57c4c38b-a8c6-4289-9897-223681fd804d`, org_id `9876543`, and account `1234567`.

### Django ORM

```bash
export ADVISOR_DB_HOST=localhost
pipenv shell
python service/manual_test/send_fake_engine_results.py
python api/advisor/manage.py freshen_hosts
python api/advisor/manage.py shell
```
Note, the 57c4c38b-a8c6-4289-9897-223681fd804d inventory ID used in the ORM queries below is from the fake engine results payload,
so that has to be imported into the database for results to appear in these queries.

Then in the shell:
```python
from api.models import Host, Upload, CurrentReport

# See the host
Host.objects.filter(inventory_id='57c4c38b-a8c6-4289-9897-223681fd804d').values()

# See uploads for this host
Upload.objects.filter(host_id='57c4c38b-a8c6-4289-9897-223681fd804d').values()

# See current reports (rule hits) for this host
CurrentReport.objects.filter(host_id='57c4c38b-a8c6-4289-9897-223681fd804d').values()

# See reports with rule IDs (more readable)
CurrentReport.objects.filter(
    host_id='57c4c38b-a8c6-4289-9897-223681fd804d'
).values('rule__rule_id', 'org_id', 'impacted_date', 'details')

# Query by org_id instead
Host.objects.filter(org_id='9876543').values()
CurrentReport.objects.filter(org_id='9876543').values('host_id', 'rule__rule_id')
```

#### Pretty printing ORM output

Use `pprint` for readable `.values()` output:
```python
from pprint import pprint
pprint(list(Host.objects.filter(org_id='9876543').values()))
```

Print each object on its own line:
```python
for r in CurrentReport.objects.filter(host_id='57c4c38b-a8c6-4289-9897-223681fd804d').values('rule__rule_id', 'org_id'):
    print(r)
```

Use `json` for JSON-style output (with `DjangoJSONEncoder` to handle datetime fields):
```python
import json
from django.core.serializers.json import DjangoJSONEncoder
qs = CurrentReport.objects.filter(host_id='57c4c38b-a8c6-4289-9897-223681fd804d').values('rule__rule_id', 'org_id', 'impacted_date')
print(json.dumps(list(qs), indent=2, cls=DjangoJSONEncoder))

# See the host with display_name from InventoryHost (via the inventory FK)
from django.db.models import F
qs = Host.objects.filter(inventory_id='57c4c38b-a8c6-4289-9897-223681fd804d').annotate(display_name=F('inventory__display_name')).values()
print(json.dumps(list(qs), indent=2, cls=DjangoJSONEncoder))
```

### Raw SQL

```bash
export ADVISOR_DB_HOST=localhost
pipenv shell
python service/manual_test/send_fake_engine_results.py
python api/advisor/manage.py freshen_hosts
python api/advisor/manage.py dbshell
```
As with the ORM queries, the 57c4c38b-a8c6-4289-9897-223681fd804d inventory ID used in the SQL queries below
has to be imported into the database for results to appear in these queries.

Then in psql:
```sql
-- See the host (table: api_host, PK column: system_uuid)
SELECT * FROM api_host
WHERE system_uuid = '57c4c38b-a8c6-4289-9897-223681fd804d';

-- See uploads for this host
SELECT * FROM api_upload
WHERE host_id = '57c4c38b-a8c6-4289-9897-223681fd804d';

-- See current reports for this host
SELECT * FROM api_currentreport
WHERE system_uuid = '57c4c38b-a8c6-4289-9897-223681fd804d';

-- See reports with rule IDs (joined)
SELECT cr.system_uuid, r.rule_id, cr.org_id, cr.impacted_date
FROM api_currentreport cr
JOIN api_rule r ON cr.rule_id = r.id
WHERE cr.system_uuid = '57c4c38b-a8c6-4289-9897-223681fd804d';

-- Query by org_id
SELECT * FROM api_host WHERE org_id = '9876543';
SELECT h.system_uuid, r.rule_id FROM api_currentreport cr
JOIN api_rule r ON cr.rule_id = r.id
WHERE cr.org_id = '9876543';
```

Note: The `Host` model's PK field is called `inventory_id` in Django but maps to the DB column `system_uuid` (via `db_column='system_uuid'`). Similarly, `CurrentReport.host` maps to `system_uuid` in the DB.

## Alternative: Run automated tests (no Kafka needed)

If you just want to verify the service logic without running real Kafka:
```bash
export ADVISOR_DB_HOST=localhost
pipenv run testservice
```
This uses pytest with mock Kafka consumers/producers (`DummyMessage`, `DummyConsumer`, etc.) and doesn't require a running Kafka broker.

# Viewing Data via the API

## Starting the API

```bash
export ADVISOR_DB_HOST=localhost
pipenv run runapi
... or ...
pipenv run python api/advisor/manage.py runserver
```

This starts the Django dev server on `http://localhost:8000`. RBAC and Kessel are disabled by default for local dev.

## Authentication

All API requests require an `x-rh-identity` header containing a base64-encoded JSON identity. Generate one matching the fake engine results data (org_id `9876543`, account `1234567`):

```bash
export RH_IDENTITY=$(echo '{"identity": {"account_number": "1234567", "org_id": "9876543", "type": "User", "auth_type": "jwt", "user": {"username": "testing", "is_internal": true}}}' | base64 -w 0)
```

## API Endpoints

The base path is `http://localhost:8000/api/insights/v1/`.

**List all systems for your org:**
```bash
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/system/ | python -m json.tool
```

**Get a specific system by inventory ID:**
```bash
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/system/57c4c38b-a8c6-4289-9897-223681fd804d/ | python -m json.tool
```

**Match system(s) with specific tags:**
```bash
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/system/?tags=insights-client%2Fcustom%252FLast%2520Reboot%3D2023-07-14%252011%253A26%253A07%2Cinsights-client%2FPrivate+IPv4%3D192.168.1.100
```
Note: the tags query parameter is URL-encoded and will match systems tagged with either or both of these tags:
- `insights-client/custom/Last Reboot=2023-07-14 11:26:07`
- `insights-client/Private IPv4=192.168.1.100`

**Get reports (rule hits) for a specific system:**
```bash
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/system/57c4c38b-a8c6-4289-9897-223681fd804d/reports/ | python -m json.tool
```

**List all rules:**
```bash
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/rule/ | python -m json.tool
```

**Get a specific rule and its systems:**
```bash
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/rule/test%7CActive_rule/ | python -m json.tool
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/rule/test%7CActive_rule/systems/ | python -m json.tool
```

**Other useful endpoints:**
```bash
# Acknowledgements
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/ack/ | python -m json.tool

# Host acknowledgements
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/hostack/ | python -m json.tool

# Stats overview
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/stats/ | python -m json.tool

# Pathways
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/pathway/ | python -m json.tool

# System types
curl -s -H "x-rh-identity: $RH_IDENTITY" http://localhost:8000/api/insights/v1/systemtype/ | python -m json.tool
```

## Swagger UI

Browse the API interactively at:
```
http://localhost:8000/api/insights/v1/openapi/swagger/
```
Use the Authorize button and paste the `$RH_IDENTITY` value into the `x-rh-identity` field.

## API Root

Visit `http://localhost:8000/api/insights/v1/` in a browser to see the full list of available endpoints (DRF's browsable API).
