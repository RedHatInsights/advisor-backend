# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Insights Advisor Backend is a Django 5.2 / Python 3.12+ application for Red Hat's Hybrid Cloud Console. It consists of two main systems:
- **API** (`api/`): Django REST Framework API serving recommendation data to users
- **Service** (`service/`): Kafka consumer that receives rule processing results and records them in the database

## Common Commands

All commands run from the repository root. Use `pipenv shell` first or prefix with `pipenv run`.

### Setup
```bash
pipenv install && pipenv install --dev
export ADVISOR_DB_HOST=localhost
podman-compose up -d advisor-db
python api/advisor/manage.py migrate
python api/advisor/manage.py mock_cyndi_table
python api/advisor/manage.py loaddata rulesets rule_categories system_types upload_sources basic_test_data
python api/advisor/manage.py freshen_hosts
```

### Running
```bash
pipenv run runapi                    # Start API server (Django runserver on :8000)
pipenv run runservice                # Start Kafka service consumer
pipenv run runtasks                  # Start Tasks service consumer
```

### Testing
```bash
pipenv run testapi                   # Run API tests (uses Django test runner with coverage)
pipenv run testtasks                 # Run Tasks tests
pipenv run testservice               # Run Service tests (pytest)
pipenv run linter                    # Run flake8 on api/ and service/
```

### Running a single API test
```bash
python api/advisor/manage.py test api/advisor/api/tests/test_rule_views    # Single test module
python api/advisor/manage.py test api/advisor/api/tests/test_rule_views.RuleViewSetTests.test_rule_list  # Single test
```

### Other useful pipenv scripts
```bash
pipenv run migratedb                 # Run migrations
pipenv run makemigrations            # Create new migrations
pipenv run mockcyndi                 # Create mock Cyndi table
pipenv run loaddata                  # Load production fixtures
pipenv run loadtestdata              # Load test fixtures
pipenv run apicovhtml                # Generate HTML coverage report
```

## Architecture

### Three APIs in one Django project

The Django project (`api/advisor/project_settings/`) serves three APIs with separate URL prefixes:

1. **Advisor API** (`api/advisor/api/`) — `/api/insights/v1/` — Main API for rules, systems, reports, acks
2. **Tasks API** (`api/advisor/tasks/`) — `/api/tasks/v1/` — Playbook execution task management
3. **Satellite Compatibility API** (`api/advisor/sat_compat/`) — `/r/insights/` — Legacy Satellite proxy compatibility

### Key data models (`api/advisor/api/models.py`)

- **Rule**, **RuleImpact**, **Resolution**, **Playbook** — Rule content imported from external repos via `import_content` command
- **InventoryHost** — Syndicated from HBI (Host-Based Inventory) via Cyndi; read-only in production. Uses `for_account(request)` manager method to scope queries by org_id and staleness
- **Host** — Advisor's own host tracking (Satellite IDs, etc.), used as FK for uploads/reports
- **CurrentReport** — Active rule hits per host. Central to most queries
- **Upload** — Groups reports from a single system check-in; tracks `checked_on` date
- **Ack** / **HostAck** — User acknowledgments to suppress recommendations (global or per-host)
- **Pathway** — Groups rules into remediation pathways

### Query filtering pattern (`api/advisor/api/filters.py`)

System-scoped filters follow a consistent pattern:
1. Define an `OpenApiParameter` in `filters.py`
2. Create a filter function returning a `Q()` object, accepting an optional `relation` parameter for use in both `InventoryHost` and `CurrentReport` queries
3. Apply via `get_systems_queryset()` (for system queries) and `get_reports_subquery()` (for report-count queries)
4. Advertise in `@extend_schema(parameters=[...])` on view methods

Use `value_of_param(param, request)` for parameter extraction/validation and `filter_on_param(field, param, request)` for simple field filters. `filter_multi_param()` handles `filter[]` bracket syntax.

### Authentication & permissions (`api/advisor/api/permissions.py`)

- Requests carry a base64-encoded JSON identity in the `x-rh-identity` HTTP header (provided by 3Scale gateway)
- `RHIdentityAuthentication` decodes and validates the identity; `org_id` scopes all data queries
- `InsightsRBACPermission` checks permissions against RBAC service (or Kessel via gRPC when enabled)
- RBAC/Kessel are disabled by default for local dev (`RBAC_ENABLED=false`, `KESSEL_ENABLED=false`)

### Service (`service/service.py`)

Kafka consumer processing `platform.engine.results` messages. Receives rule hit results, creates/updates/deletes `CurrentReport` records, manages `Upload` and `Host` records within atomic transactions.

### Testing conventions

- Tests use Django's `TestCase` with fixtures from `api/advisor/*/fixtures/`
- Test constants are centralized in `api/advisor/api/tests/__init__.py` (`from api.tests import constants`) — use these instead of hardcoded strings
- Call `update_stale_dates()` before tests involving systems to ensure hosts aren't filtered out by staleness
- External API calls use the `responses` library (not `unittest.mock`)
- Kafka mocking uses `DummyMessage`, `DummyConsumer`, `DummyProducer` from `api/advisor/kafka_utils.py`
- Custom test runner (`CyndiTestRunner`) automatically creates mock Cyndi table before tests
- API tests require the database: `podman-compose up -d advisor-db` with `ADVISOR_DB_HOST=localhost`

### Content import

Rule content is loaded via `python api/advisor/manage.py import_content -c <content_dir>`. Test content lives in `api/test_content/`.

### Feature flags

Unleash-based. For local dev, set `UNLEASH_FAKE_INITIALIZE=true` (default) or provide a bootstrap file via `UNLEASH_BOOTSTRAP_FILE`.