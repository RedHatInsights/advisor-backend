# Claude Code Notes for Insights Advisor Backend

## Project Overview

This is the Insights Advisor Backend, a Django-based service that processes
recommendations and insights for Red Hat systems. The service consumes Kafka
messages from multiple topics and manages system recommendations in a
PostgreSQL database.

## Project Structure

```
api/advisor/
├── manage.py                           # Django management command entry point
├── project_settings/                   # Django settings and configuration
│   ├── settings.py                     # Main settings
│   ├── kafka_settings.py               # Kafka configuration
│   └── testrunner.py                   # Test runner configuration
├── api/                                # Main API application
│   ├── models.py                       # Django models
│   ├── views.py                        # API views
│   ├── management/commands/            # Django management commands
│   │   └── advisor_inventory_service.py  # Main service (handles all Kafka topics)
│   └── tests/                          # Tests
├── tasks/                              # Playbook dispatcher tasks
├── sat_compat/                         # Satellite compatibility API
├── prometheus.py                       # Prometheus metrics definitions
├── thread_storage.py                   # Thread-local storage utilities
├── payload_tracker.py                  # Kafka payload tracking
├── utils.py                            # Utility functions
└── build_info.py                       # Build/version information
```

## Running Commands

**IMPORTANT:** Always run Django management commands from within the `api` directory using a subshell:

```bash
# Good - using subshell
(cd api && python advisor/manage.py test ...)

# Bad - running from project root
python api/advisor/manage.py test ...
```

## Testing

### Running Tests

```bash
# Run specific test file
(cd api && python advisor/manage.py test api.tests.test_advisor_inventory_service)

# Run multiple test files
(cd api && python advisor/manage.py test api.tests.test_advisor_service_database api.tests.test_advisor_service_webhooks)

# Run all tests in a directory
(cd api && python advisor/manage.py test api.tests)
```

### Test Organization

- `api/tests/test_advisor_inventory_service.py` - Inventory event handling tests
- `api/tests/test_advisor_service_engine_rule_hits.py` - Engine results and rule hits tests
- `api/tests/test_advisor_service_database.py` - Database operation tests
- `api/tests/test_advisor_service_webhooks.py` - Webhook integration tests

## Key Architecture Patterns

### Kafka Message Processing

The unified service (`advisor_inventory_service.py`) handles three Kafka topics:

1. **`platform.engine.results`** - Insights Engine rule processing results
2. **`platform.insights.rule-hits`** - Third-party rule hits
3. **`platform.inventory.events`** - Inventory host create/update/delete events

### Thread Pool Concurrency

The service uses a `BoundedExecutor` thread pool to handle messages concurrently:

```python
# Thread pool configuration
THREAD_POOL_SIZE = int(os.environ.get('THREAD_POOL_SIZE', 30))

# Handlers are wrapped to run asynchronously
receiver.register_handler(
    kafka_settings.ENGINE_RESULTS_TOPIC,
    make_async_handler(handle_engine_results, executor)
)
```

### Thread Storage Cleanup

**Critical:** Thread pools reuse threads, so thread-local storage must be
cleared before each task to prevent data leakage between messages.

This is handled automatically in `make_async_handler()`:

```python
def task_with_cleanup(topic, message):
    # Clear thread-local storage before each task
    thread_storage.thread_storage_object.__dict__.clear()
    return handler_func(topic, message)
```

### Payload Tracking Pattern

The service uses three helper functions to track operations for metrics and
logging:

```python
# 1. Start tracking - sets context and returns start time
started = start_operation_tracking(
    'operation_name',
    request_id=request_id,
    inventory_id=inventory_id,
    account=account,
    org_id=org_id
)

# 2. On failure - record error and timing
track_operation_failure('operation_name', started, 'error message')

# 3. On success - record timing
track_operation_success('operation_name', started)
```

Context fields are automatically stored in thread-local storage and used for:
- Kibana logging (structured log fields)
- Payload tracker (Kafka status messages)
- Prometheus metrics

## Database Patterns

### Django ORM Best Practices

- Use `select_for_update()` to lock rows and prevent race conditions
- Use `transaction.atomic()` for multi-step operations
- Django handles connection retry automatically (no manual retry needed)
- Use `bulk_create()` for efficient batch inserts

### Common Models

- **`InventoryHost`** - Cached inventory data from HBI (Host-Based Inventory)
- **`Host`** - Advisor's host record (linked to InventoryHost)
- **`Upload`** - Archive upload record from insights-client
- **`CurrentReport`** - Active recommendations for a host
- **`Rule`** - Rule metadata from content repo
- **`SystemType`** - System product/role combinations (RHEL, OpenShift, etc.)

## Prometheus Metrics

Key metrics defined in `prometheus.py`:

- `INSIGHTS_ADVISOR_UP` - Service running status
- `INSIGHTS_ADVISOR_STATUS` - Service state (initialized, starting, running, stopped)
- `INSIGHTS_ADVISOR_SERVICE_HANDLE_ENGINE_RESULTS` - Engine results processing time
- `INSIGHTS_ADVISOR_SERVICE_RULE_HITS_ELAPSED` - Rule hits processing time
- `INSIGHTS_ADVISOR_SERVICE_INVENTORY_EVENTS_ELAPSED` - Inventory event processing time
- `INSIGHTS_ADVISOR_SERVICE_DB_ELAPSED` - Database operation time

Metrics are automatically collected via decorators:
```python
@prometheus.INSIGHTS_ADVISOR_SERVICE_HANDLE_ENGINE_RESULTS.time()
def handle_engine_results(topic, message):
    ...
```

## Feature Flags

The service uses Unleash feature flags:

- **`FLAG_INVENTORY_EVENT_REPLICATION`** - Controls inventory event processing
- Check flags with `feature_flag_is_enabled(flag_constant)`.

## Common Settings

### Environment Variables

- `THREAD_POOL_SIZE` - Thread pool worker count (default: 30)
- `PROMETHEUS_PORT` - Prometheus metrics server port
- `DISABLE_PROMETHEUS` - Disable Prometheus server if true

### Kafka Settings

Defined in `project_settings/kafka_settings.py`:

- `ENGINE_RESULTS_TOPIC` - Engine results topic name
- `RULE_HITS_TOPIC` - Third-party rule hits topic name
- `INVENTORY_TOPIC` - Inventory events topic name
- `PAYLOAD_TRACKER_TOPIC` - Payload status tracking topic
- `WEBHOOKS_TOPIC` - Webhook notifications topic
- `REMEDIATIONS_HOOK_TOPIC` - Remediations topic

## Git Workflow

### Branch Information

- **Main branch:** `main`
- **Current work branch:** `service_into_advisor_claude`

### Commit Standards

- Use descriptive commit messages
- ALWAYS include `Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>` trailer
- Run tests before committing
- Use heredoc for multi-line commit messages:

```bash
git commit -m "$(cat <<'EOF'
Subject line

Detailed explanation of changes.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

## Code Style

### General standard

In general lines should be wrapped so they are no longer than 80 characters,
although to avoid Flake8 warnings about breaking boolean operators across
multiple lines sometimes longer `if` conditions are OK.

Code should be indented as little as possible.  So negative tests that exit
early are preferred:

Good:
```
    if not foo and bar and baz:
        return
    do_foo_bar_baz()
```

Bad:
```
    if foo:
        if bar:
            if baz:
                do_foo_bar_baz()
```

And multiple imports should be wrapped with brackets:

```
from api.management.commands.advisor_inventory_service import (
    handle_inventory_event, handle_created_event, handle_deleted_event
)
```

Likewise, it's better to indent function arguments to the standard four
characters than to indent at the opening bracket, with the closing
bracket on a new line.

Good:
```
    logger.info(
        "Processing engine results for Inventory ID %s on account %s and org_id %s",
        inventory_uuid, account, org_id
    )

```

Bad:
```
    logger.info("Processing engine results for Inventory ID %s on account %s and org_id %s",
                inventory_uuid, account, org_id)

```

List and Dictionary comprehensions should be broken up into stages - the
value, the for loop, and optional conditions.  Each line should only have the
standard four space indent.

Good:
```
    data = {
        key: utils.traverse_keys(engine_results, key_path)
        for key, key_path in key_paths.items()
    }
```

Bad:
```
    data = {key: utils.traverse_keys(engine_results, key_path)
                 for key, key_path in key_paths.items()}
```

### Import Organization

Imports are organised in order of proximity to Advisor's code - standard
library going first and local imports last.

```python
# Standard library
import time
import logging

# Third-party
import prometheus

# Django
from django.conf import settings
from django.db import transaction

# Local
from api.models import Host, Upload, CurrentReport
import thread_storage
import payload_tracker
```


### Error Handling

- Use descriptive error messages
- Log errors with appropriate context (extra fields)
- Update Prometheus error counters
- Send payload tracker status on errors
- Don't let exceptions crash the service - log and continue

### Logging

```python
# Standard logging with context
logger.info("Message", extra={'inventory_id': uuid, 'account': account})

# Debug logging for development
logger.debug(f"Processing {data}")

# Error logging with exception
logger.exception("Error message", extra={'context': 'data'})
```

## Testing Considerations

- Tests use `DummyProducer` instead of real Kafka (check `settings.TESTING`)
- Database is created fresh for each test run
- Use fixtures from `api.tests.constants` for test data
- Mock external services (HBI, webhooks, remediations)

## Common Issues and Solutions

### Thread Storage Not Cleared
**Symptom:** Data from one message appearing in logs for another message
**Solution:** Ensure `make_async_handler()` wrapper is used for all handlers

### Database Deadlocks
**Symptom:** `OperationalError` or `InterfaceError` on concurrent updates
**Solution:** Use `select_for_update()` within `transaction.atomic()` block

### Missing System Type
**Symptom:** "Unable to get system type from DB - load fixtures!"
**Solution:** Run fixture loading command to populate SystemType table

### Kafka Consumer Not Starting
**Symptom:** No messages being processed
**Solution:** Check topic names in kafka_settings, verify Kafka connectivity

## Useful Commands

```bash
# Run the advisor service
(cd api && python advisor/manage.py advisor_inventory_service)

# Load fixtures
(cd api && python advisor/manage.py loaddata fixtures/system_types.json)

# Run database migrations
(cd api && python advisor/manage.py migrate)

# Create a Django shell
(cd api && python advisor/manage.py shell)

# Run linting
(cd api && flake8 advisor/)

# Check for missing migrations
(cd api && python advisor/manage.py makemigrations --check --dry-run)
```

## Recent Major Changes

### Service Merge (2025)
Consolidated three separate services into `advisor_inventory_service.py`:
- `advisor_inventory_service.py` (inventory events)
- `advisor_service.py` (incomplete skeleton, deleted)
- `service/service.py` (engine results and rule hits, deleted)

This unified service handles all three Kafka topics with concurrent processing.

### Payload Tracking Refactoring (2025)
Consolidated repetitive thread_storage patterns into helper functions:
- `start_operation_tracking()` - Initialize tracking with context
- `track_operation_failure()` - Record failures
- `track_operation_success()` - Record success

### Thread Storage Cleanup (2025)
Removed manual `clean_threading_cruft()` calls and integrated cleanup into the `make_async_handler()` wrapper for automatic cleanup before each task.

## Resources

- **Repository:** Red Hat Insights Advisor Backend
- **License:** GPLv3+
- **Python Version:** 3.12
- **Django Version:** Check requirements.txt
- **Main Dependencies:** Django, confluent-kafka, prometheus-client
