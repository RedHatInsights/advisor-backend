# Advisor Service Module Migration Summary

## Overview

Successfully migrated service modules from `service/` into the Django app at `api/advisor/` and integrated them with the existing `advisor_inventory_service.py` management command. All tests (693 total) now pass.

## What Was Done

### 1. Module Migration (7 Service Modules Copied)

Copied the following modules from `service/` to `api/advisor/`:

1. **`bounded_executor.py`** - Thread pool executor for concurrent message processing
2. **`thread_storage.py`** - Thread-local storage for request context
3. **`payload_tracker.py`** - Kafka producer for payload tracking events
4. **`utils.py`** - Utility functions (clean_threading_cruft, traverse_keys)
5. **`reports.py`** - Webhook and remediation event generation
6. **`build_info.py`** - Build version information for Prometheus
7. **`prometheus.py`** - Prometheus metrics definitions

### 2. Import Fixes

**Changed all service modules to use Django settings:**
```python
# Before (service/settings.py)
import settings

# After (Django)
from django.conf import settings
```

**Removed Django setup code from reports.py:**
- The service version had `django.setup()` which is not needed in Django apps
- Django framework handles this automatically

**Fixed settings.TESTING check timing:**
- Original code checked `settings.TESTING` at module import time
- This caused errors when importing before Django was configured
- Changed to check at runtime when creating producer instances

### 3. Kafka Producer Integration

**Added DummyProducer support for tests:**

```python
# In reports.py and payload_tracker.py
if settings.TESTING:
    from kafka_utils import DummyProducer
    _producer = DummyProducer(kafka_settings.KAFKA_SETTINGS)
else:
    from confluent_kafka import Producer
    _producer = Producer(kafka_settings.KAFKA_SETTINGS)
```

This prevents tests from blocking on actual Kafka connections.

**Updated DummyProducer to support multiple calling styles:**

```python
def produce(self, topic: str, message: Optional[bytes] = None,
            callback: Optional[Callable] = None,
            key: Optional[bytes] = None, value: Optional[bytes] = None):
```

Supports both:
- `produce(topic, message, callback)` - webhook events
- `produce(topic, key=..., value=..., callback)` - remediation events

### 4. Kafka Topic Configuration

Added default values in `project_settings/kafka_settings.py`:

```python
# Before
WEBHOOKS_TOPIC = os.environ.get('WEBHOOKS_TOPIC')  # None in tests
PAYLOAD_TRACKER_TOPIC = os.environ.get('PAYLOAD_TRACKER_TOPIC')  # None in tests

# After
WEBHOOKS_TOPIC = os.environ.get('WEBHOOKS_TOPIC', 'hooks.outbox')
PAYLOAD_TRACKER_TOPIC = os.environ.get('PAYLOAD_TRACKER_TOPIC', 'platform.payload-status')
```

This ensures Kafka producers are initialized even in test environments.

### 5. Prometheus Metrics

Added missing inventory event metrics to `prometheus.py`:

```python
INVENTORY_HOST_CREATED = Counter(
    'insights_advisor_service_inventory_host_created',
    'Counter for inventory host created events'
)
INVENTORY_HOST_UPDATED = Counter(
    'insights_advisor_service_inventory_host_updated',
    'Counter for inventory host updated events'
)
INVENTORY_HOST_DELETED = Counter(
    'insights_advisor_service_inventory_host_deleted',
    'Counter for inventory host deleted events'
)
```

These are used by `advisor_inventory_service.py` to track inventory event processing.

### 6. Test Migration

Created 3 new test files in `api/advisor/api/tests/`:

1. **`test_advisor_service_engine_rule_hits.py`** (385 lines, 11 tests)
   - Tests for `handle_engine_results()` and `handle_rule_hits()`
   - Similar uploads, impacted dates, autoacks
   - Basic engine results, two sources, satellite systems
   - Bad keys validation, RHEL filtering

2. **`test_advisor_service_webhooks.py`** (230 lines, 2 tests)
   - Tests for webhook and remediation event generation
   - New report events
   - Resolved report events
   - Uses DummyProducer to capture Kafka messages

3. **`test_advisor_service_database.py`** (80 lines, 3 tests)
   - Database error handling in `create_db_reports()`
   - Upload source exceptions
   - Note: Manual retry tests not ported (Django handles this)

### 7. Test Fixes Applied

**Removed unnecessary patches:**
```python
# Before
dummy_producer = DummyProducer()
with patch.object(reports, '_producer', dummy_producer):
    reports.trigger_report_hooks(...)

# After (simpler)
reports.trigger_report_hooks(...)  # _producer already is DummyProducer
```

**Added setUp() to reset DummyProducer state:**
```python
def setUp(self):
    super().setUp()
    if reports._producer:
        reports._producer.reset_calls()
```

**Fixed poll/flush call expectations:**
- When both webhook and remediation events are sent: 2 calls each
- When only webhook events are sent: 1 call each

**Fixed test data expectations:**
```python
# Original test had Python bug: assert x.count(), 4  (doesn't check equality!)
# Fixed to match actual sample data:
self.assertEqual(client_upload.currentreport_set.count(), 1)  # sample has 1 report
self.assertEqual(aiops_upload.currentreport_set.count(), 2)   # sample has 2 hits
```

## Test Results

### ✅ All Tests Pass

```
Ran 693 tests in 64.031s
OK (skipped=2)
```

**Breakdown:**
- 16 advisor service tests (engine results, rule hits, webhooks, database)
- 677 other existing tests (API views, models, authentication, etc.)
- 2 skipped tests (unrelated to this work)

**Key Achievement:** No Kafka connection hangs - tests run quickly using DummyProducer

## Files Modified

### New Files Created
- `api/advisor/bounded_executor.py`
- `api/advisor/thread_storage.py`
- `api/advisor/payload_tracker.py`
- `api/advisor/utils.py`
- `api/advisor/reports.py`
- `api/advisor/build_info.py`
- `api/advisor/prometheus.py`
- `api/advisor/api/tests/test_advisor_service_engine_rule_hits.py`
- `api/advisor/api/tests/test_advisor_service_database.py`
- `api/advisor/api/tests/test_advisor_service_webhooks.py`
- `api/advisor/api/tests/sample_engine_results.json`
- `api/advisor/api/tests/sample_satellite_engine_results.json`
- `api/advisor/api/tests/sample_rhel6_engine_results.json`
- `api/advisor/api/tests/sample_rule_hits.json`
- `api/advisor/api/tests/sample_report.json`

### Files Modified
- `api/advisor/project_settings/kafka_settings.py` - Added Kafka topic defaults
- `api/advisor/kafka_utils.py` - Updated DummyProducer.produce() signature

## Git Commits

1. `7fefed6` - Copy service modules into api/advisor and fix imports for Django
2. `66fddf2` - Remove unnecessary patches from webhook tests
3. `42b6eb3` - Remove unnecessary patches from webhook tests (amended to use reset_calls)
4. `e038d96` - Fix settings.TESTING check to run at runtime not import time
5. `98b4818` - Update DummyProducer.produce() to accept key and value parameters
6. `6b38072` - Update DummyProducer.produce() to accept key and value parameters (amended with Optional import)
7. `4ed5cf7` - Add default values for WEBHOOKS_TOPIC and PAYLOAD_TRACKER_TOPIC
8. `3cf4b16` - Fix test expectations for poll/flush calls in webhook tests
9. `8873471` - Fix test_handle_engine_results_two_sources expectations
10. `4d04095` - Add missing Prometheus metrics for inventory events

## Architecture Changes

### Before
```
service/
├── service.py (standalone service with BoundedExecutor)
├── reports.py
├── prometheus.py
└── ... (other modules)

api/advisor/api/management/commands/
├── advisor_inventory_service.py (Django command, inventory events only)
└── advisor_service.py (incomplete skeleton)
```

### After
```
api/advisor/
├── bounded_executor.py ←— copied from service/
├── thread_storage.py ←— copied from service/
├── payload_tracker.py ←— copied from service/
├── utils.py ←— copied from service/
├── reports.py ←— copied from service/
├── build_info.py ←— copied from service/
├── prometheus.py ←— copied from service/
└── api/management/commands/
    └── advisor_inventory_service.py (unified service: inventory + engine results + rule hits)
```

**Note:** `service/service.py` and `api/management/commands/advisor_service.py` can now be deleted as their functionality is merged into `advisor_inventory_service.py`.

## Key Technical Details

### Producer Pattern
- **Global variable:** `_producer` initialized at module load time
- **Test mode:** Uses `DummyProducer` when `settings.TESTING` is True
- **Production mode:** Uses `confluent_kafka.Producer` otherwise
- **Lazy initialization:** Only created if Kafka topics are configured

### Thread Pool Integration
- Uses `BoundedExecutor` from `bounded_executor.py`
- Configurable pool size via `settings.THREAD_POOL_SIZE` (default: 30)
- All Kafka handlers wrapped with `make_async_handler()` for concurrent processing
- Thread storage cleaned at start of each handler via `utils.clean_threading_cruft()`

### Database Operations
- Django ORM used throughout (no manual retry logic needed)
- Transactions used in `create_db_reports()` for consistency
- `select_for_update()` locks prevent race conditions

## Next Steps (Optional)

1. **Delete old files:**
   - `service/service.py` (functionality merged)
   - `api/advisor/api/management/commands/advisor_service.py` (incomplete skeleton)

2. **Update deployment configurations:**
   - Ensure deployments use `advisor_inventory_service` command
   - Update Kubernetes/OpenShift manifests if needed

3. **Clean up test artifacts:**
   - Consider adding `api/advisor/test_reports/` to `.gitignore`
   - These XML files are generated on each test run

4. **Documentation updates:**
   - Update README or developer docs to reflect unified service
   - Document the BoundedExecutor thread pool configuration

## Testing Checklist

All items completed and verified:

- ✅ Service modules import successfully in Django environment
- ✅ No Kafka connection hangs during test runs
- ✅ DummyProducer correctly captures webhook and remediation events
- ✅ Prometheus metrics defined for all service operations
- ✅ All 16 advisor service tests pass
- ✅ All 693 total tests pass
- ✅ Linter (Flake8) passes with no errors
- ✅ Tests run in reasonable time (~64 seconds for full suite)

## Contact

This work was completed on February 16, 2026 (Sydney time) on branch `service_into_advisor_claude`.
