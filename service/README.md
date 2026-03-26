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
topic `platform.playbook-dispatcher.runs`, defined in the `ENGINE_RESULTS_TOPIC`
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
- Find the `CurrentReport`s for this host.
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
This will start Zookeeper, Kafka, Postgresql and Nginx.
Nginx is a stand-in and emulates s3.
```
podman-compose up
```

## Installing some plugins
This service assumes you have a shared engine instance running and broadcasting
engine results for consumption. If you do not have a share engine instance
running you may utilize the fake engine broadcast messages in
manual_tests/send_fake_engine_results.

# Running the Service

Once you have deployed the environment and set up the database. You can run the
service and begin engine results analysis.

```
BOOTSTRAP_SERVERS=localhost:9092 pipenv run python service.py
```

## Sending mock engine results

You can send in fake results for analysis using two methods.
The first method is sending in fake engine results for direct consumption in this service.
```
pipenv run python manual_test/send_fake_engine_results.py
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
