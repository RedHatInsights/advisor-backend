Insights Advisor Service
========================
This is the Insights Advisor Service. This service listens on
a specific Kafka topic for available engine results payloads to
analyze and generate reports for. This utilizes the shared engine
instances.


Pre-requisites
--------------
```
docker
docker-compose
```


Setup Python environment
------------------------
Setup the Python environment:
```
pipenv shell
pipenv install
pipenv install --dev
```


Deploying
---------
This will start Zookeeper, Kafka, Postgresql and Nginx.
Nginx is a stand-in and emulates s3.
```
docker-compose up
```


Installing some plugins
-----------------------
This service assumes you have a shared engine instance running and broadcasting engine results for consumption.
If you do not have a share engine instance running you may utilize the fake engine broadcast messages in
manual_tests/send_fake_engine_results.


Running the Service
-------------------
Once you have deployed the environment and set up the database. You can run the service and begin
engine results analysis.
```
BOOTSTRAP_SERVERS=localhost:9092 pipenv run python service.py
```


Sending mock engine results
---------------
You can send in fake results for analysis using two methods.
The first method is sending in fake engine results for direct consumption in this service.
```
pipenv run python manual_test/send_fake_engine_results.py
```

The second method emulates an inventory message and will require a shared engine instance running.
This README does not intend to go through the steps to set up a shared engine instance.
However, if you have one running you can use the following script which will send a message to the
shared engine, then broadcast its results for consumption in this service.
```
pipenv run python manual_test/send_fake_inventory_engine_message.py
```


Testing
-------
To run tests, run the following commands:
Start the DB:
```
docker-compose up
```
Then to run tests:
```
pipenv run flake8 .
pipenv run python -m pytest --cov-config=.coveragerc --cov=. --cov-report html tests -s -vv -W ignore::DeprecationWarning
```
Coverage tests will then be located at `htmlcov/index.html` and must be greater than 80%.

`pytest-django` will run DB migrations and load fixtures for you automatically.


Updating Pipfile.lock
--------------------
At this time, make sure you do the update using Python 3.6 to avoid losing the dependency of `importlib_metadata`. This is a required dependency of pytest for Python < 3.8, which our Jenkins builder uses.


Contributing
--------------------
All outstanding issues or feature requests should be filed as Issues on this Github
page. PRs should be submitted against the master branch for any new features or changes,
and pass all testing above.
