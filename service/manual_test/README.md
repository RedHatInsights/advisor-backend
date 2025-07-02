Running the service locally
========================

This provides a way for developers to run the service locally in order to debug and test.
This uses a mock engine because the plugins are difficult to install and also kind-of secret/proprietary.
This is useful for debugging kafka and database issues.

Installation Instructions
-------------------------

- Get and start Kafka

  ```
  git clone https://github.com/confluentinc/cp-docker-images
  cd cp-docker-images/examples/cp-all-in-one/
  podman compose up
  
  ```
- Start the advisor DB(see advisor api readme for full instructions)
    
    Run these from the advisor api directory
    ```
    podman run -d --name db -p 5432:5432 -e POSTGRESQL_USER=insightsapi -e POSTGRESQL_PASSWORD=InsightsData -e POSTGRESQL_DATABASE=insightsapi registry.access.redhat.com/rhscl/postgresql-96-rhel7

    pipenv run advisor/manage.py migrate
    pipenv run advisor/manage.py loaddata rulesets rule_categories system_types basic_test_data
    ```



Running
--------
```
BOOTSTRAP_SERVERS=localhost:9092 MOCK_ENGINE=True python service.py
```

Send in an archive
--------
This script will act as the upload service, sending in an archive.
```
python manual_test/send_fake_upload.py
```

