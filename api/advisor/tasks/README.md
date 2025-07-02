Tasks API
==========

The Tasks API is part of the Advisor API code for the moment, until we need
the two to be distinct projects.

Tasks allows Red Hat to define a large process run in a playbook that may take
some time to complete and which produces specialised output.  The Tasks API
allows users to find these tasks, schedule them to be executed on a list of
systems that are connected either by the Red Hat Connector or by Satellite,
and monitor the results of this run.

Setting up a local development / test environment
--------------------------------------------------
The Tasks API requires the same pre-requisites and setup as the Advisor API.
Refer to the Pre-requisites and Setup section in its [README](../../../README.md).

Start the Advisor DB and create the tables and populate it with fixture data:
```bash
export ADVISOR_DB_HOST=localhost
podman-compose up -d advisor-db
pipenv shell
python api/advisor/manage.py migrate
python api/advisor/manage.py mock_cyndi_table
python api/advisor/manage.py loaddata basic_task_test_data
```
Update the stale timestamps of the hosts in the DB to be in the future.  The
hosts won't be considered stale then and will show up in queries:
```bash
python api/advisor/manage.py freshen_hosts
```
Start the Django test server:
```bash
LOG_LEVEL=DEBUG python api/advisor/manage.py runserver
```
Access the Tasks API and Swagger interface at:
* http://localhost:8000/api/tasks/v1/
* http://localhost:8000/api/tasks/v1/schema/swagger-ui/

To test out the API via the swagger interface you will need to provide authorization.
Run this and add the value to the `x-rh-identity` field in the Swagger Authorize button/modal:
```bash
echo '{"identity": {"account_number": "1234567", "org_id": "9876543", "type": "User", "auth_type": "jwt", "user": {"username": "testing", "is_internal": true}}}' | base64 -w 0 ; echo
```

Run tests with:
```bash
pipenv run testtasks
```
... or ...
```bash
python api/advisor/manage.py test tasks
```

### Internal API

In stage and production api's reached through a separate server - when working locally we don't have that server name so we use the internal path. To test API methods you will need:
* Add `/internal/` address path before api endpoint (eg.: `http://localhost:8000/internal/api/tasks/v1/task/{slug}`)

* Provide an `Associate` authorization to the `x-rh-identity` header field, as base64 encoded, like this:
```bash
eyJpZGVudGl0eSI6IHsidHlwZSI6ICJBc3NvY2lhdGUiLCAiYXV0aF90eXBlIjogInNhbWwtYXV0aCIsICJhc3NvY2lhdGUiOiB7IlJvbGUiOiBbInNvbWUtbGRhcC1ncm91cCIsICJhbm90aGVyLWxkYXAtZ3JvdXAiXX19fQo=
```
which is bellow base64 encoded json:
```bash
echo '{"identity": {"type": "Associate", "auth_type": "saml-auth", "associate": {"Role": ["some-ldap-group", "another-ldap-group"]}}}' | base64 -w 0 ; echo
```


Implementation details
=======================

Serving playbooks
-----------------

Playbooks are served from the database - specifically, the 'playbook' field
in the Task.  This data is stored in the production tasks fixture file at
`api/advisor/tasks/fixtures/production_tasks.json`.  However, production
playbooks are large and it's much easier to edit them on the filesystem, so
playbooks also exist in the `playbooks/` directory.

After you have edited a playbook, it will need to be signed.  This process is
documented at [link].

The signed playbook can then be put into the file in the `playbooks/`
directory and then loaded into the production fixture using the command:

`api/advisor/manage.py tasks_sync_playbook_content`

(You may need to be in a `pipenv` shell for this.)

Tests will fail if the playbook does not appear to be signed, or if the
playbook content on the filesystem does not match the playbook content in the
production fixture.

Playbook output
----------------

The results of script / playbook processing should be output in JSON format.
There are two ways of doing this.

For playbooks, the last step should be exactly this:

```yaml
    - name: Print Task Result
      ansible.builtin.debug:
        var: task_results
```

This must be the last step in the playbook, as the report content search uses
the last `ansible.builtin.debug` message and the `PLAY RECAP` section break
to identify the start and end of the data.

For playbooks, the general process is to build a 'task_results' object, with
the fields as described below, and update it as the playbook continues.  This
ending step then outputs the task results in the format required.

For scripts, the JSON output should be between `### JSON START ###` and
`### JSON END ###` markers.  Similarly to playbooks, the general process is
to have variables or an `object` / `dict` structure that contains the state
of processing.  Then the last step, executed no matter what conditions the
script encountered, should be to output that information in JSON object
format.

Results contents
----------------

Results **MUST** contain these three fields:

* `alert`: a boolean indicating whether errors were detected as a result of
  running the script.
* `message`: a one line summary of the processing results.
* `report`: a block of text containing more detail about the results.

Additionally, a fourth field **SHOULD** be included:

* `report_json`: a piece of structured content that may allow other scripts
  to process the results in more detail.

Verifying Playbook Signatures
-----------------------------
If the playbook content has changed, the playbook signature very likely needs
to be updated too. To verify a playbook signature is correct, use the
playbook_verifier app within insights-client. The system must be registered
to Insights using insights-client first, then run (as root):

```bash
# insights-client -m insights.client.apps.ansible.playbook_verifier < api/advisor/tasks/playbooks/<playbook_to_verify.yml>
```
For example, to verify all the playbooks in the playbooks directory:
```bash
# cd api/advisor/tasks/playbooks; for playbook in $(ls); do echo -n "Verifying $playbook ... "; insights-client -m insights.client.apps.ansible.playbook_verifier < $playbook >/dev/null && echo "OK" || echo; done; cd -
```
Or to verify the playbooks changed in the last commit:
```bash
# for playbook in $(git show --name-only --oneline | grep .yml$); do echo -n "Verifying $playbook ... "; insights-client -m insights.client.apps.ansible.playbook_verifier < $playbook >/dev/null && echo "OK" || echo; done
```
If any playbooks fail verification more information may be found in `/var/log/insights-client/insights-client.log`.

Running Tasks on Stage
-----------------------
To run tasks in stage, you will first need to register and connect your
system to the stage environment by following these steps.

1. Install the `rhc` and `rhc-worker-playbook` RPMs (if not done already):
```shell
# dnf install rhc rhc-worker-playbook
```
2. Unregister the system from production subscription-manager and configure it to use stage:
```shell
# rhc disconnect
# subscription-manager config --server.hostname=subscription.rhsm.stage.redhat.com
# subscription-manager register --activationkey=<stage-activation-key> --org=<stage-org>
```
... rhc disconnect stops the rhcd service, unregisters the host from Insights and from Subscription Manager.

Activation keys for stage can be found here: https://console.stage.redhat.com/insights/connector/activation-keys

3. Edit `/etc/rhc/config.toml` to set these lines:
```
broker = ["wss://connect.cloud.stage.redhat.com:443"]
data-host = "cert.cloud.stage.redhat.com"
log-level = "debug"  # optional
```
Note, make sure its `cloud.stage` and not `console.stage` otherwise hosts may
not get an RHC client ID and not show up in Tasks Web UI.

4. (Optional) If using [rhc-0.2.5-1](https://issues.redhat.com/browse/RHINENG-15630) on RHEL8 or 9, also run this command:
```shell
echo 'env = ["HTTPS_PROXY=", "http_proxy=", "HTTP_PROXY=", "https_proxy="]' > /etc/rhc/workers/rhc-worker-playbook.worker.toml
```
... to workaround a bug in that version of rhc.  If the rhcd service is already running, then reboot the machine.

5. Edit `/usr/lib/systemd/system/rhcd.service` to set these lines:
```
[Service]
Environment="HTTP_PROXY=http://squid.corp.redhat.com:3128"
Environment="HTTPS_PROXY=http://squid.corp.redhat.com:3128"
```

6. Edit `/etc/insights-client/insights-client.conf` to set these lines:
```
auto_config=False
base_url=cert.console.stage.redhat.com:443/r/insights
cert_verify=False
proxy=http://squid.corp.redhat.com:3128
username=<stage-username>
password=<stage-password>
```

7. Run rhc connect:
```shell
# rhc connect
```
... which registers the host with Subscription Manager (requires your stage username/password
if you didn't register using activation keys above) and with Insights and starts the rhcd service.

Note, if you are configuring a CentOS system for (pre-)conversion follow the instructions [here](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/converting_from_an_rpm-based_linux_distribution_to_rhel/index#proc_preparing-for-a-rhel-conversion-using-insights_converting-using-insights)
and use the configuration above if you wish to register it to the Insights Stage environment.

Viewing playbook output
------------------------
By default, task playbook output is logged to `/var/log/rhc-worker-playbook/ansible/<random_uuid>/stdout` on the client.

It's also possible to configure ansible to log playbook output to a specific
file, eg `/var/log/ansible.log`. Edit `/etc/ansible/ansible.cfg` and add
these lines:
```
[defaults]
log_path = /var/log/ansible.log
display_args_to_stdout = True
```
Then `tail -f /var/log/ansible.log` to watch the playbook output.

Viewing, adding and editing tasks in Stage
-------------------------------------------
### Via the Web UI

The complete list of tasks can be accessed in Stage at https://internal.console.stage.redhat.com/api/tasks/v1/task.

These HTML pages contain forms for adding and editing tasks and their playbooks.
For example, tasks can be activated / deactivated and filters / filter messages can be added or modified, amongst other things.

### Via the command line

The tasks in stage can also be accessed from the command line with curl, like so:
```shell
$ curl -sX GET 'https://console.stage.redhat.com/api/tasks/v1/task/<SLUG>' \
-u $USERPASS -H 'Content-Type: application/json' --proxy http://squid.corp.redhat.com:3128 | \
jq .
```
Note: `$USERPASS` is an environment variable containing a stage username and password in the form `username:password`.
Substitute with other authentication methods you are familiar with, eg `-n` for a `.netrc` file, or a basic auth header.

For example, to view the slug and title of all tasks in stage, you can use curl and jq, like so:
```shell
$ curl -sX GET 'https://console.stage.redhat.com/api/tasks/v1/task' \
-u $USERPASS -H 'Content-Type: application/json' --proxy http://squid.corp.redhat.com:3128 | \
jq -r '.data[] | "\(.slug): \(.title)"'
...
insights-client: Run the insights-client
ping: Run the ansible ping module
convert-to-rhel-analysis: Pre-conversion analysis for converting to RHEL
leapp-preupgrade: Pre-upgrade analysis for in-place upgrade from RHEL 8
convert-to-rhel-analysis-stage: Pre-conversion analysis for converting to RHEL (stage)
...
```

To modify the fields of a task in stage, you can issue a curl PATCH request, like so:
```shell
$ curl -sX PATCH 'https://internal.console.stage.redhat.com/api/tasks/v1/task/ping' \
-H 'Content-Type: application/json' -H 'Cookie: session=<TURNPIKE SESSION ID>' --proxy http://squid.corp.redhat.com:3128 \
--data-raw '{"active": true}'
```
... which activates the ping task.
```shell
curl -sX PATCH 'https://internal.console.stage.redhat.com/api/tasks/v1/task/convert-to-rhel-conversion-stage' \
-H 'Content-Type: application/json' -H 'Cookie: session=<TURNPIKE SESSION ID>' --proxy http://squid.corp.redhat.com:3128 \
--data-raw '{"filter_message": "Eligible systems include systems running any version of CentOS 7", "filters": ["os_v7", "centos"]}'
```
... which sets the filters and filter_message on the convert-to-rhel-conversion-stage task.

Note: The `<TURNPIKE SESSION ID>` value can be obtained by opening the browser tools when accessing
https://internal.console.stage.redhat.com/api/tasks/v1/task, viewing the Cookies in the Network tab,
and using the `session` cookie value.

Running tasks in Stage via the command line
-------------------------------------------
To run the ping task against a particular host, `POST` to the `executed_task` endpoint with the host's UUID:
```shell
curl -sX POST 'https://console.stage.redhat.com/api/tasks/v1/executed_task' \
-u $USERPASS -H 'Content-Type: application/json' --proxy http://squid.corp.redhat.com:3128 \
--data-raw '{"task": "ping", "hosts": ["<host_UUID_from_inventory>"]}'
```
To run a task with parameters, you only need to specify the parameter keys and values for parameters that are
different from their default values, eg:
```shell
curl -sX POST 'https://console.stage.redhat.com/api/tasks/v1/executed_task' \
-u $USERPASS -H 'Content-Type: application/json' --proxy http://squid.corp.redhat.com:3128 \
--data-raw '{"task": "insights-client", "hosts": ["<host_UUID_from_inventory>"], "parameters": [{"key": "status", "value": "True"}]}'
```
... where the `True` value for the `status` parameter is different from its default value.

Testing playbooks on the command line of target systems
-------------------------------------------------------
Copy the playbook to target system.  If the playbook has variables that can be overridden as task parameters,
pass the variables as a JSON object after the `-e` option.

For example, in the `rhel-ai-update.yml` playbook, the `update_version` variable can be overridden to specify
the new RHEL AI image tag to update to, eg `1.5`:
```shell
[local-system]$ scp api/advisor/tasks/playbooks/rhel-ai-update.yml user@<target_system>:/tmp
[target-system]$ sudo ansible-playbook --syntax-check /tmp/rhel-ai-update.yml
[target-system]$ sudo ansible-playbook /tmp/rhel-ai-update.yml -e "{'content_vars':{'update_version':'1.5'}}"
```

Troubleshooting failed tasks
-----------------------------
Unfortunately, the messages displayed in the Tasks UI may not be helpful in
determining why a task failed to run.

For example, `Task failed to complete for an unknown reason. Retry this task
at a later time.` showing in the UI doesn't give any clues as to the problem.

Things to try:

1. **Run `rhc status` and make sure all the bullet points are green / connected / active:**
    ```
    ● Connected to Red Hat Subscription Management
    ● Connected to Red Hat Insights
    ● The Remote Host Configuration daemon is inactive
    ```
    Here you can see the `rhcd` service wasn't running.  If any items are red / failed, try running `rhc connect` to restore the failed items.


2. **Tail the logs as you try to execute the task**

    Use `journalctl -u rhcd -f` or `tail -f /var/log/messages` to make sure your system is receiving the playbook to run.  For example:
    ```
    ...
    Nov 29 17:46:45 host-system rhcd[390014]: [rhcd] 2023/11/29 17:46:45 /builddir/build/BUILD/rhc/yggdrasil-0.2.3/cmd/yggd/mqtt.go:18: received a message on topic redhat/insights/c3e66d99-e93c-47c2-9d20-1f60705a95c8/data/in
    Nov 29 17:46:45 host-system rhcd[390014]: [rhcd] 2023/11/29 17:46:45 /builddir/build/BUILD/rhc/yggdrasil-0.2.3/cmd/yggd/http.go:38: sending HTTP request: GET https://cert.cloud.stage.redhat.com/api/tasks/v1/task/ping/playbook
    Nov 29 17:46:46 host-system rhcd[390014]: [rhcd] 2023/11/29 17:46:46 /builddir/build/BUILD/rhc/yggdrasil-0.2.3/cmd/yggd/http.go:51: received HTTP 200 OK
    ...
    ```
    If you don't see any messages then check the system is connected ok with `rhc status`.

If the task playbook runs but produces errors, see the `Viewing playbook output` section above to view the playbook output.


Notification Events
-------------------

Tasks produces notification events under `rhel` bundle (application `tasks`).
Events include executed tasks events and individual job events.


List of events:

* `executed-task-started` — Task Started
  * A task has started.
* `executed-task-cancelled` — Task Canceled
  * A task have been canceled.
* `executed-task-completed` — Task Completed
  * All jobs within a task have completed.
* `job-started` — Task Job Started
  * A system task job has been started and dispatched.
* `job-completed` — Task Job Completed
  * A system task job has completed.
* `job-failed` — Task Job Failed
  * A system task job has failed.
* `job-cancelled` — Task Job Cancelled
  * A system task job has been cancelled.

### Event Structure

```
{
    "id": "uuid of the message"
    "version": "v1.2.0",
    "bundle": "rhel",
    "application": "tasks",
    "event_type": "(se list of events above)",
    "timestamp": "2020-12-08T09:31:39Z",       // ISO-8601 formatted date
    "account_id": "123456",
    "org_id": "54321",
    "context": {
       // see examples
    },
    "events": [                                // list of (sub)events (e.g. jobs)
      {
          "metadata": {},
          "payload": {
            ...
          }
      },
      ...
    ],
    "recipients": [],                          // not used, yet
}
```


### Event fields

* `task_name`: Title of an executed task
* `task_slug`: Task slug, human-readable id of a task type
* `executed_task_id`: ID number of an executed task
* `system_uuid`: Inventory Id of a system
* `display_name`: Display name of a system
* `status`: Status text of an executed task or a job
  * values for tasks: Running, Completed, Cancelled
  * values for jobs: Running, Success, Failure, Timeout, Cancelled

### Event payload examples


Executed task event:
```
  "context": {},
  "events": [
    {
        "metadata": {},
        "payload": {
          "task_name": "Pre-conversion analysis for converting to RHEL",
          "task_slug": "convert-to-rhel-analysis",
          "executed_task_id": "61e1fb4c-9195-4f6d-9839-9ae363df6443",
          "status": "Running",
        }
    }
  ]
```

Job event:
```
  "context": {
    "task_name": "Pre-conversion analysis for converting to RHEL",
    "task_slug": "convert-to-rhel-analysis",
    "executed_task_id": "61e1fb4c-9195-4f6d-9839-9ae363df6443",
  },
  "events":[
      {
          "system_uuid": "9a666449-3e7d-4cea-b897-5d9e4535642d",
          "display_name": "host1.example.com",
          "status": "Running",
      },
      {
          "system_uuid": "4bcf6599-5725-4f2d-a57b-766732484886",
          "display_name": "host2.example.com",
          "status": "Running",
      }
  ]
```
