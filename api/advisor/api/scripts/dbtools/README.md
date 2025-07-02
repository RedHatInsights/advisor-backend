# DB Tools

Tools related to dumping/restoring a database for testing purposes

## Taking a database dump

You should collect the commands for "clean"/"pre-data", "data", and "post-data" sections separately. This allows the indices/fk constraints to be dropped while importing the data, which is the recommended way to populate a large DB.

From the postgres documentation:

> The data section contains actual table data, large-object contents, and sequence values. Post-data items include definitions of indexes, triggers, rules, and constraints other than validated check constraints. Pre-data items include all other data definition items.


### The easy way
Use the script that glues everything together: `run.sh`

1) Set the proper creds for your target database in `test_db_creds.sh`
2) Set the proper host for your target database in `ansible/hosts`
3) Log in to OpenShift and switch to the advisor namespace you want to copy the DB from:
    ```
    oc login <url> --token=<token>
    oc project advisor-prod
    ```
4) Run the script that does it all for you:
    ```
    bash run.sh
    ```

### The long way (if you're curious)
The long version of what this script does is below:


#### Dumping the source database
1) Log into the advisor-prod project with `oc`
2) Create a pod for running the dump, we use the postgres image since it has 'psql' installed
    ```
    oc apply -f db-copier.yaml
    ```
    This pod will use the secrets stored in the 'advisor-db' secret in the namespace.
3) Wait for the pod to come up, then create a dir on it for the dumps:
    ```
    POD_NAME=$(oc get pods | grep db-copier | cut -f1 -d' ')
    oc exec $POD_NAME -- /bin/bash -c 'mkdir -p /tmp/dumps'
    ```
4) Copy the `dump_db.sh` script to the pod:
    ```
    POD_NAME=$(oc get pods | grep postgres-dumper | cut -f1 -d' ')
    oc cp dump_db.sh $POD_NAME:/tmp/dumps
    ```
5) Run `dump_db.sh` inside the pod:
    ```
    cd /tmp/dumps && bash dump_db.sh
    ```
    This will produce `pre_data.sql`, `post_data.sql`, and several `data.dump.splitNN` files
6) Copy the files to the system you'll run the restore from:
    ```
    POD_NAME=$(oc get pods | grep postgres-dumper | cut -f1 -d' ')
    # Copy the files 1 at a time ... large files/dirs do not copy well with 'oc cp'
    for f in $(oc exec $POD_NAME -- /bin/bash -c 'ls -d /tmp/dumps/*.sql' | xargs); do oc cp $POD_NAME:$f .;done
    for f in $(oc exec $POD_NAME -- /bin/bash -c 'ls -d /tmp/dumps/data.dump.split*' | xargs); do oc cp $POD_NAME:$f .;done
    ```

See below on using the saved files to do a DB restore


#### Restoring to test database

1) Tweak postgresql config to allow for a faster import.
    You can alter the server's configurations using an ansible playbook. In the `ansible` dir, modify `hosts` to add your target DB.
    *NOTE*: you'll need to add your ssh pubkey into `~/.ssh/authorized_keys` on the target DB server

    Then run: `ansible-playbook -i hosts --extra-vars="env=restore" playbook.yml`

    For more details on the configs this playook is putting in place ...
    * Visit [pgtune](https://pgtune.leopard.in.ua/#/), fill out the form, and get recommended settings. Apply these to your `postgresql.conf`
    * Ideally, the system running the DB has at least 8GB RAM available. If it has less, edit the `CHUNK_SIZE` in `populate_db.sh` and set it to `(RAM available / 2)`
    * Apply these settings to postgresql.conf *only for the restore* -- these essentially turn off a lot of the data protection mechanisms in the DB.
    ```
    archive_mode = off
    autovacuum = off
    synchronous_commit = off
    wal_writer_delay = 1000ms
    fsync = off
    full_page_writes = off
    wal_level = minimal
    max_wal_senders = 0
    ```
    * Restart your postgres service
    * It's recommended to drop the `insightsapi` database and re-create it, which you can do as the postgres user with:
    ```
    postgres:~$ dropdb
    postgres:~$ createdb insightsapi
    postgres:~$ psql
    postgres=# grant all privileges on database insightsapi to user insightsapi;
    ```
2) If during a copy, your system's OOM reaper kills the DB process -- this can help:
    ```
    sysctl -w vm.overcommit_memory = 2
    sysctl -w vm.overcommit_ratio = 90
    ```
3) Place `pre_data.sql`, `data.dump.split` files, and `post_data.sql` in a directory along with the `populate_db.sh` and `db_creds.sh` scripts.
4) Edit `test_db_creds.sh` to set proper creds for your target DB.
5) Run the restore:
    ```
    source test_db_creds.sh && bash populate_db.sh
    ```
6) Run the anonymizer to scrub customer info:
    ```
    pipenv run advisor/manage.py anonymize
    ```
7) Restore your DB settings back to "normal" configurations. If using ansible, you can do this with:
    ```
    ansible-playbook -i hosts --extra-vars="env=prod" playbook.yml
    ```
