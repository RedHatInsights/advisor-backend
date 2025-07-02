# dbtools ansible

ansible playbooks used to configure the perf test database

## Obtaining postgres config options

To obtain settings from a running postgresql deployment, launch psql and run:
```
COPY (select name, setting, boot_val, reset_val, unit from pg_settings order by name)
  TO "config.csv"
  WITH (FORMAT CSV, HEADER);
```

Then run `python3 extract_db_settings.py config.csv` and save the output to a yaml file
in the `vars` directory. This can be used as an `env` when running the playbook.

## Running the playbook

1) Make sure the ome postgresql role is installed:
```
ansible-galaxy install ome.postgresql
```

2) Ensure the server you are connecting to (defined in `hosts`) has ssh public key auth set up
and that you're able to log in as root via a public key.

3) To set the test DB configuration to match prod:
```
ansible-playbook -i hosts --extra-vars="env=prod" playbook.yml
```

4) To set the test DB configuration with config optimized for a DB restore:
```
ansible-playbook -i hosts --extra-vars="env=prod" playbook.yml
```
