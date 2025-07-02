#!/bin/bash

# Copyright 2016-2024 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

# Insights Advisor is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# Insights Advisor is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with Insights Advisor. If not, see <https://www.gnu.org/licenses/>.

# -e: Exit immediately if any command or compound command exits
# -u: Treat unset variables and parameters as failures.
set -eu -o pipefail

# Make sure we can get a connection to the database server before we do anything
set +u
db_host=${ADVISOR_DB_HOST:-${ADVISOR_BACKEND_DB_SERVICE_HOST}}
db_port=${ADVISOR_DB_PORT_NUM:-${ADVISOR_BACKEND_DB_SERVICE_PORT}}
if [[ -z "$db_host" || -z "$db_port" ]]; then
    echo "Failed to get database host and port from environment - skipping connection check"
else
    until echo select 1 > /dev/tcp/$db_host/$db_port
    do
        echo Waiting for database connection to $db_host:$db_port
        sleep 1
    done
fi
set -u

if [ "${ENABLE_INIT_CONTAINER_MIGRATIONS,,}" == "true" ]; then
    echo "Running database migrations ..."
    pipenv run python api/advisor/manage.py migrate --noinput
fi
# Note: don't load data which is loaded by content import - e.g. resolution_risks
pipenv run python api/advisor/manage.py loaddata -v 3 rulesets rule_categories system_types upload_sources

if [ "${ADVISOR_ENV}" != 'dev' ]; then
    echo "Loading production fixtures for tasks and pathways ..."
    pipenv run python api/advisor/manage.py loaddata -v 3 production_tasks pathways_prod
fi

# Idempotent due to use of `CREATE IF NOT EXISTS` and `CREATE OR REPLACE`.
if [ "${ADVISOR_ENV}" == 'dev' ]; then
    echo "Creating mocked inventory table for the dev environment ..."
    pipenv run python api/advisor/manage.py mock_cyndi_table
fi

# Register notify hooks for new/resolved reports
# cd api/advisor
pipenv run python api/advisor/api/scripts/register_hooks.py
# cd -

dumped_content_dir=dumped_content

if [ "${ADVISOR_ENV}" == 'dev' ]; then
    echo "Skipping importing content because ADVISOR_ENV == dev"
    exit 0
elif [ "${ENABLE_INIT_CONTAINER_IMPORT_CONTENT:-false,,}" != "true" ]; then
    echo "Skipping importing content because ENABLE_INIT_CONTAINER_IMPORT_CONTENT != 'true'"
    exit 0
fi

# Look for the content files we need
if [[ ! (
    ( -f ${dumped_content_dir}/rule_content.yaml || -f ${dumped_content_dir}/rule_content.yaml.gz ) &&
    ( -f ${dumped_content_dir}/playbook_content.yaml || -f ${dumped_content_dir}/playbook_content.yaml.gz ) &&
    -f ${dumped_content_dir}/config.yaml
) ]]; then
    echo "Missing content files:"
    ls -lA ${dumped_content_dir}
    exit 1
fi

# Import the previously built content
echo "Importing content from ${PWD}/${dumped_content_dir} ..."
pipenv run python api/advisor/manage.py import_content -c ${dumped_content_dir}/
