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

echo "Running database migrations ..."
# podman-compose ensures the advisor-db service is running first
pipenv run python api/advisor/manage.py migrate --noinput
pipenv run python api/advisor/manage.py loaddata --verbosity=3 rulesets rule_categories system_types upload_sources

echo "Loading production fixtures for tasks and pathways ..."
pipenv run python api/advisor/manage.py loaddata --verbosity=3 production_tasks pathways_prod

# Create fake inventory data for the dev environment, and load basic test data for the API, eg rules and hosts
echo "Creating mocked inventory table and loading test data ..."
pipenv run python api/advisor/manage.py mock_cyndi_table
pipenv run python api/advisor/manage.py loaddata --verbosity=3 basic_test_data basic_task_test_data
pipenv run python api/advisor/manage.py freshen_hosts

# Import content from the dumped content directory if it exists
dumped_content_dir='api/test_content/real_content'
if [[ -d ${dumped_content_dir} && (
    ( -f ${dumped_content_dir}/rule_content.yaml || -f ${dumped_content_dir}/rule_content.yaml.gz ) &&
    ( -f ${dumped_content_dir}/playbook_content.yaml || -f ${dumped_content_dir}/playbook_content.yaml.gz ) &&
    -f ${dumped_content_dir}/config.yaml
) ]]; then
    echo "Importing content from ${PWD}/${dumped_content_dir} ..."
    pipenv run python api/advisor/manage.py import_content -c ${dumped_content_dir}/
else
    echo "No content to import from ${PWD}/${dumped_content_dir} - skipping content import"
fi
