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

# This script does the following:
#   1. deploys a 'db copier' pod into an advisor OpenShift project
#   2. Copies dump_db.sh to the pod and runs the script
#   3. Downloads the data
#   4. Runs ansible playbook on target DB to set it up for 'restore'
#   5. Runs populate_db.sh on the target DB to restore the downloaded data
#   6. Runs anonymizer
#   7. Runs ansible playbook to restore standard "prod-like" config on the DB
#
# Usage:
#   Set the correct DB host in "ansible/hosts"
#   Set the correct DB creds in "test_db_creds.sh"
#   $ oc login ${API_URL} --token=${TOKEN}
#   $ oc project ${PROJECT}
#   $ bash run.sh

set -e

echo "*** Installing required ansible role"
cd ansible
ansible-galaxy install ome.postgresql
cd -

echo "*** Removing old db-copier pod"
if [[ $(oc get pods -l app=db-copier) ]]; then
    oc delete dc db-copier
    echo "Waiting for db-copier pod to delete..."
    while [[ $(oc get pods -l app=db-copier) ]]; do
        echo -n "."
        sleep 0.5
    done
fi

echo "*** Deploying db copier pod"

oc apply -f db-copier.yaml

set +e
REVISION=$(oc rollout latest dc/db-copier --output=jsonpath='{.status.latestVersion}')
set -e
if [ -z "$REVISION" ]; then
    REVISION=$(oc get dc/db-copier --output=jsonpath='{.status.latestVersion}' | tail -n 1)
fi
oc rollout status dc/db-copier --revision=${REVISION}

POD=$(oc get pods -l deployment=db-copier-${REVISION} | tail -n 1 | cut -f1 -d' ')

echo "*** Copying dump_db.sh to pod"
oc exec ${POD} -- /bin/bash -c 'mkdir -p /tmp/dumps'
oc cp dump_db.sh ${POD}:/tmp/dumps

echo "*** Running pg_dump..."

oc exec ${POD} -- /bin/bash -c 'cd /tmp/dumps && bash dump_db.sh'

echo "*** Downloading files..."
for f in $(oc exec ${POD} -- /bin/bash -c 'ls -d /tmp/dumps/*.sql' | xargs); do
    fname=$(basename $f)
    echo "*** Downloading $fname"
    oc cp ${POD}:$f .
    ls -lh $fname
    echo "*** $fname completed"
done
for f in $(oc exec ${POD} -- /bin/bash -c 'ls -d /tmp/dumps/data.dump.split*' | xargs); do
    fname=$(basename $f)
    echo "*** Downloading $fname"
    oc cp ${POD}:$f .
    ls -lh $fname
    echo "*** $fname completed"
done

echo "*** Restoring to test DB"

echo "*** Applying restore config to test DB"
cd ansible
ansible-playbook -i hosts --extra-vars="env=restore" playbook.yml
cd -

echo "*** Running restore"
source test_db_creds.sh
source populate_db.sh

echo "*** Running anonymizer"
cd ../../../../
pipenv run advisor/manage.py anonymize
cd -

echo "*** Applying standard config to test DB"
cd ansible
ansible-playbook -i hosts --extra-vars="env=prod" playbook.yml
cd -
