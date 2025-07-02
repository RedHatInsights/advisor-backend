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

set +e

echo "Recombining split files"
cat data.dump.split?? > data.dump

# The restores can return exit code 1 with some non-fatal errors
set -e

echo "Importing pre-data"
psql -q < pre_data.sql

echo "Importing compressed data"

pg_restore -Fc --section="data" -d $PGDATABASE data.dump

echo "Importing post-data"
psql -q < post_data.sql

set +e

echo "Removing details from current reports"
psql -c "alter table api_currentreport drop details"
psql -c "alter table api_currentreport add details jsonb default '{}'"

echo "Running analyze"
psql -q -c "analyze"

echo "Done"
