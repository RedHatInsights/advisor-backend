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

# Load postgres DB connection env vars:
#   $ source test_db_creds.sh

# Adjust these vars as needed ...
export PGHOST=CHANGE_TO_IP_ADDR
export PGPORT=5432
export PGUSER=insightsapi
export PGDATABASE=insightsapi
export PGPASSWORD=InsightsData


export ADVISOR_DB_HOST=$PGHOST
export ADVISOR_DB_PORT=$PGPORT
export ADVISOR_DB_USER=$PGUSER
export ADVISOR_DB_NAME=$PGDATABASE
export ADVISOR_DB_PASSWORD=$PGPASSWORD
