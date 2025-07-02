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

from django.core.management.base import BaseCommand
from django.db import connection


cyndi_query = """
CREATE SCHEMA IF NOT EXISTS inventory;

CREATE TABLE IF NOT EXISTS inventory.hosts_table (
    id uuid PRIMARY KEY,
    account character varying(10),
    org_id character varying(50) NOT NULL,
    display_name character varying(200) NOT NULL,
    tags jsonb NOT NULL,
    groups jsonb NOT NULL,
    updated timestamp with time zone NOT NULL,
    created timestamp with time zone NOT NULL,
    stale_timestamp timestamp with time zone NOT NULL,
    stale_warning_timestamp timestamp with time zone NOT NULL,
    culled_timestamp timestamp with time zone NOT NULL,
    system_profile jsonb NOT NULL,
    per_reporter_staleness jsonb default '{}'::jsonb,
    insights_id uuid
);

CREATE OR REPLACE VIEW inventory.hosts (
    id, account, org_id, display_name, tags, groups, updated, created, stale_timestamp,
    stale_warning_timestamp, culled_timestamp, system_profile, per_reporter_staleness, insights_id
) AS
SELECT
    id, account, org_id, display_name, tags, groups, updated, created, stale_timestamp,
    stale_warning_timestamp, culled_timestamp, system_profile, per_reporter_staleness, insights_id
FROM inventory.hosts_table;
"""


class Command(BaseCommand):
    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            cursor.execute(cyndi_query)
