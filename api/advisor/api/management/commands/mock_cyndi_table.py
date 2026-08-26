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
    last_check_in timestamp with time zone NOT NULL,
    stale_timestamp timestamp with time zone NOT NULL,
    system_profile jsonb NOT NULL default '{}'::jsonb,
    reporter character varying(200) NOT NULL,
    per_reporter_staleness jsonb default '{}'::jsonb,
    insights_id uuid,
    inventory_id uuid,
    os_name character varying(50),
    os_major integer,
    os_minor integer,
    host_type character varying(50),
    bootc_booted_image character varying(512),
    bootc_booted_image_digest character varying(256),
    rhc_client_id uuid,
    workloads jsonb default '{}'::jsonb,
    system_update_method character varying(50),
    workspace_id uuid,
    workspace_name character varying(200)
);

DROP VIEW IF EXISTS inventory.hosts;

CREATE OR REPLACE VIEW inventory.hosts (
    id, account, org_id, display_name, tags, groups, updated, created,
    last_check_in, stale_timestamp, system_profile, reporter,
    per_reporter_staleness, insights_id,
    inventory_id, os_name, os_major, os_minor, host_type,
    bootc_booted_image, bootc_booted_image_digest, rhc_client_id,
    workloads, system_update_method, workspace_id, workspace_name
) AS
SELECT
    id, account, org_id, display_name, tags, groups, updated, created,
    last_check_in, stale_timestamp, system_profile, reporter,
    per_reporter_staleness, insights_id,
    inventory_id, os_name, os_major, os_minor, host_type,
    bootc_booted_image, bootc_booted_image_digest, rhc_client_id,
    workloads, system_update_method, workspace_id, workspace_name
FROM inventory.hosts_table;
"""


class Command(BaseCommand):
    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            cursor.execute(cyndi_query)
