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

# This script is heavily based on
# https://github.com/chambridge/replication_subscriber/blob/main/replication_subscriber/

from django.core.management.base import BaseCommand
from django.db import connection
from django.conf import settings

import psycopg2
import logging
import os
import sys
from time import sleep

logger = logging.getLogger(__name__)

INVENTORY_SCHEMA = "hbi"
HOSTS_TABLE_NAME = "hosts"
SYSTEM_PROFILE_STATIC_TABLE_NAME = "system_profiles_static"
SYSTEM_PROFILE_DYNAMIC_TABLE_NAME = "system_profiles_dynamic"
EXPECTED_TABLE_COUNT_IN_PUBLICATION = 3

# The HBI DB config files are created from a secret during the application
# deployment, and they are used only for two purposes:
# 1. To create the subscription to the HBI database.
# 2. To verify publication readiness on ephemeral environments.
HBI_CONFIG_PATH = "/etc/db/hbi/"
HBI_FILENAME_OF_KEY = {
    'host': 'db_host', 'port': 'db_port', 'dbname': 'db_name', 'user': 'db_user',
    'password': 'db_password'
}

SSL_CERT_FILE = "/etc/db/rdsclientca/rds_cacert"


def _read_config_files() -> dict:
    """Read multiple config files and return their contents."""
    path_for_key = {
        key: os.path.join(HBI_CONFIG_PATH, file_name)
        for key, file_name in HBI_FILENAME_OF_KEY.items()
    }

    if missing_files := [p for p in path_for_key.values() if not os.path.isfile(p)]:
        raise FileNotFoundError(
            f"Required config files are missing: {missing_files}"
        )

    config = {}
    for key, file_path in path_for_key.items():
        with open(file_path) as file:
            config[key] = file.read().strip()

    return config


def _db_exists(sql: str) -> int:
    logger.debug(f"exists sql: {sql}")
    with connection.cursor() as cursor:
        cursor.execute(sql)
        rows = cursor.fetchall()
        return len(rows)


def _table_exists(schema_name: str, table_name: str) -> bool:
    query = (
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = %s AND table_name = %s"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [schema_name, table_name])
        return cursor.fetchone() is not None


def _execute_sql_batch(statements, success_log_message=None) -> None:
    for statement in statements:
        with connection.cursor() as cursor:
            cursor.execute(statement)
    if success_log_message:
        logger.info(success_log_message)


def _create_partitioned_table_if_missing(
    schema_name: str, table_name: str, columns_sql: str,
    partition_key: str = "org_id"
) -> None:
    if _table_exists(schema_name, table_name):
        logger.info(f"{schema_name}.{table_name} already exists.")
        return

    logger.info(f"{schema_name}.{table_name} not found.")
    create_table_sql = f"""
        CREATE TABLE {schema_name}.{table_name} (
            {columns_sql}
        )
        PARTITION BY HASH ({partition_key});
    """
    with connection.cursor() as cursor:
        cursor.execute(create_table_sql)
        logger.info(f"{schema_name}.{table_name} created.")

    partition_statements = []
    num_partitions = settings.HBI_TABLES_NUM_PARTITIONS
    for i in range(num_partitions):
        partition_statements.append(
            f"""
            CREATE TABLE {schema_name}.{table_name}_p{i}
                PARTITION OF {schema_name}.{table_name}
                FOR VALUES WITH (MODULUS {num_partitions}, REMAINDER {i});
            """
        )
    _execute_sql_batch(
        partition_statements, f"{schema_name}.{table_name} partitions created."
    )


def check_or_create_schema():
    check_schema = (
        "SELECT schema_name FROM information_schema.schemata "
        f"WHERE schema_name = '{INVENTORY_SCHEMA}'"
    )
    if not _db_exists(check_schema):
        logger.info(f"{INVENTORY_SCHEMA} schema not found.")
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {INVENTORY_SCHEMA}")
            logger.info(f"{INVENTORY_SCHEMA} schema created.")


def check_or_create_hosts_table():
    hosts_columns_sql = """
            org_id varchar(36) NOT NULL,
            id uuid NOT NULL,
            account varchar(10) NULL,
            display_name varchar(200) NULL,
            created_on timestamptz NULL,
            modified_on timestamptz NULL,
            tags_alt jsonb NULL,
            "groups" jsonb NOT NULL,
            last_check_in timestamptz NULL,
            stale_timestamp timestamptz NOT NULL,
            deletion_timestamp timestamptz NULL,
            stale_warning_timestamp timestamptz NULL,
            reporter varchar(255) NOT NULL,
            per_reporter_staleness jsonb DEFAULT '{}'::jsonb NOT NULL,
            insights_id uuid NOT NULL,
            CONSTRAINT hosts_pkey PRIMARY KEY (org_id, id)
    """
    _create_partitioned_table_if_missing(
        INVENTORY_SCHEMA, HOSTS_TABLE_NAME, hosts_columns_sql,
        partition_key="org_id"
    )


def check_or_create_hosts_table_indexes():
    tbl = f"{INVENTORY_SCHEMA}.{HOSTS_TABLE_NAME}"
    db_indexes = [
        f"CREATE INDEX IF NOT EXISTS hosts_account_index ON {tbl} (account)",
        f"CREATE INDEX IF NOT EXISTS hosts_display_name_index ON {tbl} (display_name)",
        f"CREATE INDEX IF NOT EXISTS hosts_tags_alt_index ON {tbl} "
        "USING GIN (tags_alt JSONB_PATH_OPS)",
        f"CREATE INDEX IF NOT EXISTS hosts_stale_timestamp_index ON {tbl} "
        "(stale_timestamp)",
        f"CREATE INDEX IF NOT EXISTS hosts_reporter_index ON {tbl} (reporter)",
        "CREATE INDEX IF NOT EXISTS hosts_per_reporter_staleness_index "
        f"ON {tbl} USING GIN (per_reporter_staleness JSONB_PATH_OPS)",
        f"CREATE INDEX IF NOT EXISTS hosts_groups_index ON {tbl} "
        "USING GIN (groups JSONB_PATH_OPS)",
        f"CREATE INDEX IF NOT EXISTS hosts_insights_id_index ON {tbl} "
        "(insights_id)",
        f"CREATE INDEX IF NOT EXISTS hosts_replica_identity_index ON {tbl} "
        "(org_id, id, insights_id)",
    ]
    _execute_sql_batch(db_indexes, f"{tbl} indexes created.")


def check_or_create_system_profile_tables():
    hosts_tbl = f"{INVENTORY_SCHEMA}.{HOSTS_TABLE_NAME}"
    static_cols = f"""
            org_id varchar(36) NOT NULL,
            host_id uuid NOT NULL,
            insights_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
            arch varchar(50) NULL,
            bootc_status jsonb NULL,
            dnf_modules _jsonb NULL,
            host_type varchar(12) NULL,
            image_builder jsonb NULL,
            operating_system jsonb NULL,
            owner_id uuid NULL,
            releasever varchar(100) NULL,
            rhc_client_id uuid NULL,
            rhsm jsonb NULL,
            satellite_managed bool DEFAULT false NULL,
            system_update_method varchar(10) NULL,
            yum_repos _jsonb NULL,
            CONSTRAINT pk_system_profiles_static PRIMARY KEY (org_id, host_id),
            CONSTRAINT fk_static_hosts FOREIGN KEY (org_id, host_id)
                REFERENCES {hosts_tbl} (org_id, id) ON DELETE CASCADE
    """
    _create_partitioned_table_if_missing(
        INVENTORY_SCHEMA, SYSTEM_PROFILE_STATIC_TABLE_NAME, static_cols
    )

    dynamic_cols = f"""
            org_id varchar(36) NOT NULL,
            host_id uuid NOT NULL,
            insights_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
            installed_packages _varchar NULL,
            installed_products jsonb NULL,
            workloads jsonb NULL,
            CONSTRAINT pk_system_profiles_dynamic PRIMARY KEY (org_id, host_id),
            CONSTRAINT fk_dynamic_hosts FOREIGN KEY (org_id, host_id)
                REFERENCES {hosts_tbl} (org_id, id) ON DELETE CASCADE
    """
    _create_partitioned_table_if_missing(
        INVENTORY_SCHEMA, SYSTEM_PROFILE_DYNAMIC_TABLE_NAME, dynamic_cols
    )


def check_or_create_system_profile_tables_indexes():
    static_tbl = f"{INVENTORY_SCHEMA}.{SYSTEM_PROFILE_STATIC_TABLE_NAME}"
    static_indexes = [
        "CREATE INDEX IF NOT EXISTS system_profiles_static_bootc_status_index "
        f"ON {static_tbl} USING btree (bootc_status)",
        "CREATE INDEX IF NOT EXISTS system_profiles_static_host_id_index "
        f"ON {static_tbl} USING btree (host_id)",
        "CREATE INDEX IF NOT EXISTS system_profiles_static_host_type_index "
        f"ON {static_tbl} USING btree (host_type)",
        (
            "CREATE INDEX IF NOT EXISTS "
            "system_profiles_static_operating_system_multi_index "
            f"ON {static_tbl} USING btree "
            "(((operating_system ->> 'name'::text)), "
            "(((operating_system ->> 'major'::text))::integer), "
            "(((operating_system ->> 'minor'::text))::integer), org_id) "
            "WHERE (operating_system IS NOT NULL)"
        ),
        "CREATE INDEX IF NOT EXISTS system_profiles_static_rhc_client_id_index "
        f"ON {static_tbl} USING btree (rhc_client_id)",
        "CREATE INDEX IF NOT EXISTS system_profiles_static_replica_identity_index "
        f"ON {static_tbl} (org_id, host_id, insights_id)",
    ]
    _execute_sql_batch(static_indexes, f"{static_tbl} indexes created.")

    dynamic_tbl = f"{INVENTORY_SCHEMA}.{SYSTEM_PROFILE_DYNAMIC_TABLE_NAME}"
    dynamic_indexes = [
        "CREATE INDEX IF NOT EXISTS system_profiles_dynamic_workloads_gin_index "
        f"ON {dynamic_tbl} USING gin (workloads)",
        "CREATE INDEX IF NOT EXISTS system_profiles_dynamic_replica_identity_index "
        f"ON {dynamic_tbl} (org_id, host_id, insights_id)",
    ]
    _execute_sql_batch(dynamic_indexes, f"{dynamic_tbl} indexes created.")


def check_or_create_view():
    hosts = f"{INVENTORY_SCHEMA}.{HOSTS_TABLE_NAME}"
    static = f"{INVENTORY_SCHEMA}.{SYSTEM_PROFILE_STATIC_TABLE_NAME}"
    dynamic = f"{INVENTORY_SCHEMA}.{SYSTEM_PROFILE_DYNAMIC_TABLE_NAME}"
    view_template = f"""
        CREATE OR REPLACE VIEW {INVENTORY_SCHEMA}.hosts_view AS
        SELECT
            h.org_id,
            h.id,
            h.account,
            h.display_name,
            h.created_on AS created,
            h.modified_on AS updated,
            h.tags_alt AS tags,
            h."groups" AS groups,
            h.stale_timestamp,
            h.deletion_timestamp AS culled_timestamp,
            h.stale_warning_timestamp,
            h.per_reporter_staleness,
            h.insights_id,
            -- Conditionally build the system_profile object, omitting NULL values.
            (
                (CASE WHEN s.bootc_status IS NOT NULL
                    THEN jsonb_build_object('bootc_status', s.bootc_status)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN s.host_type IS NOT NULL
                    THEN jsonb_build_object('host_type', s.host_type)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN s.operating_system IS NOT NULL
                    THEN jsonb_build_object('operating_system', s.operating_system)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN s.owner_id IS NOT NULL
                    THEN jsonb_build_object('owner_id', s.owner_id)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN s.rhc_client_id IS NOT NULL
                    THEN jsonb_build_object('rhc_client_id', s.rhc_client_id)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN s.system_update_method IS NOT NULL
                    THEN jsonb_build_object('system_update_method', s.system_update_method)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN s.rhsm IS NOT NULL
                    THEN jsonb_build_object('rhsm', s.rhsm)
                    ELSE '{{}}'::jsonb END) ||
                (CASE WHEN d.workloads IS NOT NULL
                    THEN jsonb_build_object('workloads', d.workloads)
                    ELSE '{{}}'::jsonb END)
            ) AS system_profile
        FROM {hosts} h
        LEFT JOIN {static} s ON s.org_id = h.org_id AND s.host_id = h.id
        LEFT JOIN {dynamic} d ON d.org_id = h.org_id AND d.host_id = h.id;
    """

    with connection.cursor() as cursor:
        cursor.execute(view_template)


def check_or_create_subscription():
    sub_name = settings.HBI_SUBSCRIPTION

    check_subscription = f"SELECT subname FROM pg_subscription WHERE subname = '{sub_name}'"
    if _db_exists(check_subscription):
        logger.info(f"{sub_name} found.")
        return
    logger.info(f"{sub_name} not found.")

    try:
        hbi_config = _read_config_files()
    except FileNotFoundError as e:
        logger.error(f"HBI configuration error: {e}")
        return

    hbi_config['sslmode'] = settings.HBI_SSL_MODE
    if settings.HBI_SSL_MODE and os.path.isfile(SSL_CERT_FILE):
        hbi_config['sslcert'] = SSL_CERT_FILE

    hbi_connection = _create_connection_string(hbi_config)

    subscription_create = (
        f"CREATE SUBSCRIPTION {sub_name} "
        f"CONNECTION {hbi_connection} "
        f"PUBLICATION {settings.HBI_PUBLICATION};"
    )

    with connection.cursor() as cursor:
        cursor.execute(subscription_create)
        logger.info(f"{sub_name} created.")


def drop_subscription():
    sub_to_drop = settings.HBI_DROP_SUBSCRIPTION
    if not sub_to_drop:
        return

    subscription_drop = f"DROP SUBSCRIPTION IF EXISTS {sub_to_drop}"
    with connection.cursor() as cursor:
        cursor.execute(subscription_drop)
        logger.info(f"{sub_to_drop} was dropped.")


def drop_tables():
    if not settings.HBI_DROP_TABLES:
        return

    tables_to_drop = [
        HOSTS_TABLE_NAME,
        SYSTEM_PROFILE_STATIC_TABLE_NAME,
        SYSTEM_PROFILE_DYNAMIC_TABLE_NAME
    ]

    for table_name in tables_to_drop:
        drop_sql = f"DROP TABLE IF EXISTS {INVENTORY_SCHEMA}.{table_name} CASCADE"
        with connection.cursor() as cursor:
            cursor.execute(drop_sql)
            logger.info(f"{INVENTORY_SCHEMA}.{table_name} was dropped.")


def _check_hbi_publication_is_ready() -> bool:
    """
    Checks if the HBI publication on the publisher is ready for subscription.

    This check verifies the publication exists, contains the expected number
    of tables, and all tables have a valid REPLICA IDENTITY. It polls with a
    timeout to handle race conditions in ephemeral environments.

    Note: A direct database connection (psycopg2) is used here instead of
    a Django-managed one. This approach avoids
    adding a temporary, external database configuration to the application's
    global state, as this connection is only used for this specific check
    on the HBI database.
    """
    if "env-ephemeral" not in settings.ENV_NAME:
        return True

    max_retries = 100
    retry_interval_seconds = 5

    try:
        hbi_config = _read_config_files()
    except FileNotFoundError as e:
        logger.error(
            f"Cannot check publication: HBI config files not found. Error: {e}"
        )
        return False

    readiness_query = """
        SELECT
            count(*)::int AS total_tables,
            count(*) FILTER (WHERE c.relreplident = 'n')::int AS unready_tables
        FROM
            pg_publication_tables pt
        JOIN
            pg_class c ON c.oid =
                (pt.schemaname || '.' || pt.tablename)::regclass
        WHERE
            pt.pubname = %s;
    """

    for attempt in range(max_retries):
        try:
            with psycopg2.connect(**hbi_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(readiness_query, [settings.HBI_PUBLICATION])
                    result = cursor.fetchone()

                    if result:
                        total, unready = result
                        logger.info(
                            f"Publication check {attempt + 1}/{max_retries}: "
                            f"Found {total} tables, {unready} not ready."
                        )

                        if (total >= EXPECTED_TABLE_COUNT_IN_PUBLICATION
                                and unready == 0):
                            logger.info("Publication is ready.")
                            return True

        except (psycopg2.OperationalError, psycopg2.Error) as e:
            logger.info(f"Connection/query failed: {e}. Retrying...")
        except Exception as e:
            logger.warning(
                f"Unexpected error checking pub: {e}. Retrying..."
            )

        logger.info(
            f"Publication not ready. Retrying in {retry_interval_seconds}s..."
        )
        sleep(retry_interval_seconds)

    logger.error(
        f"Publication '{settings.HBI_PUBLICATION}' did not become ready "
        f"after {max_retries} attempts."
    )
    return False


def _create_connection_string(params: dict) -> str:
    return "'" + ' '.join(
        f"{key}={val}"
        for key, val in params.items()
        if val
    ) + "'"


class Command(BaseCommand):
    help = 'Setup HBI database logical replication'

    def handle(self, *args, **options):
        if settings.ENVIRONMENT != 'dev':
            drop_subscription()
        drop_tables()
        check_or_create_schema()
        check_or_create_hosts_table()
        check_or_create_hosts_table_indexes()
        check_or_create_system_profile_tables()
        check_or_create_system_profile_tables_indexes()
        check_or_create_view()
        if settings.ENVIRONMENT != 'dev':
            if _check_hbi_publication_is_ready():
                check_or_create_subscription()
            else:
                logger.error(
                    "Aborting: Could not verify HBI publication readiness."
                )
                sys.exit(1)
