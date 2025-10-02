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

from django_prometheus.db.backends.postgresql.base import DatabaseWrapper as BaseDatabaseWrapper
from django.db.backends.utils import CursorWrapper as BaseCursorWrapper

from feature_flags import (
    feature_flag_is_enabled,
    FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION
)

from advisor_logging import logger


class DatabaseWrapper(BaseDatabaseWrapper):
    """
    Use our own CursorWrapper to select which underlying hosts to use
    """
    def _cursor(self, name=None):
        cursor = super()._cursor(name)
        return CursorWrapper(cursor, self)


class CursorWrapper(BaseCursorWrapper):
    """
    In order to select the underlying hosts table on the fly, we have to
    rewrite the SQL. Not particularly nice, but it works.
    """
    def execute(self, sql, params=None):
        if feature_flag_is_enabled(FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION):
            sql = sql.replace('"inventory"."hosts"', '"hbi"."hosts_view"')
            logger.debug("Using Logical replication view")
        else:
            logger.debug("Using Cyndi replication view")
        return self.cursor.execute(sql, params)

    def executemany(self, sql, param_list):
        if feature_flag_is_enabled(FLAG_INVENTORY_HOSTS_DB_LOGICAL_REPLICATION):
            sql = sql.replace('"inventory"."hosts"', '"hbi"."hosts_view"')
            logger.debug("Using Logical replication view")
        else:
            logger.debug("Using Cyndi replication view")
        return self.cursor.executemany(sql, param_list)
