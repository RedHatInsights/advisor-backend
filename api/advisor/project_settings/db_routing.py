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

import os


class ReadOnlyReplicaRouter:
    def db_for_read(self, model, **hints):
        """
        All reads go to our read only replica.
        """
        return 'readonly' if os.environ.get('ADVISOR_DB_READONLY_HOST') else 'default'

    def db_for_write(self, model, **hints):
        """
        All writes go to our writable master.
        """
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow all relations between two objects in our database replicas -
        we don't otherwise have an opinion (None).
        """
        db_list = ('default', 'readonly')
        if obj1._state.db in db_list and obj2._state.db in db_list:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        All models are allowed to migrate in these databases; writes will
        still go to the writable master.
        """
        return None
