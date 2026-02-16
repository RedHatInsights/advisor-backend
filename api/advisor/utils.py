#!/usr/bin/env python

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

from thread_storage import thread_storage_object


def clean_threading_cruft():
    """
    TODO: use thread pool executor initializer once on python 3.7
    We do this because there is cruft leftover with Python ThreadPoolExecutor
    and old Threading.local() thread storage objects/values
    """
    thread_storage_object.__dict__.clear()


def traverse_keys(d, keys, default=None):
    """
    Allows you to look up a 'path' of keys in nested dicts without knowing whether each key exists
    """
    key = keys.pop(0)
    item = d.get(key, default)
    if len(keys) == 0:
        return item
    if not item:
        return default
    return traverse_keys(item, keys, default)
