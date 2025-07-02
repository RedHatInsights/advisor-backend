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

"""
This script can be run to pull configuration settings from an RDS DB
for creating a test postgres config that closely mimics prod
"""

import csv
import re
import sys
import yaml


special_char_regex = re.compile(r'[@_!#$%^&*()<>?/\|}{~:,\s]')
page_unit_regex = re.compile(r'^\d+kB$')

try:
    filename = sys.argv[1]
except IndexError:
    sys.stdout.write(f"usage: {sys.argv[0]} <csv file>\n")
    sys.exit(1)


# Config values we will override for a testing DB
forced_config = {
    'ssl': 'off',
    'listen_addresses': '*'
}

data = {}

with open(filename) as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = row['name']
        if key in forced_config:
            value = forced_config[key]
        else:
            value = row['setting']

        # Skip analyzing values if they are already set to the default
        if value == row['boot_val']:
            continue

        unit = row['unit']
        # If the unit is XkB (denoting a page unit), just remove the unit
        # otherwise we'll end up with a value that looks like: '08kB'
        if page_unit_regex.search(unit):
            unit = None

        # Check if the value is an int...
        if value.lstrip('-').isdigit():
            value = f"{int(value)}{unit}" if unit else int(value)
        else:
            # Check if the value is a float
            try:
                value = f"{float(value)}{unit}" if unit else float(value)
            except ValueError:
                # Value is not a float and not an int, must be a string
                if special_char_regex.search(str(value)) or not value:
                    # value has special chars, so quote it
                    value = f"\'{value}{unit}\'"
        data[key] = value


# Delete some config details which should not be changed
keys_to_delete = [
    'archive_command',
    'config_file',
    'data_directory',
    'hba_file',
    'ident_file',
    'krb_server_keyfile',
    'log_directory',
    'ssl_ca_file',
    'ssl_cert_file',
    'ssl_key_file',
    'stats_temp_directory',
    'unix_socket_directories',
    'unix_socket_group',
    'block_size',
    'data_checksums',
    'debug_assertions',
    'integer_datetimes',
    'lc_collate',
    'shared_preload_libraries',
    'log_file_mode',
    'unix_socket_permissions',
    'lc_ctype',
    'server_encoding'
]

# Also delete rds specific keys
for key in data:
    if key.startswith("rds."):
        keys_to_delete.append(key)

for key in set(keys_to_delete):
    if key in data:
        del data[key]

final_data = {"postgresql_server_conf": data}
sys.stdout.write(yaml.safe_dump(final_data, default_flow_style=False))
