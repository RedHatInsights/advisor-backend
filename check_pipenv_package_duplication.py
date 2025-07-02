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

import argparse
import json
from os import remove, rename

parser = argparse.ArgumentParser()
parser.add_argument(
    '--rewrite', default=False, action='store_true'
)
args = parser.parse_args()

with open("Pipfile.lock", 'r') as fh:
    pipenv = json.loads(fh.read())

assert 'default' in pipenv, "Pipfile.lock expected to have default section"
assert 'develop' in pipenv, "Pipfile.lock expected to have develop section"

# This checks that no package found in the 'develop' section of the
# Pipfile.lock file also appears in the 'default' section.  The --dev
# packages installed are always (AFAIK) assumed to be installed on top of the
# default packages.  We got bitten at the end of 2024 by having the Django
# package in both, and being different versions.

warning = False
for package_name, package_details in pipenv['default'].items():
    if package_name in pipenv['develop']:
        print(f"Warning: '{package_name}' in default and in develop")
        if args.rewrite:
            del(pipenv['develop'][package_name])
        warning = True
        continue

if warning and args.rewrite:
    rename('Pipfile.lock', 'Pipfile.lock.old')
    with open('Pipfile.lock', 'w') as ofh:
        json.dump(pipenv, ofh, indent=4)

exit(code=1 if warning else 0)
