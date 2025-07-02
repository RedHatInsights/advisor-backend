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

import json
import os
import requests
import sys


def main():
    if 'HOOKS_REGISTRATION_URL' not in os.environ:
        sys.stderr.write("No registration URL provided, skipping.\n")
        sys.exit(0)

    headers = {'Content-Type': 'application/json'}
    report_levels = [
        {"id": 4, "title": "Critical"},
        {"id": 3, "title": "High"},
        {"id": 2, "title": "Medium"},
        {"id": 1, "title": "Low"}
    ]
    payload = {
        "application": {
            "name": "insights",
            "title": "Insights"
        },
        "event_types": [
            {"id": "new-report",
                "title": "New report identified",
                "levels": report_levels
             },
            {"id": "report-resolved",
                "title": "Report resolved",
                "levels": report_levels
             }
        ]
    }
    try:
        requests.post(os.environ['HOOKS_REGISTRATION_URL'], data=json.dumps(payload), headers=headers)
    except Exception as e:
        sys.stderr.write("Failed to register hooks, request failed with error\n{}".format(e))


if __name__ == '__main__':
    main()
