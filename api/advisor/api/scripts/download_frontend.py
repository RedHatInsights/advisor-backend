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

import shutil
from subprocess import call

# delete old stuff
try:
    shutil.rmtree('advisor/frontend/static')
    shutil.rmtree('advisor/frontend/platform')
except:
    pass


call(["git", "clone", "-b", "prod-stable", "git@github.com:RedHatInsights/insights-advisor-frontend-build.git", "advisor/frontend/platform/advisor"])
call(["git", "clone", "-b", "prod-stable", "git@github.com:RedHatInsights/insights-chrome-build.git", "advisor/frontend/static/chrome"])

# Needed because we have to get the ESI injected version of index.html
call(["wget", "-O", "advisor/frontend/platform/advisor/index.html", "https://access.redhat.com/insights/platform/advisor/"])
