#!/bin/bash

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

APP_HOME=${APP_HOME:-api/advisor}
APP_MODULE=${APP_MODULE:-project_settings.wsgi}
GUNICORN_CONF=${GUNICORN_CONF:-gunicorn_conf.py}
BIND_ADDR="0.0.0.0:${GUNICORN_PORT:-8000}"
TIMEOUT=${GUNICORN_TIMEOUT:-120}
LIMIT_REQUEST_FIELD_SIZE=${GUNICORN_LIMIT_REQUEST_FIELD_SIZE:-16384} # Use 16k to avoid 431 errors

export PYTHONPATH=${APP_HOME}
cd ${APP_HOME}
CMD="pipenv run gunicorn
  --preload
  --config ${GUNICORN_CONF}
  --bind ${BIND_ADDR}
  --timeout ${TIMEOUT}
  --limit-request-field_size ${LIMIT_REQUEST_FIELD_SIZE}
  ${APP_MODULE}"

echo "Running ${CMD} ..."
exec ${CMD}
