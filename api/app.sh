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

if [ "${USE_DJANGO_WEBSERVER,,}" == "true" ]; then
    # Run Advisor with Django's built-in webserver
    # CMD="python api/advisor/manage.py runserver --noreload 0.0.0.0:8000"
    CMD="pipenv run runapi --noreload 0.0.0.0:8000"
else
    # Guess the number of workers according to the number of cores
    function get_default_web_concurrency() {
      limit_vars=$($HOME/cgroup-limits)
      local $limit_vars
      if [ -z "${NUMBER_OF_CORES:-}" ]; then
        echo 1
        return
      fi

      local max=$((NUMBER_OF_CORES*2))
      # Require at least 43 MiB and additional 40 MiB for every worker
      local default=$(((${MEMORY_LIMIT_IN_BYTES:-MAX_MEMORY_LIMIT_IN_BYTES}/1024/1024 - 43) / 40))
      default=$((default > max ? max : default))
      default=$((default < 1 ? 1 : default))
      # According to http://docs.gunicorn.org/en/stable/design.html#how-many-workers,
      # 12 workers should be enough to handle hundreds or thousands requests per second
      # But Advisor can probably make do with less than that, say, 6 should be plenty
      default=$((default > 6 ? 6 : default))
      echo $default
    }

    export WEB_CONCURRENCY=${WEB_CONCURRENCY:-$(get_default_web_concurrency)}
    echo "Web concurrency is $WEB_CONCURRENCY"

    APP_HOME=${APP_HOME:-api/advisor}
    APP_MODULE=${APP_MODULE:-project_settings.wsgi}
    LOGGING_CONF=${LOGGING_CONF:-logging_conf.py}
    BIND_ADDR="0.0.0.0:${GUNICORN_PORT:-8000}"
    TIMEOUT=${GUNICORN_TIMEOUT:-120}

    export PYTHONPATH=${APP_HOME}
    export PROMETHEUS_MULTIPROC_DIR=${PROMETHEUS_MULTIPROC_DIR:-/metrics}
    # 2022-10-18 PJW - looks like the '--chdir' option takes place AFTER
    # it tries to load the configuration file.  Unfortunately, the config
    # tries to load other packages without an explicit path, and since we're
    # not in that directory the import fails.  So we 'cd' first, then the
    # --chdir option is no longer needed and the config imports work.
    cd ${APP_HOME}
    CMD="pipenv run gunicorn --preload --config ${LOGGING_CONF} --bind ${BIND_ADDR} --timeout ${TIMEOUT} ${APP_MODULE}"
fi

echo "Running ${CMD} ..."
exec ${CMD}
