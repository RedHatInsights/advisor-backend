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

set -e

echo "Dumping pre-data"
pg_dump --clean --section="pre-data" > pre_data.sql

echo "Dumping data using compressed format"
pg_dump --data-only --exclude-table-data="api_report" --exclude-table-data="api_historicreport" -Fc > data.dump &
pid=$! # Get PID of background command
while kill -0 $pid; do  # Signal 0 just tests whether the process exists
    echo -n "."
    sleep 0.5
done

echo "Dumping post-data"
pg_dump --section="post-data" > post_data.sql

echo "Splitting data file into chunks"
infile=data.dump
outprefix=data.dump.split
filesize=$( stat -c %s $infile )
segsize=500
segments=$(( $filesize / ($segsize*1024*1024) ))
for segment in $( seq $segments -1 0 ); do
    suffix=$( printf %02d $segment )
    dd if=$infile of=${outprefix}${suffix} bs=1M skip=$(( $segsize*$segment )) count=$segsize
    truncate $infile -s $(( $segsize*$segment ))M
done

echo "Done"
