#!/usr/bin/env bash

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CUR_DIR"/../shell_config.sh

function get_header()
{
    local stage=$1 && shift
    local query=$1 && shift

    echo "[$stage] $query"
    $CLICKHOUSE_CLIENT --stage "$stage" -q "$query"
}

for stage in with_mergeable_state with_mergeable_state_after_aggregation with_mergeable_state_after_aggregation_and_limit; do
    get_header $stage "SELECT k FROM (SELECT materialize('foo') AS k, -1 AS v) ORDER BY abs(v) AS _v ASC LIMIT 1 BY k FORMAT TSVWithNames"
    get_header $stage "SELECT k FROM (SELECT materialize('foo') AS k, -1 AS v) ORDER BY abs(v) AS _v ASC FORMAT TSVWithNames"
done

