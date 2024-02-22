#!/usr/bin/env bash

CLICKHOUSE_CLIENT_OPT+=" --allow_experimental_analyzer=0 "

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CUR_DIR"/../shell_config.sh

function get_query() {
  alias_name=$1

  query="WITH a AS
    (
        SELECT sumIf(dummy, dummy IN (select dummy from system.one)) as $alias_name
        FROM cluster(test_cluster_two_shards, system.one)
    )
  SELECT
      sum(dummy),
      sumIf(dummy, dummy IN (a))
  FROM cluster(test_cluster_two_shards, system.one) settings distributed_product_mode='allow'"
  echo "$query"
}

# Getting counter for auto-generated subquery alias
# NOTE: no need to execute full query, find out current counter for subquery is enough
last_alias_counter=$($CLICKHOUSE_CLIENT -q "EXPLAIN SYNTAX $(get_query 'test_alias')" | grep -m1 -F _subquery | sed -E 's/^.*_subquery([0-9]+).*$/\1/')
# NOTE: query analysis done multiple times
for i in {1..10}; do
  new_query=$(get_query "_subquery$((last_alias_counter + i))")
  $CLICKHOUSE_CLIENT -q "$new_query" --format Null || exit 1
done
