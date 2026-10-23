#!/usr/bin/env bash

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CUR_DIR"/../shell_config.sh

victim_db="victim_${CLICKHOUSE_DATABASE}"
attacker_db="attacker_${CLICKHOUSE_DATABASE}"
attacker="attacker_user_${CLICKHOUSE_DATABASE}"
# `system.completions.belongs` carries the bare table name, so this one has to be server-unique.
alias_table="sink_alias_${CLICKHOUSE_DATABASE}"
attacker_client="$CLICKHOUSE_CLIENT --user $attacker"

$CLICKHOUSE_CLIENT -m -q "
    DROP DATABASE IF EXISTS $victim_db;
    DROP DATABASE IF EXISTS $attacker_db;
    DROP USER IF EXISTS $attacker;

    CREATE DATABASE $victim_db;
    CREATE TABLE $victim_db.sink (id UInt64, PROJECTION p (SELECT id ORDER BY id))
    ENGINE = MergeTree ORDER BY id;
    INSERT INTO $victim_db.sink VALUES (1);
    INSERT INTO $victim_db.sink VALUES (2);

    CREATE DATABASE $attacker_db;
    CREATE USER $attacker IDENTIFIED WITH no_password;
    GRANT CREATE TABLE, SHOW COLUMNS, SYSTEM MERGES ON $attacker_db.* TO $attacker;
    GRANT TABLE ENGINE ON Alias TO $attacker;
    GRANT SELECT ON system.columns TO $attacker;
    GRANT SELECT ON system.completions TO $attacker;
"

$attacker_client -q "CREATE TABLE $attacker_db.$alias_table ENGINE = Alias('$victim_db', 'sink')"

echo '-- the target metadata is out of reach even where the caller forgot to check'
$attacker_client -q "SELECT * FROM mergeTreeProjection('$attacker_db', '$alias_table', 'p')" 2>&1 | grep -o -m1 'ACCESS_DENIED'

echo '-- and the metadata system tables stay empty instead of failing'
$attacker_client -m -q "
    SELECT count() FROM system.columns WHERE database = '$attacker_db' AND table = '$alias_table';
    SELECT count() FROM system.completions WHERE context = 'column' AND belongs = '$alias_table';
"

echo '-- stopping merges through the alias does not reach the target'
$attacker_client -q "SYSTEM STOP MERGES $attacker_db.$alias_table"
$attacker_client -q "SYSTEM STOP MERGES"
$CLICKHOUSE_CLIENT -m -q "
    OPTIMIZE TABLE $victim_db.sink FINAL;
    SELECT count() FROM system.parts WHERE database = '$victim_db' AND table = 'sink' AND active;
"

echo '-- a grant on the target brings the metadata back'
$CLICKHOUSE_CLIENT -q "GRANT SHOW COLUMNS ON $victim_db.sink TO $attacker"
$attacker_client -m -q "
    SELECT count() FROM system.columns WHERE database = '$attacker_db' AND table = '$alias_table';
    SELECT count() FROM system.completions WHERE context = 'column' AND belongs = '$alias_table';
"

$CLICKHOUSE_CLIENT -m -q "
    DROP DATABASE $victim_db;
    DROP DATABASE $attacker_db;
    DROP USER $attacker;
"
