#!/usr/bin/env bash

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
export CLICKHOUSE_DATABASE=default
. "$CUR_DIR"/../shell_config.sh

server_config="$CUR_DIR/$(basename "${BASH_SOURCE[0]}" .sh).config.xml"
server_log="$CUR_DIR/$(basename "${BASH_SOURCE[0]}" .sh).server.log"
server_pid=
server_port=
server_path="$(mktemp -d clickhouse.XXXXXX)"

function client() { $CLICKHOUSE_CLIENT --host 127.1 --port "$server_port" "$@"; }

function cleanup()
{
    kill -9 $server_pid

    echo "Test failed. Server log:"
    cat "$server_log"
    rm -rf "$server_log" "$server_path"

    exit 1
}

# wait until server will start to listen (max 30 seconds)
function server_discover_listen_port()
{
    server_port=
    i=0 retries=300
    while [[ -z $server_port ]] && [[ $i -lt $retries ]]; do
        server_port=$(lsof -n -a -P -i tcp -s tcp:LISTEN -p $server_pid 2>/dev/null | awk -F'[ :]' '/LISTEN/ { print $(NF-1) }')
        ((++i))
        sleep 0.1
    done
    if [[ -z $server_port ]]; then
        echo "Cannot wait for LISTEN socket" >&2
        exit 1
    fi
}

# wait for the server to start accepting tcp connections (max 30 seconds)
function server_wait_accept()
{
    i=0 retries=300
    while ! client --format Null -q 'select 1' 2>/dev/null && [[ $i -lt $retries ]]; do
        sleep 0.1
    done
    if ! client --format Null -q 'select 1'; then
        echo "Cannot wait until server will start accepting connections on <tcp_port>" >&2
        exit 1
    fi
}

function server_start()
{
    local server_opts=(
        "--config-file=$server_config"
        "--"
        "--path=$server_path"
        # to avoid multiple listen sockets (complexity for port discovering)
        "--listen_host=127.1"
        # we will discover the real port later.
        "--tcp_port=0"
        "--shutdown_wait_unfinished=0"
    )
    CLICKHOUSE_WATCHDOG_ENABLE=0 $CLICKHOUSE_SERVER_BINARY "${server_opts[@]}" >& "$server_log" &
    server_pid=$!

    trap cleanup EXIT

    server_discover_listen_port
    server_wait_accept
}

function client_run()
{
    client -nm -q "
    CREATE TABLE data_01830 (
        key UInt64 CODEC(NONE),
        value String CODEC(NONE)
    )
    Engine=MergeTree()
    ORDER BY key
    SETTINGS min_bytes_for_wide_part=0;

    SYSTEM STOP MERGES data_01830;

    INSERT INTO data_01830 SELECT number, toString(number) FROM numbers(1e6);
    "

    # duplicate parts (using hardlinks)
    for i in {1..5}; do
        client -q "ALTER TABLE data_01830 ATTACH PARTITION tuple() FROM data_01830"
    done

    # expand hardlinks
    client -nm -q "
    SYSTEM START MERGES data_01830;
    OPTIMIZE TABLE data_01830 FINAL;
    "

    client -q "SELECT ignore(*) FROM data_01830" --format Null --min_bytes_to_use_mmap_io=0

    # since mmap() does not accounted in the memory tracker
    # once memory tracker will be synced with RSS and reach max_server_memory_usage
    # any subsequent allocation will fail, so this query will eventually fail.
    if client -q "SELECT ignore(*) FROM data_01830" --format Null --min_bytes_to_use_mmap_io=1 2>/dev/null; then
        echo "SELECT with min_bytes_to_use_mmap_io==0 should fail" >&2
        exit 1
    fi

    return 0
}

function main()
{
    server_start

    client_run || exit 1

    trap '' EXIT
    kill -9 $server_pid
    rm -f "$server_log"
}
main "$@"
