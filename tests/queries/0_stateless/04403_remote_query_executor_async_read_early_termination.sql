-- Tags: shard
-- - shard: needs the test cluster to build a Distributed table

DROP TABLE IF EXISTS t_rqe_async_local SYNC;
DROP TABLE IF EXISTS t_rqe_async_dist SYNC;

CREATE TABLE t_rqe_async_local (a UInt64) ENGINE = MergeTree ORDER BY a;
INSERT INTO t_rqe_async_local SELECT number FROM numbers(10000000);

CREATE TABLE t_rqe_async_dist (a UInt64)
ENGINE = Distributed(test_cluster_two_shards, currentDatabase(), t_rqe_async_local);

-- prefer_localhost_replica = 0 forces a RemoteQueryExecutor for every shard.
-- async_socket_for_remote = 1 reads through a fiber (the read context). LIMIT
-- terminates the query while the shards are still streaming, so the read
-- context is active when the executor is torn down. It must be cancelled on the
-- worker thread before that thread is destroyed, otherwise the fiber accesses
-- thread-local state of an already-gone thread (use-after-free).
SELECT a FROM t_rqe_async_dist
SETTINGS prefer_localhost_replica = 0, async_socket_for_remote = 1, max_threads = 1
LIMIT 10
FORMAT Null;

-- Same teardown path, but triggered by an exception coming from the shards
-- while the read context is in progress.
SELECT throwIf(a >= 0) FROM t_rqe_async_dist
SETTINGS prefer_localhost_replica = 0, async_socket_for_remote = 1, max_threads = 1
FORMAT Null; -- { serverError FUNCTION_THROW_IF_VALUE_IS_NON_ZERO }

-- The server must still be alive (a crash would have killed it).
SELECT 'ok';

DROP TABLE t_rqe_async_local SYNC;
DROP TABLE t_rqe_async_dist SYNC;
