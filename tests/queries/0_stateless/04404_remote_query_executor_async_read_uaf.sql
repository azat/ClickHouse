-- Tags: no-parallel
-- - no-parallel: uses a fail point (global server state)

SYSTEM ENABLE FAILPOINT remote_query_executor_inject_exception_in_read;

-- async_socket_for_remote = 1 reads the remote result through a fiber (the read
-- context). The fail point raises an exception while that fiber is active. The
-- read context then has to be cancelled on the worker thread that ran it,
-- before that thread is destroyed; otherwise cancelling it later (from the
-- executor destructor, on an unrelated thread) unwinds the fiber and touches
-- thread-local state of an already-gone thread (use-after-free, caught by
-- sanitizers). The server staying alive below is the regression signal.
-- prefer_localhost_replica = 0 forces the query through a RemoteQueryExecutor
-- (otherwise a 127.0.0.1 replica is read locally and no read context is used).
SELECT * FROM remote('127.0.0.1', numbers(1000000))
SETTINGS async_socket_for_remote = 1, prefer_localhost_replica = 0, max_threads = 1
FORMAT Null; -- { serverError FAULT_INJECTED }

SYSTEM DISABLE FAILPOINT remote_query_executor_inject_exception_in_read;

SELECT 'ok';
