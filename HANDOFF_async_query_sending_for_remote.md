# Handoff: PR #74765 — fix possible UAF in distributed queries (async_query_sending_for_remote)

Scratch handoff doc for continuing on another machine. **Delete this file/commit before pushing the PR.**

> ⚠️ **STATE WARNING (read first).** On `async_query_sending_for_remote-rebase` the
> "Use the multi-threaded path" commit was amended then `git reset HEAD^`-ed away
> (see reflog). So the fix branch's `04404` test is currently the **BROKEN
> `max_threads=1`, single-shard** version that does NOT exercise the leak (it takes
> the single-threaded `cancel()` path). The CORRECT multi-threaded/multi-shard test
> is preserved on the `failpoint-rqe-read-uaf-repro` branch
> (commit `257378ac96a`). First action on the other machine: re-apply it, e.g.
> `git checkout failpoint-rqe-read-uaf-repro -- tests/queries/0_stateless/04404_remote_query_executor_async_read_uaf.sql`
> then commit. See "The regression test" section for why.

- Upstream PR: https://github.com/ClickHouse/ClickHouse/pull/74765 (azat, OPEN, stale since Jan 2025)
- Issue: https://github.com/ClickHouse/ClickHouse/issues/65942 ("Possible crash with async sockets, likely due to `async_query_sending_for_remote`")
- Original (older) PR this resubmits: https://github.com/ClickHouse/ClickHouse/pull/65984

## Branches (LOCAL only — not pushed yet)

1. `async_query_sending_for_remote-rebase` — **the fix**, rebased onto master + adaptations + regression test.
   - Based on local master `baadbda88f0` (rebased the 5 original PR commits; resolved conflicts).
   - Commits on top of master (HEAD = `0e0c9935cf2`):
     - `f1a5ecaf97c` Cleaner code for asynchronous socket for Distributed queries (conflicts resolved)
     - `ac20e63efc5` Use default logger in RemoteQueryExecutor
     - `4bc6e70b26f` Fix query cancellation in case of exception from PipelineExecutor itself
     - `726c56db696` Call cancel if query has finished with exception in PullingAsyncPipelineExecutor
     - `6d68c23df47` Some clarifications about cancellation in PullingAsyncPipelineExecutor dtor
     - `d5531e968d7` Handle cancel-before-send in read()/readAsync() instead of throwing  ← **new, mine**
     - `242b2c5fd75` Add regression test for async read context teardown (OLD 04403 sql test — later deleted)
     - `1c3bbc03e8d` Clarify why is_finished is left unset on exception (PullingAsyncPipelineExecutor)  ← **new, mine**
     - `710383d7aad` Add failpoint regression test for read context use-after-free (drops 04403, adds failpoint+04404)  ← **new, mine**
     - `0e0c9935cf2` Force the remote path in the read-context UAF test (prefer_localhost_replica=0)  ← **new, mine; HEAD**
     - (the "Use the multi-threaded path" commit was reset away — see STATE WARNING; `04404` here is still `max_threads=1`)

2. `failpoint-rqe-read-uaf-repro` — **repro only** (failpoint + test, NO fix), on top of master. For demonstrating the crash under ASan. Not for merging.
   - `6fcf67…` Failpoint + test to reproduce read context use-after-free (no fix)
   - `257378…` Use the multi-threaded path in the read-context UAF test

## The bug

A `RemoteQueryExecutor` read is driven through a fiber (`RemoteQueryExecutorReadContext`,
`async_socket_for_remote`). If that fiber is left **uncancelled** when the worker
thread that ran it is destroyed, the executor destructor cancels it later on an
unrelated thread; unwinding the fiber then touches thread-local state
(`current_thread`/`ThreadStatus`) of the gone worker thread → use-after-free.
Rare in production, only seen under sanitizers / specific timing.

## The fix (3 parts) + supporting changes

1. `PipelineExecutor::spawnThreads` worker-exception catch: `finish()` → **`cancel()`**.
   This is THE key change — on the multi-threaded path, a worker exception must cancel
   processors (and thus their read contexts) on the worker thread, not just stop scheduling.
2. `PullingAsyncPipelineExecutor::threadFunction`: on exception do **not** set `is_finished`.
   `cancel()` is a no-op once `is_finished` is set, so leaving it unset lets the consumer's
   `cancel()` reach `executor->cancel()`.
3. `~RemoteQueryExecutor`: instead of cancelling `read_context` in the dtor (the old, unsafe
   behavior still on master), **assert** it is already cancelled/finished, else `LOG_FATAL`+`abort()`
   (guarded by `#if defined(OS_LINUX)`). This is the deterministic, sanitizer-independent detector:
   turns the silent UAF into a loud abort.
   - `setFinished()`/`isFinished()` added to `AsyncTaskExecutor` (used by `sendQueryUnlocked` for the
     replica-unavailable path, where the context never runs).
   - Many `read_context->cancel()` calls added on the termination paths (EndOfStream, Exception,
     unknown packet, unavailable shard, was_cancelled).
4. `read()`/`readAsync()` now **throw `LOGICAL_ERROR "Query had not been sent"`** if `!sent_query`
   (implicit `sendQuery()` removed). Callers must send first; `getStructureOfRemoteTable` updated.
   - **My adaptation (`d5531e…`)**: check `was_cancelled` BEFORE that throw, otherwise master's
     `remote_query_executor_cancel_before_send` failpoint / test `04151` regresses (cancel-before-send
     leaves `sent_query=false` legitimately → must return empty, not throw).

## Rebase conflict resolutions (vs current master)

- `read()`: master kept implicit `sendQuery()` + a `connections`-null guard and switched to
  `LockAndBlocker`. Took the PR's "throw if not sent" behavior but kept `LockAndBlocker`; then moved
  the throw to AFTER the `was_cancelled` check (see adaptation above).
- `readAsync()`: combined master's `LockAndBlocker` with the PR's added `read_context->cancel()`.
- `getStructureOfRemoteTable.cpp`: master changed the loop to `for (... readBlock() ...)` and
  **deleted** `getExtendedObjectsOfRemoteTables`; kept master's deletion, added `executor.sendQuery()`
  before the remaining loop.

## The regression test — IMPORTANT learnings

`tests/queries/0_stateless/04404_remote_query_executor_async_read_uaf.sql`
- Failpoint `remote_query_executor_inject_exception_in_read` (`ONCE`, registered in `FailPoint.cpp`)
  throws `FAULT_INJECTED` from `readAsync()` right after `read_context->resume()` (fiber is alive).
- Test query MUST use the **multi-threaded path** and **multiple shards**:
  `SELECT * FROM remote('127.0.0.{1,2,3,4}', numbers(20000000))
   SETTINGS async_socket_for_remote=1, prefer_localhost_replica=0, max_threads=4`.
  Reasons (verified):
  - `prefer_localhost_replica=1` (default) reads a `127.0.0.1` replica **locally** → no
    `RemoteQueryExecutor`, no read context, failpoint never hit. Must set `=0`.
    (saved to memory: reference_force_remote_path_in_tests)
  - `max_threads=1` runs single-threaded; `PipelineExecutor::executeImpl`'s catch calls `cancel()`
    → read context cancelled on the worker thread → **no leak** (failpoint fires but nothing leaks).
    The leak is ONLY on the `spawnThreads` path (`max_threads>1`), whose catch calls `finish()`.
  - Need several shards so sibling read contexts are still active when one source throws.

### What is verified vs NOT

- VERIFIED on a local **RelWithDebInfo (no sanitizer)** build:
  - `04151` and `04404` PASS on the fix branch.
  - On the repro branch, the failpoint fires reliably on the multi-threaded path (25/25 `FAULT_INJECTED`),
    server stays alive (no ASan → freed-TLS read doesn't fault).
- NOT verified: an actual crash. Needs an **ASan/TSan build**. On the repro branch with ASan, the
  multi-threaded test SHOULD crash (leaked fiber cancelled from dtor after its worker thread —
  owned by `PipelineExecutor`'s `std::unique_ptr<ThreadPool> pool` — is destroyed).

## NEXT STEPS (on the other machine)

1. Build `failpoint-rqe-read-uaf-repro` **with ASan** and run
   `tests/clickhouse-test 04404_remote_query_executor_async_read_uaf` → confirm it crashes/aborts.
   (Optional cleaner demo: a branch with failpoint + ONLY the dtor `abort()` guard (no cancellation
   fix) aborts deterministically on ANY build — proves the leak without ASan.)
2. Build `async_query_sending_for_remote-rebase` (ASan) and confirm `04404` + `04151` PASS.
3. Push branches; run full CI. The original PR's CI had **Stress test failures** + author note
   "lots of other failures" (linked #75067) — the global `finish()`→`cancel()` change is broad
   (affects every query's exception path). Re-validate stress + parallel-replicas suites.
4. PR metadata: category is `Improvement`; this is a real crash/UAF fix → consider `Bug Fix`.
5. Open review concerns still standing (from the review):
   - Release-build `abort()` in the dtor: deliberate (abort > UAF) but every async-remote teardown
     path must cancel the context or it's a hard server crash. Document per-executor coverage or
     ASan-soak.
   - `restartQueryWithoutDuplicatedUUIDs` now forces sync read after a dedup retry (TODO in code);
     confirm the duplicated-part-uuids test still passes under `async_socket_for_remote`.

## Environment rules (do not violate)

- Do NOT run `ninja`/build — the user builds.
- Do NOT start/stop `clickhouse-server` — the user manages servers. (I violated this once; a stray
  `clickhouse server -C programs/server/config.xml …` + `tmp/server_repro.log` may exist — user cleans up.)
- Use `git grep`, `pgrep`, `tmp/` for scratch.
