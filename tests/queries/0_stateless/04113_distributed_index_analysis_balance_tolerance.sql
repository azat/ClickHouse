-- Tags: long, no-parallel
-- Verify that `distributed_index_analysis_balance_tolerance` rebalances parts
-- away from their consistent-hash home when their sizes are unequal.

drop table if exists test_balance;

create table test_balance (key UInt32)
engine=MergeTree()
order by key
partition by key
settings
    distributed_index_analysis_min_parts_to_activate=0,
    distributed_index_analysis_min_indexes_bytes_to_activate=0,
    index_granularity = 1024;

system stop merges test_balance;

-- One huge part dominates the total marks; many tiny parts spread across replicas.
-- Under pure consistent hashing the replica that receives the huge part is overloaded,
-- while small parts on it are easy to move away to balance the load.
insert into test_balance select 0 from numbers(1000000) settings max_block_size=1000000;
insert into test_balance select number + 1 from numbers(50);

set allow_experimental_parallel_reading_from_replicas=0;
set parallel_replicas_for_non_replicated_merge_tree=1;
set parallel_replicas_index_analysis_only_on_coordinator=1;
set parallel_replicas_local_plan=1;
set distributed_index_analysis=1;
set max_parallel_replicas=10;
set cluster_for_parallel_replicas='parallel_replicas';
-- Ignore warnings about an intentionally unavailable replica in `parallel_replicas`.
set send_logs_level='error';

-- Sanity: same result regardless of tolerance.
select count() from test_balance settings distributed_index_analysis_balance_tolerance=-1;
select count() from test_balance settings distributed_index_analysis_balance_tolerance=0.5;
select count() from test_balance settings distributed_index_analysis_balance_tolerance=0;

system flush logs query_log;

select
    toFloat32OrNull(Settings['distributed_index_analysis_balance_tolerance']) as tolerance,
    ProfileEvents['DistributedIndexAnalysisRebalancedParts'] > 0 as rebalanced
from system.query_log
where
    current_database = currentDatabase()
    and event_date >= yesterday() and event_time >= now() - 600
    and type = 'QueryFinish'
    and query_kind = 'Select'
    and is_initial_query
    and has(Settings, 'distributed_index_analysis_balance_tolerance')
order by event_time_microseconds
format TSV;

drop table test_balance;
