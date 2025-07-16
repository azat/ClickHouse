-- Tags: no-random-settings, no-random-merge-tree-settings
-- Disable randomization since this may change parts

drop table if exists test_10m;
create table test_10m (key Int, value Int) engine=MergeTree() order by ();
system stop merges test_10m;
insert into test_10m select number, number*100 from numbers(10e6);

set parallel_replicas_for_non_replicated_merge_tree=1, parallel_replicas_index_analysis=1, enable_parallel_replicas=1, cluster_for_parallel_replicas='';

-- { echo }
select * from test_10m order by value desc limit 1 settings enable_parallel_replicas=0;
select * from test_10m order by value desc limit 1 settings cluster_for_parallel_replicas='test_cluster_one_shard_two_replicas';
select * from test_10m order by value desc limit 1 settings cluster_for_parallel_replicas='parallel_replicas';

select groupArraySortedDistinct(10)(_part), sum(key), sum(value) from test_10m settings enable_parallel_replicas=0;
select groupArraySortedDistinct(10)(_part), sum(key), sum(value) from test_10m settings cluster_for_parallel_replicas='test_cluster_one_shard_two_replicas';
select groupArraySortedDistinct(10)(_part), sum(key), sum(value) from test_10m settings cluster_for_parallel_replicas='parallel_replicas';
