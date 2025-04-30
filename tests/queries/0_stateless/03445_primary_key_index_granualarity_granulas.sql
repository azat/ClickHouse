-- Tags: no-random-settings, no-random-merge-tree-settings

drop table if exists pk_ratio;
create table pk_ratio (key Int, value String) engine=MergeTree() order by key settings
    primary_key_index_granualarity_granulas=100,
    index_granularity=8192, use_const_adaptive_granularity=true,
    -- FIXME: the following is not supported:
    -- adapative granualrity
    -- compression in memory
    -- compression on disk
    index_granularity_bytes=0,
    enable_index_granularity_compression=0,
    compress_marks=0,
    min_bytes_for_wide_part=0,
    max_suspicious_broken_parts=0, max_suspicious_broken_parts_bytes=0;
insert into pk_ratio select number, number*100 from numbers(1e6);

-- FIXME: for now the index will be persistent after INSERT, need to DETACH/ATTACH to workaround this
detach table pk_ratio;
attach table pk_ratio;

-- { echoOn }
select sum(primary_key_bytes_in_memory), count() from system.parts where database = currentDatabase() and table = 'pk_ratio' and active;

select * from pk_ratio where key = 1;
select * from pk_ratio where key = 1000;
select * from pk_ratio where key = 8192;
select sum(primary_key_bytes_in_memory) from system.parts where database = currentDatabase() and table = 'pk_ratio' and active;

select * from pk_ratio where key = 10000;
select * from pk_ratio where key = 81920;
select sum(primary_key_bytes_in_memory) from system.parts where database = currentDatabase() and table = 'pk_ratio' and active;

select * from pk_ratio where key = 100000;
select * from pk_ratio where key = 819200;
select sum(primary_key_bytes_in_memory) from system.parts where database = currentDatabase() and table = 'pk_ratio' and active;
