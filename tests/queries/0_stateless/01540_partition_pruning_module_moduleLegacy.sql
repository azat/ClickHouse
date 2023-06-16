drop table if exists data;

create table data (key String) engine=MergeTree() order by tuple() partition by cityHash64(key) % 20;
insert into data select 'foo' || number::String from numbers(100);
select _partition_id, min(key), max(key), count() from data group by _partition_id order by _partition_id::UInt64;

select * from (explain indexes=1 select * from data where key = 'foo60') where explain like '%Parts%' or explain like '%Partition%' or explain like '%MinMax%' format LineAsString;
select * from (explain indexes=1 select * from data where key in ('foo60')) where explain like '%Parts%' or explain like '%Partition%' or explain like '%MinMax%' format LineAsString;
select * from (explain indexes=1 select * from data where key in ('foo60', 'foo20')) where explain like '%Parts%' or explain like '%Partition%' or explain like '%MinMax%' format LineAsString;
