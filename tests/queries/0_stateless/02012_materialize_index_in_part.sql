-- TODO: cover ReplicatedMergeTree

drop table if exists data;
create table data (key Int, value Int) engine=MergeTree() order by key partition by key settings index_granularity=1;
-- system stop merges data;
insert into data values (1, 1)(2, 2);
insert into data values (1, 1)(2, 2);
select * from data where value = 2 settings max_rows_to_read=1; -- { serverError TOO_MANY_ROWS }
alter table data add index value_idx value type minmax granularity 1;
select * from data where value = 2 settings max_rows_to_read=1; -- { serverError TOO_MANY_ROWS }

set mutations_sync=2;
alter table data materialize index value_idx in part id '2_2_2_0'; -- { clientError BAD_ARGUMENTS }
alter table data materialize index value_idx in part '2_2_2_0';
alter table data materialize index value_idx in part '2_4_4_0';
select * from data where value = 2 settings max_rows_to_read=1;
