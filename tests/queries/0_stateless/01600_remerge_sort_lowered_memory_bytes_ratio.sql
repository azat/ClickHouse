-- Check remerge_sort_lowered_memory_bytes_ratio setting

set max_memory_usage='5Gi';
-- enter remerge once limit*2 is reached
set max_bytes_before_remerge_sort='10Mi';
-- remerge works in terms of max_block_size
-- so for limit 400e3 and max_block_size=40001 it will be reached with 800020
-- and 800020 is too close to 800000 to not get 2x profit in memory usage after remerge.
set max_block_size=40001;

-- MergeSortingTransform: Memory usage is lowered from 1.91 GiB to 980.00 MiB (remerge limit was increased to 1600000)
select number k, repeat(toString(number), 101) v1, repeat(toString(number), 102) v2, repeat(toString(number), 103) v3 from numbers(toUInt64(10e6)) order by k limit 400e3 format Null;
