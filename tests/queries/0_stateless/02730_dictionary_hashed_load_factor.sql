DROP TABLE IF EXISTS dict_data;
DROP DICTIONARY IF EXISTS dict_sharded;

CREATE TABLE dict_data (key UInt64, value UInt16) engine=Memory() AS SELECT number, number%65535 FROM numbers(1e6);
CREATE DICTIONARY dict_sharded (key UInt64, value UInt16) PRIMARY KEY key SOURCE(CLICKHOUSE(TABLE 'dict_data')) LIFETIME(MIN 0 MAX 0) LAYOUT(HASHED(SHARDS 32));

SELECT load_factor < 1 FROM system.dictionaries WHERE database = currentDatabase() AND name = 'dict_sharded';

DROP DICTIONARY dict_sharded;
DROP TABLE dict_data;
