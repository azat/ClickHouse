-- https://github.com/ClickHouse/ClickHouse/issues/46424

DROP DICTIONARY IF EXISTS dict;
DROP TABLE IF EXISTS data;
DROP TABLE IF EXISTS dist;

CREATE TABLE data (key Int16, value String) engine=Memory;
INSERT INTO data VALUES (1, 'one'), (2, 'two');

CREATE TABLE dist AS data Engine=Distributed('test_cluster_two_shards_localhost', currentDatabase(), data);

CREATE DICTIONARY dict (key Int16, value String)
PRIMARY KEY key
SOURCE(ClickHouse(TABLE 'data'))
LAYOUT(FLAT())
LIFETIME(0);

-- { echoOn }
SELECT *, dictGet(currentDatabase() || '.dict', 'value', key) FROM dist ORDER BY key;
SELECT *, dictGet('dict', 'value', key) FROM dist ORDER BY key;
SELECT *, dictGet('dict', 'value', key) AS a FROM dist ORDER BY key;
SELECT DISTINCT dictGet('dict', 'value', key) AS a FROM dist ORDER BY a;
