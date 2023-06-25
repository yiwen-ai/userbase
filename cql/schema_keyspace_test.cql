-- test environment
CREATE KEYSPACE IF NOT EXISTS userbase_test
WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '1' };
USE userbase_test;
