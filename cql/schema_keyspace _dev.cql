-- development environment
CREATE KEYSPACE IF NOT EXISTS userbase
WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '1' };
USE userbase;
