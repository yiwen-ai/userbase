-- test environment
CREATE KEYSPACE IF NOT EXISTS userbase_test
WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '1' };
USE userbase_test;

-- development environment
CREATE KEYSPACE IF NOT EXISTS userbase
WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '1' };
USE userbase;

-- production environment
CREATE KEYSPACE IF NOT EXISTS userbase
WITH replication = { 'class': 'NetworkTopologyStrategy', 'replication_factor': '3' };
USE userbase;
