-- production environment
CREATE KEYSPACE IF NOT EXISTS userbase
WITH replication = { 'class': 'NetworkTopologyStrategy', 'replication_factor': '3' };
USE userbase;
