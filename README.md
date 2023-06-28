# userbase

## Development

### Running Scylla in docker

start Scylla:
```bash
docker run -d -p 9042:9042 --name scylla scylladb/scylla:5.2 --smp 2
```

check Scylla status:
```bash
docker exec -it scylla nodetool status
```

start cqlsh and then run cql schemas:
```bash
docker exec -it scylla cqlsh
```

restart Scylla:
```bash
docker exec -it scylla supervisorctl restart scylla
```