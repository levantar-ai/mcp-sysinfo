# MCP System Info - Enterprise Plugin Catalog

Premium plugin offerings for enterprise environments. Each plugin provides specialized diagnostics, configuration auditing, and health monitoring for specific enterprise products.

---

## Table of Contents

1. [Database Systems - Relational](#database-systems---relational)
2. [Database Systems - NoSQL & Document](#database-systems---nosql--document)
3. [Database Systems - Time Series](#database-systems---time-series)
4. [Database Systems - Graph](#database-systems---graph)
5. [Database Systems - NewSQL & Distributed](#database-systems---newsql--distributed)
6. [Database Systems - In-Memory & Cache](#database-systems---in-memory--cache)
7. [Database Systems - Embedded & Edge](#database-systems---embedded--edge)
8. [Cloud Providers](#cloud-providers)
9. [Container Orchestration](#container-orchestration)
10. [Message Queues & Event Streaming](#message-queues--event-streaming)
11. [Web Servers & Reverse Proxies](#web-servers--reverse-proxies)
12. [Load Balancers & Traffic Management](#load-balancers--traffic-management)
13. [CI/CD Platforms](#cicd-platforms)
14. [Observability & Monitoring](#observability--monitoring)
15. [Security & Secrets Management](#security--secrets-management)
16. [Identity & Access Management](#identity--access-management)
17. [Antivirus & Anti-Malware](#antivirus--anti-malware)
18. [Endpoint Detection & Response (EDR/XDR)](#endpoint-detection--response-edrxdr)
19. [Endpoint Protection Platforms (EPP)](#endpoint-protection-platforms-epp)
20. [Mobile Device Management (MDM/UEM)](#mobile-device-management-mdmuem)
21. [Data Loss Prevention (DLP)](#data-loss-prevention-dlp)
22. [SIEM & Security Analytics](#siem--security-analytics)
23. [Networking & Firewalls](#networking--firewalls)
24. [Storage Systems](#storage-systems)
25. [Virtualization Platforms](#virtualization-platforms)
26. [Backup & Disaster Recovery](#backup--disaster-recovery)
27. [Service Mesh](#service-mesh)
28. [Serverless Platforms](#serverless-platforms)
29. [CDN & Edge Computing](#cdn--edge-computing)
30. [APM & Distributed Tracing](#apm--distributed-tracing)
31. [Log Management](#log-management)
32. [Configuration Management](#configuration-management)
33. [DNS & Domain Services](#dns--domain-services)
34. [Email & Messaging](#email--messaging)
35. [Collaboration & Communication](#collaboration--communication)
36. [ERP Systems](#erp-systems)
37. [CRM Platforms](#crm-platforms)
38. [Big Data & Analytics](#big-data--analytics)
39. [Machine Learning Platforms](#machine-learning-platforms)
40. [API Gateways](#api-gateways)
41. [Certificate Management](#certificate-management)
42. [Compliance & Governance](#compliance--governance)
43. [Network Access Control (NAC)](#network-access-control-nac)
44. [Privileged Access Management (PAM)](#privileged-access-management-pam)
45. [Vulnerability Management](#vulnerability-management)

---

## Database Systems - Relational

### MySQL / MariaDB Plugin
**Scope:** `mysql`

| Query | Description |
|-------|-------------|
| `get_mysql_status` | Get server status variables (connections, queries, threads) |
| `get_mysql_variables` | Get server configuration variables |
| `get_mysql_processlist` | Get active connections and running queries |
| `get_mysql_replication_status` | Get master/slave replication status and lag |
| `get_mysql_innodb_status` | Get InnoDB engine status (buffer pool, transactions) |
| `get_mysql_slow_queries` | Get recent slow query log entries |
| `get_mysql_table_sizes` | Get table sizes and row counts by schema |
| `get_mysql_index_usage` | Get index usage statistics |
| `get_mysql_locks` | Get current lock waits and deadlocks |
| `get_mysql_binary_logs` | Get binary log status and positions |
| `get_mysql_user_grants` | Get user privileges (redacted passwords) |
| `get_mysql_performance_schema` | Get performance schema digest summaries |

### PostgreSQL Plugin
**Scope:** `postgresql`

| Query | Description |
|-------|-------------|
| `get_pg_stat_activity` | Get active connections and queries |
| `get_pg_stat_replication` | Get streaming replication status |
| `get_pg_stat_bgwriter` | Get background writer statistics |
| `get_pg_stat_database` | Get database-level statistics |
| `get_pg_locks` | Get current locks and blocking queries |
| `get_pg_vacuum_stats` | Get vacuum and autovacuum statistics |
| `get_pg_table_bloat` | Get table and index bloat estimates |
| `get_pg_slow_queries` | Get slow queries from pg_stat_statements |
| `get_pg_indexes` | Get index usage and efficiency stats |
| `get_pg_settings` | Get runtime configuration parameters |
| `get_pg_extensions` | Get installed extensions and versions |
| `get_pg_wal_status` | Get WAL archiving status and positions |
| `get_pg_logical_replication` | Get logical replication slot status |

### MongoDB Plugin
**Scope:** `mongodb`

| Query | Description |
|-------|-------------|
| `get_mongo_server_status` | Get server status (connections, ops, memory) |
| `get_mongo_replicaset_status` | Get replica set member states and lag |
| `get_mongo_sharding_status` | Get sharding configuration and chunk distribution |
| `get_mongo_current_ops` | Get currently running operations |
| `get_mongo_collection_stats` | Get collection sizes and index stats |
| `get_mongo_index_stats` | Get index usage statistics |
| `get_mongo_slow_queries` | Get slow queries from profiler |
| `get_mongo_locks` | Get current lock states |
| `get_mongo_wiredtiger_stats` | Get WiredTiger cache and checkpoint stats |
| `get_mongo_connections` | Get connection pool statistics |
| `get_mongo_users` | Get user roles and privileges |
| `get_mongo_oplog_status` | Get oplog window and utilization |

### Redis Plugin
**Scope:** `redis`

| Query | Description |
|-------|-------------|
| `get_redis_info` | Get comprehensive server info |
| `get_redis_memory` | Get memory usage breakdown |
| `get_redis_clients` | Get connected clients list |
| `get_redis_slowlog` | Get slow command log |
| `get_redis_keyspace` | Get key counts by database |
| `get_redis_replication` | Get replication status (master/replica) |
| `get_redis_cluster_info` | Get cluster state and slot distribution |
| `get_redis_cluster_nodes` | Get cluster node topology |
| `get_redis_sentinel_masters` | Get Sentinel monitored masters |
| `get_redis_persistence` | Get RDB/AOF persistence status |
| `get_redis_latency` | Get latency histogram data |
| `get_redis_big_keys` | Scan for large keys (memory hogs) |

### Elasticsearch Plugin
**Scope:** `elasticsearch`

| Query | Description |
|-------|-------------|
| `get_es_cluster_health` | Get cluster health status |
| `get_es_cluster_stats` | Get cluster-wide statistics |
| `get_es_node_stats` | Get per-node statistics |
| `get_es_index_stats` | Get index-level statistics |
| `get_es_shard_allocation` | Get shard allocation status |
| `get_es_pending_tasks` | Get pending cluster tasks |
| `get_es_thread_pools` | Get thread pool statistics |
| `get_es_hot_threads` | Get hot threads analysis |
| `get_es_cat_indices` | Get index list with metrics |
| `get_es_cat_nodes` | Get node list with metrics |
| `get_es_ilm_status` | Get Index Lifecycle Management status |
| `get_es_snapshot_status` | Get snapshot repository status |
| `get_es_ml_jobs` | Get machine learning job status |

### Oracle Database Plugin
**Scope:** `oracle`

| Query | Description |
|-------|-------------|
| `get_oracle_instance_info` | Get instance status and version |
| `get_oracle_sessions` | Get active sessions (v$session) |
| `get_oracle_wait_events` | Get wait event statistics |
| `get_oracle_tablespace_usage` | Get tablespace sizes and free space |
| `get_oracle_asm_status` | Get ASM disk group status |
| `get_oracle_dataguard_status` | Get Data Guard sync status |
| `get_oracle_rac_status` | Get RAC node interconnect stats |
| `get_oracle_redo_logs` | Get redo log status and switches |
| `get_oracle_rman_status` | Get RMAN backup job status |
| `get_oracle_awr_snapshot` | Get AWR top SQL and wait events |
| `get_oracle_ash_report` | Get Active Session History summary |
| `get_oracle_locks` | Get blocking locks and deadlocks |
| `get_oracle_pga_stats` | Get PGA memory allocation |
| `get_oracle_sga_stats` | Get SGA component sizes |

### Microsoft SQL Server Plugin
**Scope:** `sqlserver`

| Query | Description |
|-------|-------------|
| `get_sqlserver_instance_info` | Get instance version and edition |
| `get_sqlserver_sessions` | Get active sessions (sp_who2) |
| `get_sqlserver_wait_stats` | Get wait statistics |
| `get_sqlserver_database_sizes` | Get database file sizes |
| `get_sqlserver_index_fragmentation` | Get index fragmentation levels |
| `get_sqlserver_missing_indexes` | Get missing index recommendations |
| `get_sqlserver_blocking` | Get blocking chain analysis |
| `get_sqlserver_alwayson_status` | Get Availability Group status |
| `get_sqlserver_backup_history` | Get recent backup history |
| `get_sqlserver_job_history` | Get SQL Agent job status |
| `get_sqlserver_query_stats` | Get top queries by CPU/IO |
| `get_sqlserver_plan_cache` | Get plan cache analysis |
| `get_sqlserver_tempdb_usage` | Get tempdb utilization |
| `get_sqlserver_memory_clerks` | Get memory clerk allocation |

### Cassandra Plugin
**Scope:** `cassandra`

| Query | Description |
|-------|-------------|
| `get_cassandra_cluster_info` | Get cluster name and topology |
| `get_cassandra_node_status` | Get node up/down status |
| `get_cassandra_ring` | Get token ring distribution |
| `get_cassandra_table_stats` | Get table read/write latencies |
| `get_cassandra_compaction` | Get compaction status |
| `get_cassandra_repair_status` | Get repair progress |
| `get_cassandra_gc_stats` | Get garbage collection stats |
| `get_cassandra_streaming` | Get streaming operations |
| `get_cassandra_hints` | Get hinted handoff status |
| `get_cassandra_thread_pools` | Get thread pool statistics |
| `get_cassandra_dropped_messages` | Get dropped message counts |
| `get_cassandra_snapshot_status` | Get snapshot list |

### CockroachDB Plugin
**Scope:** `cockroachdb`

| Query | Description |
|-------|-------------|
| `get_crdb_cluster_nodes` | Get cluster node status |
| `get_crdb_range_status` | Get range distribution |
| `get_crdb_jobs` | Get running/paused jobs |
| `get_crdb_sessions` | Get active sessions |
| `get_crdb_statements` | Get statement statistics |
| `get_crdb_hot_ranges` | Get hot range analysis |
| `get_crdb_changefeed_status` | Get changefeed status |
| `get_crdb_replication_lag` | Get replication lag stats |
| `get_crdb_backup_status` | Get backup schedule status |
| `get_crdb_contention` | Get contention analysis |

### IBM Db2 Plugin
**Scope:** `db2`

| Query | Description |
|-------|-------------|
| `get_db2_instance_info` | Get instance configuration |
| `get_db2_database_cfg` | Get database configuration |
| `get_db2_tablespaces` | Get tablespace status and usage |
| `get_db2_bufferpools` | Get buffer pool hit ratios |
| `get_db2_connections` | Get active connections |
| `get_db2_locks` | Get lock waits and deadlocks |
| `get_db2_hadr_status` | Get HADR replication status |
| `get_db2_utilities` | Get running utilities |
| `get_db2_logs` | Get transaction log status |
| `get_db2_diagnostics` | Get db2diag.log entries |
| `get_db2_snapshots` | Get database snapshots |

### SAP HANA Plugin
**Scope:** `hana`

| Query | Description |
|-------|-------------|
| `get_hana_system_overview` | Get system status and version |
| `get_hana_services` | Get service status |
| `get_hana_memory` | Get memory allocation breakdown |
| `get_hana_connections` | Get active connections |
| `get_hana_expensive_statements` | Get expensive SQL statements |
| `get_hana_blocked_transactions` | Get blocked transactions |
| `get_hana_replication` | Get system replication status |
| `get_hana_backup_catalog` | Get backup catalog |
| `get_hana_alerts` | Get system alerts |
| `get_hana_volumes` | Get persistence volume status |
| `get_hana_delta_merge` | Get delta merge statistics |

### Teradata Plugin
**Scope:** `teradata`

| Query | Description |
|-------|-------------|
| `get_teradata_system_info` | Get DBS version and config |
| `get_teradata_nodes` | Get node/AMP status |
| `get_teradata_sessions` | Get active sessions |
| `get_teradata_queries` | Get running queries |
| `get_teradata_space` | Get database space usage |
| `get_teradata_workloads` | Get TASM workload status |
| `get_teradata_skew` | Get data skew analysis |
| `get_teradata_locks` | Get lock information |
| `get_teradata_stats` | Get statistics collection status |

### Sybase/SAP ASE Plugin
**Scope:** `sybase`

| Query | Description |
|-------|-------------|
| `get_sybase_server_info` | Get server version and config |
| `get_sybase_databases` | Get database status |
| `get_sybase_processes` | Get active processes |
| `get_sybase_locks` | Get lock contention |
| `get_sybase_devices` | Get device allocation |
| `get_sybase_replication` | Get Rep Server status |
| `get_sybase_caches` | Get data cache statistics |
| `get_sybase_engines` | Get engine utilization |

### Informix Plugin
**Scope:** `informix`

| Query | Description |
|-------|-------------|
| `get_informix_status` | Get instance status |
| `get_informix_dbspaces` | Get dbspace usage |
| `get_informix_sessions` | Get active sessions |
| `get_informix_locks` | Get lock information |
| `get_informix_checkpoints` | Get checkpoint history |
| `get_informix_logs` | Get logical log status |
| `get_informix_replication` | Get HDR/RSS status |

### Firebird Plugin
**Scope:** `firebird`

| Query | Description |
|-------|-------------|
| `get_firebird_server_info` | Get server version |
| `get_firebird_databases` | Get database list |
| `get_firebird_connections` | Get active connections |
| `get_firebird_transactions` | Get transaction status |
| `get_firebird_statistics` | Get database statistics |
| `get_firebird_trace` | Get trace session data |

---

## Database Systems - NoSQL & Document

### Amazon DynamoDB Plugin
**Scope:** `dynamodb`

| Query | Description |
|-------|-------------|
| `get_dynamodb_tables` | Get table inventory |
| `get_dynamodb_table_metrics` | Get table CloudWatch metrics |
| `get_dynamodb_capacity` | Get provisioned/on-demand capacity |
| `get_dynamodb_indexes` | Get GSI/LSI status |
| `get_dynamodb_streams` | Get DynamoDB Streams status |
| `get_dynamodb_backups` | Get backup status |
| `get_dynamodb_global_tables` | Get global table replication |
| `get_dynamodb_dax` | Get DAX cluster status |

### Azure Cosmos DB Plugin
**Scope:** `cosmosdb`

| Query | Description |
|-------|-------------|
| `get_cosmosdb_accounts` | Get account inventory |
| `get_cosmosdb_databases` | Get database list |
| `get_cosmosdb_containers` | Get container metrics |
| `get_cosmosdb_throughput` | Get RU/s allocation |
| `get_cosmosdb_partitions` | Get partition key distribution |
| `get_cosmosdb_replication` | Get geo-replication status |
| `get_cosmosdb_consistency` | Get consistency settings |
| `get_cosmosdb_conflicts` | Get conflict resolution |

### CouchDB Plugin
**Scope:** `couchdb`

| Query | Description |
|-------|-------------|
| `get_couchdb_server_info` | Get server status |
| `get_couchdb_databases` | Get database list |
| `get_couchdb_database_info` | Get database statistics |
| `get_couchdb_active_tasks` | Get running tasks |
| `get_couchdb_replication` | Get replication status |
| `get_couchdb_cluster` | Get cluster membership |
| `get_couchdb_scheduler` | Get scheduler jobs |
| `get_couchdb_shards` | Get shard distribution |

### Couchbase Plugin
**Scope:** `couchbase`

| Query | Description |
|-------|-------------|
| `get_couchbase_cluster` | Get cluster overview |
| `get_couchbase_nodes` | Get node status |
| `get_couchbase_buckets` | Get bucket statistics |
| `get_couchbase_indexes` | Get GSI index status |
| `get_couchbase_xdcr` | Get cross-datacenter replication |
| `get_couchbase_fts` | Get full-text search status |
| `get_couchbase_analytics` | Get analytics service status |
| `get_couchbase_eventing` | Get eventing functions |
| `get_couchbase_backup` | Get backup service status |

### RavenDB Plugin
**Scope:** `ravendb`

| Query | Description |
|-------|-------------|
| `get_ravendb_server_info` | Get server status |
| `get_ravendb_databases` | Get database list |
| `get_ravendb_indexes` | Get index status |
| `get_ravendb_replication` | Get replication topology |
| `get_ravendb_subscriptions` | Get data subscriptions |
| `get_ravendb_operations` | Get running operations |
| `get_ravendb_studio` | Get studio usage stats |

### ArangoDB Plugin
**Scope:** `arangodb`

| Query | Description |
|-------|-------------|
| `get_arangodb_server_info` | Get server version |
| `get_arangodb_databases` | Get database list |
| `get_arangodb_collections` | Get collection statistics |
| `get_arangodb_indexes` | Get index inventory |
| `get_arangodb_graphs` | Get graph definitions |
| `get_arangodb_cluster` | Get cluster health |
| `get_arangodb_replication` | Get replication status |
| `get_arangodb_jobs` | Get async job status |

### MarkLogic Plugin
**Scope:** `marklogic`

| Query | Description |
|-------|-------------|
| `get_marklogic_cluster` | Get cluster status |
| `get_marklogic_hosts` | Get host health |
| `get_marklogic_forests` | Get forest status |
| `get_marklogic_databases` | Get database config |
| `get_marklogic_servers` | Get app server status |
| `get_marklogic_requests` | Get active requests |
| `get_marklogic_transactions` | Get open transactions |
| `get_marklogic_backup_status` | Get backup history |

---

## Database Systems - Time Series

### InfluxDB Plugin
**Scope:** `influxdb`

| Query | Description |
|-------|-------------|
| `get_influxdb_health` | Get server health |
| `get_influxdb_databases` | Get database list (v1) |
| `get_influxdb_buckets` | Get bucket list (v2) |
| `get_influxdb_orgs` | Get organization list |
| `get_influxdb_users` | Get user list |
| `get_influxdb_retention` | Get retention policies |
| `get_influxdb_continuous_queries` | Get CQ status |
| `get_influxdb_subscriptions` | Get subscriptions |
| `get_influxdb_shards` | Get shard groups |
| `get_influxdb_tasks` | Get Flux tasks |
| `get_influxdb_cardinality` | Get series cardinality |

### TimescaleDB Plugin
**Scope:** `timescaledb`

| Query | Description |
|-------|-------------|
| `get_timescale_version` | Get extension version |
| `get_timescale_hypertables` | Get hypertable list |
| `get_timescale_chunks` | Get chunk information |
| `get_timescale_compression` | Get compression status |
| `get_timescale_continuous_aggs` | Get continuous aggregates |
| `get_timescale_retention` | Get retention policies |
| `get_timescale_jobs` | Get background jobs |
| `get_timescale_replication` | Get multi-node status |

### Prometheus TSDB Plugin
**Scope:** `prometheus_tsdb`

| Query | Description |
|-------|-------------|
| `get_prom_tsdb_status` | Get TSDB statistics |
| `get_prom_head_stats` | Get head block stats |
| `get_prom_wal_status` | Get WAL statistics |
| `get_prom_block_stats` | Get block metadata |
| `get_prom_tombstones` | Get tombstone count |
| `get_prom_exemplars` | Get exemplar storage |
| `get_prom_label_names` | Get label cardinality |

### Victoria Metrics Plugin
**Scope:** `victoriametrics`

| Query | Description |
|-------|-------------|
| `get_vm_status` | Get server status |
| `get_vm_storage` | Get storage statistics |
| `get_vm_active_queries` | Get running queries |
| `get_vm_top_queries` | Get heaviest queries |
| `get_vm_tsid_status` | Get TSID statistics |
| `get_vm_replication` | Get vmstorage replication |
| `get_vm_cluster` | Get cluster component status |

### QuestDB Plugin
**Scope:** `questdb`

| Query | Description |
|-------|-------------|
| `get_questdb_status` | Get server status |
| `get_questdb_tables` | Get table list |
| `get_questdb_columns` | Get column metadata |
| `get_questdb_partitions` | Get partition info |
| `get_questdb_wal` | Get WAL status |
| `get_questdb_metrics` | Get server metrics |

### Apache Druid Plugin
**Scope:** `druid`

| Query | Description |
|-------|-------------|
| `get_druid_cluster` | Get cluster status |
| `get_druid_coordinator` | Get coordinator status |
| `get_druid_overlord` | Get overlord status |
| `get_druid_brokers` | Get broker status |
| `get_druid_historicals` | Get historical node status |
| `get_druid_datasources` | Get datasource list |
| `get_druid_segments` | Get segment inventory |
| `get_druid_tasks` | Get ingestion tasks |
| `get_druid_supervisors` | Get streaming supervisors |
| `get_druid_lookups` | Get lookup status |

### Graphite Plugin
**Scope:** `graphite`

| Query | Description |
|-------|-------------|
| `get_graphite_metrics` | Get metric index |
| `get_graphite_whisper_info` | Get whisper file stats |
| `get_graphite_carbon_stats` | Get carbon daemon stats |
| `get_graphite_retention` | Get storage schemas |
| `get_graphite_aggregation` | Get aggregation rules |

### OpenTSDB Plugin
**Scope:** `opentsdb`

| Query | Description |
|-------|-------------|
| `get_opentsdb_version` | Get server version |
| `get_opentsdb_stats` | Get internal statistics |
| `get_opentsdb_suggest` | Get metric suggestions |
| `get_opentsdb_uid` | Get UID assignment stats |
| `get_opentsdb_region_clients` | Get HBase region clients |

---

## Database Systems - Graph

### Neo4j Plugin
**Scope:** `neo4j`

| Query | Description |
|-------|-------------|
| `get_neo4j_server_info` | Get server version/edition |
| `get_neo4j_databases` | Get database list |
| `get_neo4j_cluster` | Get causal cluster status |
| `get_neo4j_store_sizes` | Get store file sizes |
| `get_neo4j_transactions` | Get transaction stats |
| `get_neo4j_page_cache` | Get page cache metrics |
| `get_neo4j_indexes` | Get index status |
| `get_neo4j_constraints` | Get constraint definitions |
| `get_neo4j_procedures` | Get procedure list |
| `get_neo4j_queries` | Get running queries |
| `get_neo4j_logs` | Get query log entries |

### Amazon Neptune Plugin
**Scope:** `neptune`

| Query | Description |
|-------|-------------|
| `get_neptune_cluster` | Get cluster status |
| `get_neptune_instances` | Get instance health |
| `get_neptune_endpoints` | Get endpoint configuration |
| `get_neptune_parameters` | Get parameter groups |
| `get_neptune_statistics` | Get graph statistics |
| `get_neptune_status` | Get engine status |
| `get_neptune_sparql_status` | Get SPARQL endpoint status |
| `get_neptune_gremlin_status` | Get Gremlin endpoint status |

### JanusGraph Plugin
**Scope:** `janusgraph`

| Query | Description |
|-------|-------------|
| `get_janusgraph_status` | Get server status |
| `get_janusgraph_schema` | Get graph schema |
| `get_janusgraph_indexes` | Get index status |
| `get_janusgraph_backends` | Get storage backend status |
| `get_janusgraph_metrics` | Get performance metrics |
| `get_janusgraph_transactions` | Get open transactions |

### TigerGraph Plugin
**Scope:** `tigergraph`

| Query | Description |
|-------|-------------|
| `get_tigergraph_cluster` | Get cluster status |
| `get_tigergraph_graphs` | Get graph list |
| `get_tigergraph_vertices` | Get vertex type stats |
| `get_tigergraph_edges` | Get edge type stats |
| `get_tigergraph_queries` | Get installed queries |
| `get_tigergraph_loading_jobs` | Get loading job status |
| `get_tigergraph_users` | Get user list |
| `get_tigergraph_gsql_server` | Get GSQL server status |

### Dgraph Plugin
**Scope:** `dgraph`

| Query | Description |
|-------|-------------|
| `get_dgraph_health` | Get cluster health |
| `get_dgraph_state` | Get cluster state |
| `get_dgraph_zeros` | Get Zero group status |
| `get_dgraph_alphas` | Get Alpha group status |
| `get_dgraph_schema` | Get GraphQL schema |
| `get_dgraph_predicates` | Get predicate list |
| `get_dgraph_enterprise` | Get license/ACL status |

### OrientDB Plugin
**Scope:** `orientdb`

| Query | Description |
|-------|-------------|
| `get_orientdb_server` | Get server status |
| `get_orientdb_databases` | Get database list |
| `get_orientdb_cluster` | Get distributed status |
| `get_orientdb_classes` | Get class definitions |
| `get_orientdb_indexes` | Get index status |
| `get_orientdb_connections` | Get active connections |
| `get_orientdb_profiler` | Get profiler statistics |

---

## Database Systems - NewSQL & Distributed

### TiDB Plugin
**Scope:** `tidb`

| Query | Description |
|-------|-------------|
| `get_tidb_cluster_info` | Get cluster topology |
| `get_tidb_stores` | Get TiKV store status |
| `get_tidb_regions` | Get region distribution |
| `get_tidb_pd_health` | Get PD leader health |
| `get_tidb_schemas` | Get database schemas |
| `get_tidb_slow_queries` | Get slow query log |
| `get_tidb_statements` | Get statement summary |
| `get_tidb_hotspots` | Get read/write hotspots |
| `get_tidb_gc_status` | Get GC status |
| `get_tidb_backup_status` | Get BR backup status |

### YugabyteDB Plugin
**Scope:** `yugabyte`

| Query | Description |
|-------|-------------|
| `get_yb_cluster_info` | Get cluster configuration |
| `get_yb_masters` | Get master status |
| `get_yb_tservers` | Get tablet server status |
| `get_yb_tablets` | Get tablet distribution |
| `get_yb_tables` | Get table list |
| `get_yb_namespaces` | Get namespace list |
| `get_yb_replication` | Get xCluster replication |
| `get_yb_load_balancer` | Get load balancer status |

### VoltDB Plugin
**Scope:** `voltdb`

| Query | Description |
|-------|-------------|
| `get_voltdb_cluster` | Get cluster overview |
| `get_voltdb_hosts` | Get host status |
| `get_voltdb_partitions` | Get partition status |
| `get_voltdb_procedures` | Get stored procedures |
| `get_voltdb_dr` | Get DR replication status |
| `get_voltdb_export` | Get export status |
| `get_voltdb_import` | Get import status |
| `get_voltdb_statistics` | Get procedural statistics |

### SingleStore (MemSQL) Plugin
**Scope:** `singlestore`

| Query | Description |
|-------|-------------|
| `get_singlestore_cluster` | Get cluster status |
| `get_singlestore_leaves` | Get leaf node status |
| `get_singlestore_aggregators` | Get aggregator status |
| `get_singlestore_databases` | Get database list |
| `get_singlestore_pipelines` | Get pipeline status |
| `get_singlestore_replication` | Get replication status |
| `get_singlestore_mv_status` | Get management views |
| `get_singlestore_workloads` | Get resource pools |

### Vitess Plugin
**Scope:** `vitess`

| Query | Description |
|-------|-------------|
| `get_vitess_topology` | Get cluster topology |
| `get_vitess_cells` | Get cell status |
| `get_vitess_keyspaces` | Get keyspace list |
| `get_vitess_shards` | Get shard distribution |
| `get_vitess_tablets` | Get tablet status |
| `get_vitess_vschema` | Get VSchema definition |
| `get_vitess_vtgate` | Get VTGate status |
| `get_vitess_replication` | Get replication lag |

### Spanner Plugin
**Scope:** `spanner`

| Query | Description |
|-------|-------------|
| `get_spanner_instances` | Get instance list |
| `get_spanner_databases` | Get database list |
| `get_spanner_sessions` | Get session pool status |
| `get_spanner_operations` | Get long-running operations |
| `get_spanner_backup` | Get backup status |
| `get_spanner_iam` | Get IAM policies |

---

## Database Systems - In-Memory & Cache

### Memcached Plugin
**Scope:** `memcached`

| Query | Description |
|-------|-------------|
| `get_memcached_stats` | Get general statistics |
| `get_memcached_slabs` | Get slab allocation |
| `get_memcached_items` | Get item statistics |
| `get_memcached_settings` | Get server settings |
| `get_memcached_conns` | Get connection stats |
| `get_memcached_sizes` | Get item size distribution |

### Hazelcast Plugin
**Scope:** `hazelcast`

| Query | Description |
|-------|-------------|
| `get_hazelcast_cluster` | Get cluster state |
| `get_hazelcast_members` | Get member list |
| `get_hazelcast_maps` | Get IMap statistics |
| `get_hazelcast_queues` | Get IQueue statistics |
| `get_hazelcast_topics` | Get ITopic statistics |
| `get_hazelcast_executors` | Get executor stats |
| `get_hazelcast_caches` | Get JCache statistics |
| `get_hazelcast_wan` | Get WAN replication |
| `get_hazelcast_cp` | Get CP subsystem status |

### Apache Ignite Plugin
**Scope:** `ignite`

| Query | Description |
|-------|-------------|
| `get_ignite_cluster` | Get cluster topology |
| `get_ignite_nodes` | Get node attributes |
| `get_ignite_caches` | Get cache statistics |
| `get_ignite_baseline` | Get baseline topology |
| `get_ignite_compute` | Get compute task stats |
| `get_ignite_services` | Get deployed services |
| `get_ignite_sql` | Get SQL query stats |
| `get_ignite_persistence` | Get persistence status |

### Aerospike Plugin
**Scope:** `aerospike`

| Query | Description |
|-------|-------------|
| `get_aerospike_info` | Get server info |
| `get_aerospike_namespaces` | Get namespace stats |
| `get_aerospike_sets` | Get set statistics |
| `get_aerospike_bins` | Get bin statistics |
| `get_aerospike_sindex` | Get secondary indexes |
| `get_aerospike_xdr` | Get XDR replication |
| `get_aerospike_jobs` | Get scan/query jobs |
| `get_aerospike_latency` | Get latency histograms |

### Apache Geode Plugin
**Scope:** `geode`

| Query | Description |
|-------|-------------|
| `get_geode_cluster` | Get cluster status |
| `get_geode_members` | Get member list |
| `get_geode_regions` | Get region statistics |
| `get_geode_locators` | Get locator status |
| `get_geode_gateways` | Get WAN gateway status |
| `get_geode_indexes` | Get index list |
| `get_geode_pdx` | Get PDX type registry |
| `get_geode_disk_stores` | Get disk store status |

### KeyDB Plugin
**Scope:** `keydb`

| Query | Description |
|-------|-------------|
| `get_keydb_info` | Get server info |
| `get_keydb_active_replica` | Get active replication status |
| `get_keydb_mvcc` | Get MVCC statistics |
| `get_keydb_flash` | Get flash storage stats |
| `get_keydb_subkey_expires` | Get subkey expiration stats |

### Dragonfly Plugin
**Scope:** `dragonfly`

| Query | Description |
|-------|-------------|
| `get_dragonfly_info` | Get server info |
| `get_dragonfly_memory` | Get memory breakdown |
| `get_dragonfly_replication` | Get replication status |
| `get_dragonfly_cluster` | Get cluster info |
| `get_dragonfly_metrics` | Get performance metrics |

---

## Database Systems - Embedded & Edge

### SQLite Plugin
**Scope:** `sqlite`

| Query | Description |
|-------|-------------|
| `get_sqlite_version` | Get SQLite version |
| `get_sqlite_databases` | Enumerate SQLite files |
| `get_sqlite_schema` | Get database schema |
| `get_sqlite_integrity` | Run integrity check |
| `get_sqlite_stats` | Get table statistics |
| `get_sqlite_indexes` | Get index list |
| `get_sqlite_wal_status` | Get WAL checkpoint status |
| `get_sqlite_compile_options` | Get compile options |

### DuckDB Plugin
**Scope:** `duckdb`

| Query | Description |
|-------|-------------|
| `get_duckdb_version` | Get DuckDB version |
| `get_duckdb_databases` | Get attached databases |
| `get_duckdb_tables` | Get table list |
| `get_duckdb_extensions` | Get loaded extensions |
| `get_duckdb_settings` | Get configuration |
| `get_duckdb_memory` | Get memory usage |

### LevelDB/RocksDB Plugin
**Scope:** `rocksdb`

| Query | Description |
|-------|-------------|
| `get_rocksdb_stats` | Get statistics |
| `get_rocksdb_properties` | Get DB properties |
| `get_rocksdb_levels` | Get level statistics |
| `get_rocksdb_compaction` | Get compaction stats |
| `get_rocksdb_memtable` | Get memtable status |
| `get_rocksdb_sstables` | Get SSTable info |
| `get_rocksdb_options` | Get option settings |

### Berkeley DB Plugin
**Scope:** `berkeleydb`

| Query | Description |
|-------|-------------|
| `get_bdb_version` | Get DB version |
| `get_bdb_stats` | Get database statistics |
| `get_bdb_environment` | Get environment status |
| `get_bdb_locks` | Get lock statistics |
| `get_bdb_logs` | Get log file status |
| `get_bdb_replication` | Get replication status |

### LMDB Plugin
**Scope:** `lmdb`

| Query | Description |
|-------|-------------|
| `get_lmdb_info` | Get environment info |
| `get_lmdb_stat` | Get database statistics |
| `get_lmdb_readers` | Get reader table |
| `get_lmdb_size` | Get map size usage |

### EdgeDB Plugin
**Scope:** `edgedb`

| Query | Description |
|-------|-------------|
| `get_edgedb_server_info` | Get server version |
| `get_edgedb_databases` | Get database list |
| `get_edgedb_branches` | Get schema branches |
| `get_edgedb_migrations` | Get migration status |
| `get_edgedb_roles` | Get role list |
| `get_edgedb_config` | Get instance config |

### SurrealDB Plugin
**Scope:** `surrealdb`

| Query | Description |
|-------|-------------|
| `get_surrealdb_health` | Get server health |
| `get_surrealdb_namespaces` | Get namespace list |
| `get_surrealdb_databases` | Get database list |
| `get_surrealdb_tables` | Get table definitions |
| `get_surrealdb_users` | Get user list |
| `get_surrealdb_tokens` | Get token metadata |

---

## Cloud Providers

### AWS Plugin
**Scope:** `aws`

| Query | Description |
|-------|-------------|
| `get_aws_ec2_instances` | Get EC2 instance inventory and status |
| `get_aws_ec2_instance_health` | Get instance status checks |
| `get_aws_rds_instances` | Get RDS database instances |
| `get_aws_rds_performance` | Get RDS performance insights |
| `get_aws_s3_buckets` | Get S3 bucket inventory |
| `get_aws_iam_users` | Get IAM user list (no secrets) |
| `get_aws_iam_roles` | Get IAM role inventory |
| `get_aws_vpc_subnets` | Get VPC and subnet configuration |
| `get_aws_security_groups` | Get security group rules |
| `get_aws_elb_status` | Get load balancer health |
| `get_aws_lambda_functions` | Get Lambda function inventory |
| `get_aws_ecs_services` | Get ECS service status |
| `get_aws_eks_clusters` | Get EKS cluster status |
| `get_aws_cloudwatch_alarms` | Get CloudWatch alarm states |
| `get_aws_cost_explorer` | Get cost breakdown by service |
| `get_aws_trusted_advisor` | Get Trusted Advisor findings |
| `get_aws_guardduty_findings` | Get GuardDuty security findings |
| `get_aws_secrets_manager` | Get secret metadata (not values) |

### Google Cloud Platform Plugin
**Scope:** `gcp`

| Query | Description |
|-------|-------------|
| `get_gcp_compute_instances` | Get Compute Engine instances |
| `get_gcp_cloud_sql` | Get Cloud SQL instances |
| `get_gcp_gke_clusters` | Get GKE cluster status |
| `get_gcp_cloud_storage` | Get Cloud Storage bucket list |
| `get_gcp_iam_policies` | Get IAM policy bindings |
| `get_gcp_vpc_networks` | Get VPC network config |
| `get_gcp_firewall_rules` | Get firewall rules |
| `get_gcp_load_balancers` | Get load balancer status |
| `get_gcp_cloud_functions` | Get Cloud Functions inventory |
| `get_gcp_cloud_run` | Get Cloud Run services |
| `get_gcp_pubsub_topics` | Get Pub/Sub topic stats |
| `get_gcp_bigquery_datasets` | Get BigQuery dataset info |
| `get_gcp_monitoring_alerts` | Get alerting policy status |
| `get_gcp_security_findings` | Get Security Command Center findings |

### Microsoft Azure Plugin
**Scope:** `azure`

| Query | Description |
|-------|-------------|
| `get_azure_vms` | Get virtual machine inventory |
| `get_azure_vm_health` | Get VM health status |
| `get_azure_sql_databases` | Get Azure SQL databases |
| `get_azure_cosmos_db` | Get Cosmos DB accounts |
| `get_azure_storage_accounts` | Get storage account list |
| `get_azure_aks_clusters` | Get AKS cluster status |
| `get_azure_app_services` | Get App Service status |
| `get_azure_functions` | Get Azure Functions list |
| `get_azure_vnets` | Get virtual network config |
| `get_azure_nsgs` | Get network security groups |
| `get_azure_load_balancers` | Get load balancer health |
| `get_azure_key_vaults` | Get Key Vault inventory |
| `get_azure_ad_users` | Get Azure AD users |
| `get_azure_rbac` | Get role assignments |
| `get_azure_defender_alerts` | Get Defender for Cloud alerts |
| `get_azure_cost_analysis` | Get cost breakdown |

---

## Container Orchestration

### Kubernetes Plugin
**Scope:** `kubernetes`

| Query | Description |
|-------|-------------|
| `get_k8s_cluster_info` | Get cluster version and API server info |
| `get_k8s_nodes` | Get node status and capacity |
| `get_k8s_node_conditions` | Get node conditions (Ready, DiskPressure, etc.) |
| `get_k8s_namespaces` | Get namespace list and status |
| `get_k8s_pods` | Get pod status by namespace |
| `get_k8s_pod_events` | Get recent pod events |
| `get_k8s_deployments` | Get deployment status and replicas |
| `get_k8s_statefulsets` | Get StatefulSet status |
| `get_k8s_daemonsets` | Get DaemonSet status |
| `get_k8s_services` | Get service endpoints |
| `get_k8s_ingresses` | Get ingress configuration |
| `get_k8s_configmaps` | Get ConfigMap list (no data) |
| `get_k8s_secrets` | Get Secret metadata (no values) |
| `get_k8s_pvcs` | Get PersistentVolumeClaim status |
| `get_k8s_pvs` | Get PersistentVolume inventory |
| `get_k8s_storage_classes` | Get StorageClass definitions |
| `get_k8s_resource_quotas` | Get namespace resource quotas |
| `get_k8s_limit_ranges` | Get namespace limit ranges |
| `get_k8s_hpas` | Get HorizontalPodAutoscaler status |
| `get_k8s_network_policies` | Get NetworkPolicy rules |
| `get_k8s_rbac_roles` | Get Role/ClusterRole definitions |
| `get_k8s_service_accounts` | Get ServiceAccount inventory |
| `get_k8s_crds` | Get CustomResourceDefinition list |
| `get_k8s_api_resources` | Get available API resources |
| `get_k8s_top_nodes` | Get node CPU/memory usage |
| `get_k8s_top_pods` | Get pod CPU/memory usage |

### OpenShift Plugin
**Scope:** `openshift`

| Query | Description |
|-------|-------------|
| `get_openshift_cluster_version` | Get OpenShift version and update status |
| `get_openshift_cluster_operators` | Get cluster operator status |
| `get_openshift_projects` | Get project list with quotas |
| `get_openshift_builds` | Get build status |
| `get_openshift_deploymentconfigs` | Get DeploymentConfig status |
| `get_openshift_routes` | Get route configuration |
| `get_openshift_imagestreams` | Get ImageStream inventory |
| `get_openshift_templates` | Get template catalog |
| `get_openshift_scc` | Get SecurityContextConstraints |
| `get_openshift_oauth_clients` | Get OAuth client config |
| `get_openshift_machine_sets` | Get MachineSet status |
| `get_openshift_node_pools` | Get node pool configuration |

### HashiCorp Nomad Plugin
**Scope:** `nomad`

| Query | Description |
|-------|-------------|
| `get_nomad_servers` | Get server cluster members |
| `get_nomad_clients` | Get client node status |
| `get_nomad_jobs` | Get job list and status |
| `get_nomad_allocations` | Get allocation health |
| `get_nomad_deployments` | Get deployment status |
| `get_nomad_namespaces` | Get namespace list |
| `get_nomad_volumes` | Get CSI volume status |
| `get_nomad_acl_tokens` | Get ACL token metadata |
| `get_nomad_sentinel_policies` | Get Sentinel policies |
| `get_nomad_metrics` | Get Nomad server metrics |

### Docker Swarm Plugin
**Scope:** `swarm`

| Query | Description |
|-------|-------------|
| `get_swarm_nodes` | Get swarm node status |
| `get_swarm_services` | Get service replicas |
| `get_swarm_tasks` | Get task status |
| `get_swarm_networks` | Get overlay network list |
| `get_swarm_secrets` | Get secret metadata |
| `get_swarm_configs` | Get config metadata |
| `get_swarm_stacks` | Get stack list |

---

## Message Queues & Event Streaming

### Apache Kafka Plugin
**Scope:** `kafka`

| Query | Description |
|-------|-------------|
| `get_kafka_cluster_info` | Get cluster ID and broker list |
| `get_kafka_broker_status` | Get broker health metrics |
| `get_kafka_topics` | Get topic list and partition counts |
| `get_kafka_topic_config` | Get topic-level configuration |
| `get_kafka_consumer_groups` | Get consumer group list |
| `get_kafka_consumer_lag` | Get consumer group lag |
| `get_kafka_partition_leaders` | Get partition leader distribution |
| `get_kafka_under_replicated` | Get under-replicated partitions |
| `get_kafka_isr_shrink` | Get ISR shrink events |
| `get_kafka_acls` | Get ACL configurations |
| `get_kafka_quotas` | Get client quotas |
| `get_kafka_connect_connectors` | Get Kafka Connect connector status |
| `get_kafka_connect_tasks` | Get connector task status |
| `get_kafka_schema_registry` | Get Schema Registry subjects |

### RabbitMQ Plugin
**Scope:** `rabbitmq`

| Query | Description |
|-------|-------------|
| `get_rabbitmq_overview` | Get cluster overview metrics |
| `get_rabbitmq_nodes` | Get node status and memory |
| `get_rabbitmq_queues` | Get queue depths and rates |
| `get_rabbitmq_exchanges` | Get exchange list and types |
| `get_rabbitmq_bindings` | Get exchange-queue bindings |
| `get_rabbitmq_connections` | Get connection list |
| `get_rabbitmq_channels` | Get channel statistics |
| `get_rabbitmq_consumers` | Get consumer list |
| `get_rabbitmq_vhosts` | Get virtual host list |
| `get_rabbitmq_users` | Get user list and tags |
| `get_rabbitmq_permissions` | Get user permissions |
| `get_rabbitmq_policies` | Get policy definitions |
| `get_rabbitmq_federation` | Get federation link status |
| `get_rabbitmq_shovel` | Get shovel status |

### Apache ActiveMQ Plugin
**Scope:** `activemq`

| Query | Description |
|-------|-------------|
| `get_activemq_broker_info` | Get broker version and status |
| `get_activemq_queues` | Get queue depths |
| `get_activemq_topics` | Get topic subscriber counts |
| `get_activemq_connections` | Get active connections |
| `get_activemq_producers` | Get producer statistics |
| `get_activemq_consumers` | Get consumer statistics |
| `get_activemq_network_connectors` | Get network bridge status |
| `get_activemq_dlq` | Get dead letter queue contents |
| `get_activemq_storage` | Get KahaDB storage stats |

### Apache Pulsar Plugin
**Scope:** `pulsar`

| Query | Description |
|-------|-------------|
| `get_pulsar_cluster_info` | Get cluster and broker info |
| `get_pulsar_brokers` | Get broker load and status |
| `get_pulsar_bookies` | Get BookKeeper status |
| `get_pulsar_namespaces` | Get namespace policies |
| `get_pulsar_topics` | Get topic statistics |
| `get_pulsar_subscriptions` | Get subscription backlog |
| `get_pulsar_functions` | Get Pulsar Functions status |
| `get_pulsar_sources` | Get IO connector sources |
| `get_pulsar_sinks` | Get IO connector sinks |
| `get_pulsar_schema` | Get schema registry info |

### Amazon SQS Plugin
**Scope:** `sqs`

| Query | Description |
|-------|-------------|
| `get_sqs_queues` | Get queue list and attributes |
| `get_sqs_queue_metrics` | Get queue CloudWatch metrics |
| `get_sqs_dlq_redrive` | Get DLQ redrive policy |
| `get_sqs_fifo_dedup` | Get FIFO deduplication stats |

### NATS Plugin
**Scope:** `nats`

| Query | Description |
|-------|-------------|
| `get_nats_server_info` | Get server version and config |
| `get_nats_varz` | Get general server statistics |
| `get_nats_connz` | Get connection details |
| `get_nats_routez` | Get cluster route info |
| `get_nats_gatewayz` | Get gateway connections |
| `get_nats_leafz` | Get leaf node connections |
| `get_nats_jsz` | Get JetStream overview |
| `get_nats_streams` | Get JetStream stream stats |
| `get_nats_consumers` | Get JetStream consumer stats |
| `get_nats_accounts` | Get account information |

---

## Web Servers & Reverse Proxies

### Nginx Plugin
**Scope:** `nginx`

| Query | Description |
|-------|-------------|
| `get_nginx_status` | Get stub_status/plus status |
| `get_nginx_config` | Get parsed nginx.conf (redacted) |
| `get_nginx_upstreams` | Get upstream server status |
| `get_nginx_server_zones` | Get server zone metrics |
| `get_nginx_connections` | Get connection statistics |
| `get_nginx_ssl_certs` | Get SSL certificate info |
| `get_nginx_access_logs` | Get recent access log entries |
| `get_nginx_error_logs` | Get recent error log entries |
| `get_nginx_rate_limits` | Get rate limit zone status |
| `get_nginx_cache_status` | Get cache hit/miss stats |

### Apache HTTP Server Plugin
**Scope:** `apache`

| Query | Description |
|-------|-------------|
| `get_apache_server_status` | Get mod_status metrics |
| `get_apache_config` | Get parsed httpd.conf (redacted) |
| `get_apache_vhosts` | Get virtual host list |
| `get_apache_modules` | Get loaded modules |
| `get_apache_mpm_status` | Get MPM worker stats |
| `get_apache_balancer_status` | Get mod_proxy_balancer members |
| `get_apache_ssl_certs` | Get SSL certificate info |
| `get_apache_access_logs` | Get recent access logs |
| `get_apache_error_logs` | Get recent error logs |

### HAProxy Plugin
**Scope:** `haproxy`

| Query | Description |
|-------|-------------|
| `get_haproxy_stats` | Get stats socket data |
| `get_haproxy_info` | Get process info |
| `get_haproxy_frontends` | Get frontend status |
| `get_haproxy_backends` | Get backend status |
| `get_haproxy_servers` | Get server health |
| `get_haproxy_stick_tables` | Get stick table contents |
| `get_haproxy_maps` | Get map file contents |
| `get_haproxy_acls` | Get ACL definitions |
| `get_haproxy_ssl_certs` | Get SSL certificate info |
| `get_haproxy_config` | Get parsed config (redacted) |

### Traefik Plugin
**Scope:** `traefik`

| Query | Description |
|-------|-------------|
| `get_traefik_overview` | Get Traefik dashboard data |
| `get_traefik_routers` | Get router configuration |
| `get_traefik_services` | Get service status |
| `get_traefik_middlewares` | Get middleware list |
| `get_traefik_entrypoints` | Get entrypoint config |
| `get_traefik_tls_stores` | Get TLS store info |
| `get_traefik_providers` | Get provider status |

### Caddy Plugin
**Scope:** `caddy`

| Query | Description |
|-------|-------------|
| `get_caddy_config` | Get current configuration |
| `get_caddy_status` | Get server status |
| `get_caddy_certificates` | Get managed certificates |
| `get_caddy_reverse_proxies` | Get upstream status |
| `get_caddy_logs` | Get recent logs |

---

## Load Balancers & Traffic Management

### F5 BIG-IP Plugin
**Scope:** `f5`

| Query | Description |
|-------|-------------|
| `get_f5_system_info` | Get device version and HA status |
| `get_f5_virtual_servers` | Get virtual server list and status |
| `get_f5_pools` | Get pool member health |
| `get_f5_nodes` | Get node status |
| `get_f5_profiles` | Get profile configuration |
| `get_f5_irules` | Get iRule list |
| `get_f5_ssl_certs` | Get SSL certificate info |
| `get_f5_partitions` | Get partition list |
| `get_f5_routes` | Get routing table |
| `get_f5_vlans` | Get VLAN configuration |
| `get_f5_self_ips` | Get self IP list |
| `get_f5_traffic_stats` | Get traffic statistics |
| `get_f5_gtm_wideips` | Get GTM wide IP status |
| `get_f5_ltm_policies` | Get LTM policy config |
| `get_f5_asm_policies` | Get ASM (WAF) policy status |

### Citrix NetScaler/ADC Plugin
**Scope:** `netscaler`

| Query | Description |
|-------|-------------|
| `get_netscaler_system` | Get system info and HA status |
| `get_netscaler_vservers` | Get virtual server status |
| `get_netscaler_services` | Get service status |
| `get_netscaler_servicegroups` | Get service group members |
| `get_netscaler_lbmonitors` | Get monitor status |
| `get_netscaler_ssl_certs` | Get SSL certificate list |
| `get_netscaler_gslb_sites` | Get GSLB site status |
| `get_netscaler_gslb_services` | Get GSLB service bindings |
| `get_netscaler_policies` | Get responder/rewrite policies |
| `get_netscaler_aaa` | Get AAA configuration |

### AWS ELB/ALB/NLB Plugin
**Scope:** `aws_elb`

| Query | Description |
|-------|-------------|
| `get_elb_classic_status` | Get Classic ELB health |
| `get_alb_target_groups` | Get ALB target group health |
| `get_alb_listeners` | Get listener configuration |
| `get_alb_rules` | Get listener rule config |
| `get_nlb_target_groups` | Get NLB target health |
| `get_elb_access_logs` | Get access log config |
| `get_elb_attributes` | Get load balancer attributes |

---

## CI/CD Platforms

### Jenkins Plugin
**Scope:** `jenkins`

| Query | Description |
|-------|-------------|
| `get_jenkins_system_info` | Get Jenkins version and config |
| `get_jenkins_nodes` | Get agent node status |
| `get_jenkins_jobs` | Get job list and status |
| `get_jenkins_builds` | Get recent build history |
| `get_jenkins_queue` | Get build queue |
| `get_jenkins_executors` | Get executor usage |
| `get_jenkins_plugins` | Get installed plugins |
| `get_jenkins_credentials` | Get credential metadata (no secrets) |
| `get_jenkins_views` | Get view configuration |
| `get_jenkins_folders` | Get folder structure |
| `get_jenkins_pipeline_status` | Get pipeline stage status |
| `get_jenkins_security_realm` | Get authentication config |

### GitLab CI Plugin
**Scope:** `gitlab_ci`

| Query | Description |
|-------|-------------|
| `get_gitlab_runners` | Get runner status and tags |
| `get_gitlab_pipelines` | Get recent pipeline status |
| `get_gitlab_jobs` | Get job status and artifacts |
| `get_gitlab_environments` | Get environment deployments |
| `get_gitlab_schedules` | Get pipeline schedules |
| `get_gitlab_variables` | Get CI/CD variable metadata |
| `get_gitlab_registry` | Get container registry images |
| `get_gitlab_releases` | Get project releases |

### GitHub Actions Plugin
**Scope:** `github_actions`

| Query | Description |
|-------|-------------|
| `get_gha_workflows` | Get workflow definitions |
| `get_gha_runs` | Get recent workflow runs |
| `get_gha_jobs` | Get job status and steps |
| `get_gha_runners` | Get self-hosted runner status |
| `get_gha_artifacts` | Get workflow artifacts |
| `get_gha_secrets` | Get secret metadata (no values) |
| `get_gha_environments` | Get environment status |
| `get_gha_caches` | Get action cache usage |

### CircleCI Plugin
**Scope:** `circleci`

| Query | Description |
|-------|-------------|
| `get_circleci_projects` | Get followed projects |
| `get_circleci_pipelines` | Get pipeline status |
| `get_circleci_workflows` | Get workflow jobs |
| `get_circleci_insights` | Get test insights |
| `get_circleci_orbs` | Get orb usage |
| `get_circleci_contexts` | Get context metadata |

### ArgoCD Plugin
**Scope:** `argocd`

| Query | Description |
|-------|-------------|
| `get_argocd_applications` | Get application sync status |
| `get_argocd_app_resources` | Get managed resources |
| `get_argocd_projects` | Get project configuration |
| `get_argocd_repos` | Get repository connections |
| `get_argocd_clusters` | Get cluster connections |
| `get_argocd_sync_windows` | Get sync window config |
| `get_argocd_notifications` | Get notification status |

### Spinnaker Plugin
**Scope:** `spinnaker`

| Query | Description |
|-------|-------------|
| `get_spinnaker_applications` | Get application list |
| `get_spinnaker_pipelines` | Get pipeline definitions |
| `get_spinnaker_executions` | Get execution history |
| `get_spinnaker_clusters` | Get deployed clusters |
| `get_spinnaker_server_groups` | Get server group status |
| `get_spinnaker_load_balancers` | Get load balancer info |

---

## Observability & Monitoring

### Prometheus Plugin
**Scope:** `prometheus`

| Query | Description |
|-------|-------------|
| `get_prometheus_config` | Get active configuration |
| `get_prometheus_targets` | Get scrape target health |
| `get_prometheus_rules` | Get alerting/recording rules |
| `get_prometheus_alerts` | Get firing alerts |
| `get_prometheus_tsdb` | Get TSDB statistics |
| `get_prometheus_wal` | Get WAL status |
| `get_prometheus_runtime` | Get runtime info |
| `get_prometheus_build` | Get build information |
| `get_prometheus_flags` | Get command line flags |

### Grafana Plugin
**Scope:** `grafana`

| Query | Description |
|-------|-------------|
| `get_grafana_health` | Get Grafana health status |
| `get_grafana_datasources` | Get datasource list |
| `get_grafana_dashboards` | Get dashboard inventory |
| `get_grafana_alerts` | Get alerting rules |
| `get_grafana_alert_notifications` | Get notification channels |
| `get_grafana_users` | Get user list |
| `get_grafana_orgs` | Get organization list |
| `get_grafana_plugins` | Get installed plugins |
| `get_grafana_annotations` | Get recent annotations |

### Datadog Plugin
**Scope:** `datadog`

| Query | Description |
|-------|-------------|
| `get_datadog_hosts` | Get monitored hosts |
| `get_datadog_metrics` | Get metric metadata |
| `get_datadog_monitors` | Get monitor status |
| `get_datadog_downtimes` | Get scheduled downtimes |
| `get_datadog_synthetics` | Get synthetic test results |
| `get_datadog_slos` | Get SLO status |
| `get_datadog_dashboards` | Get dashboard list |
| `get_datadog_logs_indexes` | Get log index config |
| `get_datadog_events` | Get recent events |

### New Relic Plugin
**Scope:** `newrelic`

| Query | Description |
|-------|-------------|
| `get_newrelic_applications` | Get APM applications |
| `get_newrelic_hosts` | Get infrastructure hosts |
| `get_newrelic_alerts` | Get alert policies |
| `get_newrelic_incidents` | Get active incidents |
| `get_newrelic_synthetics` | Get synthetic monitors |
| `get_newrelic_dashboards` | Get dashboard inventory |
| `get_newrelic_nrql_results` | Run NRQL query |
| `get_newrelic_workloads` | Get workload health |

### Splunk Plugin
**Scope:** `splunk`

| Query | Description |
|-------|-------------|
| `get_splunk_server_info` | Get server status |
| `get_splunk_indexes` | Get index inventory |
| `get_splunk_search_jobs` | Get running searches |
| `get_splunk_saved_searches` | Get saved search list |
| `get_splunk_alerts` | Get triggered alerts |
| `get_splunk_inputs` | Get data input config |
| `get_splunk_forwarders` | Get forwarder status |
| `get_splunk_license` | Get license usage |
| `get_splunk_apps` | Get installed apps |
| `get_splunk_clustering` | Get cluster status |

### Nagios/Icinga Plugin
**Scope:** `nagios`

| Query | Description |
|-------|-------------|
| `get_nagios_hosts` | Get host status |
| `get_nagios_services` | Get service status |
| `get_nagios_problems` | Get current problems |
| `get_nagios_downtimes` | Get scheduled downtimes |
| `get_nagios_comments` | Get host/service comments |
| `get_nagios_history` | Get event history |
| `get_nagios_contacts` | Get contact configuration |
| `get_nagios_commands` | Get check commands |

### Zabbix Plugin
**Scope:** `zabbix`

| Query | Description |
|-------|-------------|
| `get_zabbix_hosts` | Get monitored hosts |
| `get_zabbix_host_groups` | Get host groups |
| `get_zabbix_problems` | Get active problems |
| `get_zabbix_triggers` | Get trigger status |
| `get_zabbix_items` | Get item configuration |
| `get_zabbix_templates` | Get template list |
| `get_zabbix_proxies` | Get proxy status |
| `get_zabbix_maintenance` | Get maintenance windows |

---

## Security & Secrets Management

### HashiCorp Vault Plugin
**Scope:** `vault`

| Query | Description |
|-------|-------------|
| `get_vault_status` | Get seal status and HA mode |
| `get_vault_health` | Get health check status |
| `get_vault_mounts` | Get secret engine mounts |
| `get_vault_auth_methods` | Get auth method list |
| `get_vault_policies` | Get policy list |
| `get_vault_audit_devices` | Get audit device config |
| `get_vault_leases` | Get lease count by path |
| `get_vault_tokens` | Get token accessor list |
| `get_vault_replication` | Get replication status |
| `get_vault_raft_peers` | Get Raft cluster peers |
| `get_vault_pki_certs` | Get PKI certificate list |
| `get_vault_kv_metadata` | Get KV secret metadata (no values) |

### CyberArk Plugin
**Scope:** `cyberark`

| Query | Description |
|-------|-------------|
| `get_cyberark_safes` | Get safe inventory |
| `get_cyberark_accounts` | Get account metadata |
| `get_cyberark_platforms` | Get platform definitions |
| `get_cyberark_ptas_alerts` | Get PTA security alerts |
| `get_cyberark_session_recordings` | Get PSM session list |
| `get_cyberark_cpm_status` | Get CPM status |
| `get_cyberark_pvwa_health` | Get PVWA health |

### AWS Secrets Manager Plugin
**Scope:** `aws_secrets`

| Query | Description |
|-------|-------------|
| `get_aws_secrets_list` | Get secret metadata list |
| `get_aws_secret_rotation` | Get rotation status |
| `get_aws_secret_policy` | Get resource policy |
| `get_aws_secret_versions` | Get version history |

### Azure Key Vault Plugin
**Scope:** `azure_keyvault`

| Query | Description |
|-------|-------------|
| `get_keyvault_secrets` | Get secret metadata |
| `get_keyvault_keys` | Get key metadata |
| `get_keyvault_certificates` | Get certificate info |
| `get_keyvault_access_policies` | Get access policies |
| `get_keyvault_audit_logs` | Get audit events |

---

## Identity & Access Management

### Okta Plugin
**Scope:** `okta`

| Query | Description |
|-------|-------------|
| `get_okta_users` | Get user directory |
| `get_okta_groups` | Get group memberships |
| `get_okta_applications` | Get app assignments |
| `get_okta_policies` | Get authentication policies |
| `get_okta_factors` | Get MFA enrollments |
| `get_okta_system_log` | Get system log events |
| `get_okta_api_tokens` | Get API token metadata |
| `get_okta_identity_providers` | Get IdP configuration |

### Active Directory Plugin
**Scope:** `activedirectory`

| Query | Description |
|-------|-------------|
| `get_ad_domain_info` | Get domain/forest info |
| `get_ad_domain_controllers` | Get DC health |
| `get_ad_users` | Get user accounts |
| `get_ad_groups` | Get security groups |
| `get_ad_computers` | Get computer accounts |
| `get_ad_ous` | Get OU structure |
| `get_ad_gpos` | Get Group Policy objects |
| `get_ad_trusts` | Get domain trusts |
| `get_ad_replication` | Get replication status |
| `get_ad_dns_zones` | Get DNS zone config |
| `get_ad_privileged_groups` | Get privileged group members |
| `get_ad_locked_accounts` | Get locked accounts |
| `get_ad_password_policy` | Get password policies |
| `get_ad_certificate_services` | Get AD CS status |

### LDAP Plugin
**Scope:** `ldap`

| Query | Description |
|-------|-------------|
| `get_ldap_root_dse` | Get server capabilities |
| `get_ldap_schema` | Get schema information |
| `get_ldap_naming_contexts` | Get naming contexts |
| `get_ldap_replication` | Get replication status |
| `get_ldap_statistics` | Get server statistics |

### Keycloak Plugin
**Scope:** `keycloak`

| Query | Description |
|-------|-------------|
| `get_keycloak_realms` | Get realm list |
| `get_keycloak_clients` | Get client applications |
| `get_keycloak_users` | Get user directory |
| `get_keycloak_groups` | Get group hierarchy |
| `get_keycloak_roles` | Get role definitions |
| `get_keycloak_identity_providers` | Get IdP config |
| `get_keycloak_client_scopes` | Get OAuth scopes |
| `get_keycloak_events` | Get login events |
| `get_keycloak_sessions` | Get active sessions |

### Auth0 Plugin
**Scope:** `auth0`

| Query | Description |
|-------|-------------|
| `get_auth0_clients` | Get application list |
| `get_auth0_connections` | Get identity providers |
| `get_auth0_users` | Get user directory |
| `get_auth0_roles` | Get role definitions |
| `get_auth0_rules` | Get pipeline rules |
| `get_auth0_actions` | Get Actions configuration |
| `get_auth0_logs` | Get authentication logs |
| `get_auth0_anomaly` | Get anomaly detection |

---

## Antivirus & Anti-Malware

### Symantec Endpoint Protection Plugin
**Scope:** `symantec_sep`

| Query | Description |
|-------|-------------|
| `get_sep_server_status` | Get SEPM server status |
| `get_sep_clients` | Get managed client inventory |
| `get_sep_client_status` | Get client protection status |
| `get_sep_definitions` | Get virus definition versions |
| `get_sep_threats` | Get detected threat history |
| `get_sep_scans` | Get scan status and schedules |
| `get_sep_policies` | Get policy assignments |
| `get_sep_groups` | Get group hierarchy |
| `get_sep_quarantine` | Get quarantine contents |
| `get_sep_reports` | Get security report data |
| `get_sep_replication` | Get site replication status |

### McAfee ePO Plugin
**Scope:** `mcafee_epo`

| Query | Description |
|-------|-------------|
| `get_epo_server_info` | Get ePO server status |
| `get_epo_agents` | Get managed agent inventory |
| `get_epo_agent_status` | Get agent communication status |
| `get_epo_dat_versions` | Get DAT file versions |
| `get_epo_engine_versions` | Get engine versions |
| `get_epo_threats` | Get threat event history |
| `get_epo_policies` | Get policy catalog |
| `get_epo_tasks` | Get client task status |
| `get_epo_queries` | Get saved query results |
| `get_epo_tags` | Get system tag assignments |
| `get_epo_rsd` | Get Rogue System Detection |

### Trend Micro Apex One Plugin
**Scope:** `trendmicro_apex`

| Query | Description |
|-------|-------------|
| `get_apex_server_status` | Get Apex One server status |
| `get_apex_agents` | Get agent inventory |
| `get_apex_protection_status` | Get real-time scan status |
| `get_apex_pattern_versions` | Get pattern file versions |
| `get_apex_threats` | Get threat log |
| `get_apex_dlp_incidents` | Get DLP incidents |
| `get_apex_application_control` | Get app control status |
| `get_apex_vulnerability` | Get vulnerability protection |
| `get_apex_policies` | Get policy settings |
| `get_apex_suspicious_objects` | Get suspicious object list |

### Sophos Central Plugin
**Scope:** `sophos`

| Query | Description |
|-------|-------------|
| `get_sophos_endpoints` | Get endpoint inventory |
| `get_sophos_endpoint_status` | Get protection status |
| `get_sophos_alerts` | Get security alerts |
| `get_sophos_threats` | Get threat history |
| `get_sophos_policies` | Get policy assignments |
| `get_sophos_exclusions` | Get scan exclusions |
| `get_sophos_tamper_protection` | Get tamper protection status |
| `get_sophos_web_control` | Get web filtering status |
| `get_sophos_peripheral_control` | Get device control status |
| `get_sophos_firewall` | Get endpoint firewall status |

### Kaspersky Security Center Plugin
**Scope:** `kaspersky_ksc`

| Query | Description |
|-------|-------------|
| `get_ksc_server_status` | Get administration server status |
| `get_ksc_hosts` | Get managed host inventory |
| `get_ksc_protection_status` | Get protection component status |
| `get_ksc_database_versions` | Get database update versions |
| `get_ksc_threats` | Get threat detection history |
| `get_ksc_tasks` | Get task execution status |
| `get_ksc_policies` | Get policy settings |
| `get_ksc_reports` | Get security reports |
| `get_ksc_network_attacks` | Get network attack blocks |
| `get_ksc_vulnerabilities` | Get software vulnerabilities |
| `get_ksc_encryption` | Get disk encryption status |

### ESET PROTECT Plugin
**Scope:** `eset`

| Query | Description |
|-------|-------------|
| `get_eset_server_status` | Get PROTECT server status |
| `get_eset_computers` | Get managed computer list |
| `get_eset_protection_status` | Get module status |
| `get_eset_detections` | Get detection history |
| `get_eset_quarantine` | Get quarantine contents |
| `get_eset_policies` | Get policy configuration |
| `get_eset_tasks` | Get client task status |
| `get_eset_updates` | Get module update status |
| `get_eset_firewall_rules` | Get personal firewall rules |
| `get_eset_web_control` | Get web access rules |

### Bitdefender GravityZone Plugin
**Scope:** `bitdefender_gz`

| Query | Description |
|-------|-------------|
| `get_gz_endpoints` | Get managed endpoint list |
| `get_gz_protection_status` | Get protection status |
| `get_gz_threats` | Get malware detection log |
| `get_gz_quarantine` | Get quarantine items |
| `get_gz_policies` | Get security policies |
| `get_gz_sandbox` | Get sandbox analysis results |
| `get_gz_network_incidents` | Get network attack blocks |
| `get_gz_reports` | Get security reports |
| `get_gz_patch_status` | Get patch management status |
| `get_gz_risk_analytics` | Get endpoint risk scores |

### Windows Defender / Microsoft Defender Plugin
**Scope:** `defender`

| Query | Description |
|-------|-------------|
| `get_defender_status` | Get protection status |
| `get_defender_preferences` | Get configuration preferences |
| `get_defender_threat_history` | Get threat detection history |
| `get_defender_scan_history` | Get scan history |
| `get_defender_definitions` | Get definition versions |
| `get_defender_exclusions` | Get exclusion paths/processes |
| `get_defender_threats_detected` | Get current threats |
| `get_defender_quarantine` | Get quarantine items |
| `get_defender_network_protection` | Get network protection status |
| `get_defender_controlled_folder` | Get controlled folder access |
| `get_defender_attack_surface` | Get ASR rules status |
| `get_defender_exploit_protection` | Get exploit guard settings |

### ClamAV Plugin
**Scope:** `clamav`

| Query | Description |
|-------|-------------|
| `get_clamav_version` | Get ClamAV version |
| `get_clamav_database` | Get signature database info |
| `get_clamav_config` | Get clamd configuration |
| `get_clamav_scan_queue` | Get scan queue status |
| `get_clamav_stats` | Get scanning statistics |
| `get_clamav_logs` | Get recent scan logs |
| `get_freshclam_status` | Get update daemon status |

---

## Endpoint Detection & Response (EDR/XDR)

### CrowdStrike Falcon Plugin
**Scope:** `crowdstrike`

| Query | Description |
|-------|-------------|
| `get_falcon_hosts` | Get managed host inventory |
| `get_falcon_host_details` | Get host sensor details |
| `get_falcon_detections` | Get detection alerts |
| `get_falcon_incidents` | Get security incidents |
| `get_falcon_iocs` | Get IOC matches |
| `get_falcon_prevention_policy` | Get prevention policies |
| `get_falcon_response_policy` | Get response policies |
| `get_falcon_device_control` | Get USB device control |
| `get_falcon_firewall_rules` | Get host firewall rules |
| `get_falcon_spotlight` | Get vulnerability data |
| `get_falcon_discover` | Get asset discovery data |
| `get_falcon_identity` | Get identity protection |
| `get_falcon_overwatch` | Get OverWatch alerts |

### Microsoft Defender for Endpoint Plugin
**Scope:** `mde`

| Query | Description |
|-------|-------------|
| `get_mde_machines` | Get onboarded machines |
| `get_mde_machine_health` | Get machine health status |
| `get_mde_alerts` | Get security alerts |
| `get_mde_incidents` | Get security incidents |
| `get_mde_vulnerabilities` | Get TVM vulnerabilities |
| `get_mde_recommendations` | Get security recommendations |
| `get_mde_software_inventory` | Get software inventory |
| `get_mde_indicators` | Get custom indicators |
| `get_mde_threat_analytics` | Get threat analytics |
| `get_mde_live_response` | Get live response sessions |
| `get_mde_advanced_hunting` | Run advanced hunting query |
| `get_mde_automated_investigation` | Get AIR status |

### SentinelOne Plugin
**Scope:** `sentinelone`

| Query | Description |
|-------|-------------|
| `get_s1_agents` | Get agent inventory |
| `get_s1_agent_details` | Get agent configuration |
| `get_s1_threats` | Get threat detections |
| `get_s1_activities` | Get activity log |
| `get_s1_applications` | Get application inventory |
| `get_s1_exclusions` | Get exclusion rules |
| `get_s1_policies` | Get policy settings |
| `get_s1_groups` | Get group hierarchy |
| `get_s1_sites` | Get site configuration |
| `get_s1_deep_visibility` | Query Deep Visibility |
| `get_s1_ranger` | Get network discovery |
| `get_s1_remote_scripts` | Get script library |

### Carbon Black (VMware) Plugin
**Scope:** `carbonblack`

| Query | Description |
|-------|-------------|
| `get_cb_devices` | Get device inventory |
| `get_cb_device_status` | Get sensor status |
| `get_cb_alerts` | Get security alerts |
| `get_cb_watchlists` | Get watchlist hits |
| `get_cb_processes` | Get process events |
| `get_cb_policies` | Get policy configuration |
| `get_cb_reputation` | Get file reputation |
| `get_cb_usb_devices` | Get USB device events |
| `get_cb_network_events` | Get network connections |
| `get_cb_live_query` | Run OSQuery on endpoints |
| `get_cb_audit_logs` | Get audit trail |

### Cortex XDR (Palo Alto) Plugin
**Scope:** `cortex_xdr`

| Query | Description |
|-------|-------------|
| `get_xdr_endpoints` | Get endpoint inventory |
| `get_xdr_endpoint_status` | Get agent status |
| `get_xdr_incidents` | Get security incidents |
| `get_xdr_alerts` | Get alert details |
| `get_xdr_investigations` | Get investigation status |
| `get_xdr_xql_query` | Run XQL search |
| `get_xdr_response_actions` | Get response action history |
| `get_xdr_policies` | Get security policies |
| `get_xdr_exclusions` | Get exclusion rules |
| `get_xdr_host_isolations` | Get isolated hosts |
| `get_xdr_threat_intel` | Get threat intelligence |

### Cybereason Plugin
**Scope:** `cybereason`

| Query | Description |
|-------|-------------|
| `get_cybereason_sensors` | Get sensor inventory |
| `get_cybereason_malops` | Get MalOp detections |
| `get_cybereason_suspicions` | Get suspicious elements |
| `get_cybereason_machines` | Get machine details |
| `get_cybereason_processes` | Get process tree |
| `get_cybereason_files` | Get file reputation |
| `get_cybereason_connections` | Get network connections |
| `get_cybereason_policies` | Get policy settings |
| `get_cybereason_response` | Get response actions |
| `get_cybereason_hunting` | Get threat hunting queries |

### Elastic Security Plugin
**Scope:** `elastic_security`

| Query | Description |
|-------|-------------|
| `get_elastic_sec_agents` | Get Fleet agents |
| `get_elastic_sec_alerts` | Get detection alerts |
| `get_elastic_sec_rules` | Get detection rules |
| `get_elastic_sec_exceptions` | Get rule exceptions |
| `get_elastic_sec_cases` | Get case management |
| `get_elastic_sec_timeline` | Get investigation timeline |
| `get_elastic_sec_indicators` | Get threat indicators |
| `get_elastic_sec_osquery` | Get OSQuery results |
| `get_elastic_sec_response` | Get response actions |

### Tanium Plugin
**Scope:** `tanium`

| Query | Description |
|-------|-------------|
| `get_tanium_clients` | Get client inventory |
| `get_tanium_questions` | Get saved questions |
| `get_tanium_sensor_results` | Get sensor data |
| `get_tanium_packages` | Get package library |
| `get_tanium_actions` | Get action status |
| `get_tanium_threat_response` | Get TR alerts |
| `get_tanium_comply` | Get compliance status |
| `get_tanium_patch` | Get patch status |
| `get_tanium_asset` | Get asset inventory |
| `get_tanium_discover` | Get unmanaged assets |

---

## Endpoint Protection Platforms (EPP)

### Trellix (formerly FireEye/McAfee) Plugin
**Scope:** `trellix`

| Query | Description |
|-------|-------------|
| `get_trellix_endpoints` | Get managed endpoints |
| `get_trellix_alerts` | Get security alerts |
| `get_trellix_helix` | Get Helix detections |
| `get_trellix_investigations` | Get investigation status |
| `get_trellix_policies` | Get policy configuration |
| `get_trellix_rules` | Get detection rules |
| `get_trellix_intel` | Get threat intelligence |

### Cylance (BlackBerry) Plugin
**Scope:** `cylance`

| Query | Description |
|-------|-------------|
| `get_cylance_devices` | Get device inventory |
| `get_cylance_threats` | Get threat detections |
| `get_cylance_scripts` | Get script control events |
| `get_cylance_policies` | Get protection policies |
| `get_cylance_zones` | Get zone configuration |
| `get_cylance_global_list` | Get global safe/quarantine list |
| `get_cylance_instaquery` | Run InstaQuery search |

### Malwarebytes Plugin
**Scope:** `malwarebytes`

| Query | Description |
|-------|-------------|
| `get_mb_endpoints` | Get endpoint inventory |
| `get_mb_protection_status` | Get protection status |
| `get_mb_detections` | Get threat detections |
| `get_mb_quarantine` | Get quarantine contents |
| `get_mb_policies` | Get policy settings |
| `get_mb_scans` | Get scan history |
| `get_mb_exclusions` | Get exclusion rules |
| `get_mb_software_inventory` | Get software list |

### Webroot Plugin
**Scope:** `webroot`

| Query | Description |
|-------|-------------|
| `get_webroot_endpoints` | Get endpoint inventory |
| `get_webroot_status` | Get protection status |
| `get_webroot_threats` | Get threat history |
| `get_webroot_policies` | Get policy assignments |
| `get_webroot_overrides` | Get policy overrides |
| `get_webroot_groups` | Get group configuration |
| `get_webroot_dns` | Get DNS protection status |

---

## Mobile Device Management (MDM/UEM)

### Microsoft Intune Plugin
**Scope:** `intune`

| Query | Description |
|-------|-------------|
| `get_intune_devices` | Get managed device inventory |
| `get_intune_device_compliance` | Get compliance status |
| `get_intune_device_config` | Get configuration profiles |
| `get_intune_apps` | Get managed app inventory |
| `get_intune_app_protection` | Get app protection policies |
| `get_intune_policies` | Get device policies |
| `get_intune_enrollment` | Get enrollment status |
| `get_intune_autopilot` | Get Autopilot devices |
| `get_intune_scripts` | Get PowerShell script status |
| `get_intune_updates` | Get Windows Update status |
| `get_intune_conditional_access` | Get CA policy status |

### VMware Workspace ONE Plugin
**Scope:** `workspaceone`

| Query | Description |
|-------|-------------|
| `get_ws1_devices` | Get device inventory |
| `get_ws1_device_details` | Get device configuration |
| `get_ws1_compliance` | Get compliance status |
| `get_ws1_profiles` | Get profile assignments |
| `get_ws1_apps` | Get application catalog |
| `get_ws1_smart_groups` | Get smart group membership |
| `get_ws1_tunnel` | Get Tunnel client status |
| `get_ws1_uem_console` | Get console health |
| `get_ws1_intelligence` | Get Intelligence insights |

### Jamf Pro Plugin
**Scope:** `jamf`

| Query | Description |
|-------|-------------|
| `get_jamf_computers` | Get computer inventory |
| `get_jamf_mobile_devices` | Get mobile device list |
| `get_jamf_policies` | Get policy status |
| `get_jamf_profiles` | Get configuration profiles |
| `get_jamf_packages` | Get package deployment |
| `get_jamf_scripts` | Get script status |
| `get_jamf_patch` | Get patch management |
| `get_jamf_smart_groups` | Get smart group membership |
| `get_jamf_extensions` | Get extension attributes |
| `get_jamf_prestage` | Get prestage enrollment |
| `get_jamf_protect` | Get Jamf Protect status |

### MobileIron (Ivanti) Plugin
**Scope:** `mobileiron`

| Query | Description |
|-------|-------------|
| `get_mi_devices` | Get device inventory |
| `get_mi_compliance` | Get compliance status |
| `get_mi_labels` | Get label assignments |
| `get_mi_policies` | Get security policies |
| `get_mi_apps` | Get app catalog |
| `get_mi_certificates` | Get certificate status |
| `get_mi_tunnel` | Get Tunnel status |
| `get_mi_sentry` | Get Sentry gateway status |

### Kandji Plugin
**Scope:** `kandji`

| Query | Description |
|-------|-------------|
| `get_kandji_devices` | Get device inventory |
| `get_kandji_blueprints` | Get blueprint status |
| `get_kandji_library_items` | Get library item deployments |
| `get_kandji_compliance` | Get compliance data |
| `get_kandji_threats` | Get detected threats |
| `get_kandji_laps` | Get LAPS passwords (metadata) |
| `get_kandji_device_actions` | Get action history |

### Google Workspace MDM Plugin
**Scope:** `google_mdm`

| Query | Description |
|-------|-------------|
| `get_google_mobile_devices` | Get mobile device list |
| `get_google_chrome_devices` | Get Chrome OS devices |
| `get_google_device_policies` | Get device policies |
| `get_google_app_management` | Get managed apps |
| `get_google_endpoint_verification` | Get endpoint verification |
| `get_google_context_aware` | Get context-aware access |

### SOTI MobiControl Plugin
**Scope:** `soti`

| Query | Description |
|-------|-------------|
| `get_soti_devices` | Get device inventory |
| `get_soti_profiles` | Get profile assignments |
| `get_soti_packages` | Get package deployments |
| `get_soti_geofences` | Get geofence status |
| `get_soti_alerts` | Get device alerts |
| `get_soti_rules` | Get automation rules |

---

## Data Loss Prevention (DLP)

### Symantec DLP Plugin
**Scope:** `symantec_dlp`

| Query | Description |
|-------|-------------|
| `get_sdlp_servers` | Get detection server status |
| `get_sdlp_incidents` | Get incident list |
| `get_sdlp_policies` | Get policy configuration |
| `get_sdlp_response_rules` | Get response rule status |
| `get_sdlp_agents` | Get endpoint agent status |
| `get_sdlp_discover` | Get Discover scan status |
| `get_sdlp_network_monitor` | Get Network Monitor status |
| `get_sdlp_email_monitor` | Get email inspection status |
| `get_sdlp_reports` | Get DLP reports |
| `get_sdlp_data_profiles` | Get data profile matches |

### Microsoft Purview DLP Plugin
**Scope:** `purview_dlp`

| Query | Description |
|-------|-------------|
| `get_purview_dlp_policies` | Get DLP policy status |
| `get_purview_dlp_alerts` | Get DLP alerts |
| `get_purview_sensitivity_labels` | Get sensitivity labels |
| `get_purview_label_policies` | Get label policy assignments |
| `get_purview_content_explorer` | Get content classification |
| `get_purview_activity_explorer` | Get activity data |
| `get_purview_endpoint_dlp` | Get endpoint DLP status |
| `get_purview_trainable_classifiers` | Get classifier status |
| `get_purview_exact_data_match` | Get EDM schema status |

### Forcepoint DLP Plugin
**Scope:** `forcepoint_dlp`

| Query | Description |
|-------|-------------|
| `get_forcepoint_incidents` | Get incident list |
| `get_forcepoint_policies` | Get policy configuration |
| `get_forcepoint_channels` | Get channel status |
| `get_forcepoint_endpoints` | Get endpoint agent status |
| `get_forcepoint_discovery` | Get discovery scan status |
| `get_forcepoint_fingerprints` | Get fingerprint database |
| `get_forcepoint_reports` | Get DLP reports |

### Digital Guardian Plugin
**Scope:** `digital_guardian`

| Query | Description |
|-------|-------------|
| `get_dg_agents` | Get agent inventory |
| `get_dg_policies` | Get policy configuration |
| `get_dg_events` | Get security events |
| `get_dg_classifications` | Get data classifications |
| `get_dg_rules` | Get control rules |
| `get_dg_incidents` | Get incident list |
| `get_dg_reports` | Get analytics reports |

### Netskope DLP Plugin
**Scope:** `netskope_dlp`

| Query | Description |
|-------|-------------|
| `get_netskope_dlp_policies` | Get DLP policies |
| `get_netskope_dlp_incidents` | Get DLP incidents |
| `get_netskope_dlp_profiles` | Get DLP profiles |
| `get_netskope_file_policies` | Get file policy status |
| `get_netskope_alerts` | Get security alerts |
| `get_netskope_users` | Get user activity |

### Code42 Incydr Plugin
**Scope:** `code42`

| Query | Description |
|-------|-------------|
| `get_incydr_alerts` | Get security alerts |
| `get_incydr_file_events` | Get file activity |
| `get_incydr_users` | Get user risk scores |
| `get_incydr_watchlists` | Get watchlist status |
| `get_incydr_departing` | Get departing employee risk |
| `get_incydr_trusted_activities` | Get trusted activities |
| `get_incydr_actors` | Get actor profiles |

---

## SIEM & Security Analytics

### Splunk Enterprise Security Plugin
**Scope:** `splunk_es`

| Query | Description |
|-------|-------------|
| `get_splunk_es_notable` | Get notable events |
| `get_splunk_es_investigations` | Get investigation status |
| `get_splunk_es_risk` | Get risk scores |
| `get_splunk_es_assets` | Get asset inventory |
| `get_splunk_es_identities` | Get identity information |
| `get_splunk_es_threat_intel` | Get threat intelligence |
| `get_splunk_es_correlation` | Get correlation search status |
| `get_splunk_es_suppressions` | Get suppression rules |
| `get_splunk_es_data_models` | Get data model acceleration |

### Microsoft Sentinel Plugin
**Scope:** `sentinel`

| Query | Description |
|-------|-------------|
| `get_sentinel_incidents` | Get security incidents |
| `get_sentinel_alerts` | Get alert rules |
| `get_sentinel_hunting` | Get hunting queries |
| `get_sentinel_watchlists` | Get watchlist data |
| `get_sentinel_connectors` | Get data connector status |
| `get_sentinel_analytics` | Get analytics rules |
| `get_sentinel_automation` | Get automation rules |
| `get_sentinel_workbooks` | Get workbook status |
| `get_sentinel_notebooks` | Get notebook status |
| `get_sentinel_ti` | Get threat indicators |

### IBM QRadar Plugin
**Scope:** `qradar`

| Query | Description |
|-------|-------------|
| `get_qradar_offenses` | Get offense list |
| `get_qradar_events` | Get event data |
| `get_qradar_flows` | Get flow data |
| `get_qradar_log_sources` | Get log source status |
| `get_qradar_rules` | Get correlation rules |
| `get_qradar_reference_sets` | Get reference set data |
| `get_qradar_asset_model` | Get asset inventory |
| `get_qradar_vulnerability` | Get vulnerability data |
| `get_qradar_reports` | Get report status |

### LogRhythm Plugin
**Scope:** `logrhythm`

| Query | Description |
|-------|-------------|
| `get_lr_alarms` | Get alarm list |
| `get_lr_cases` | Get case status |
| `get_lr_events` | Get log events |
| `get_lr_ai_engine` | Get AI Engine rules |
| `get_lr_log_sources` | Get log source health |
| `get_lr_entities` | Get entity data |
| `get_lr_lists` | Get list contents |
| `get_lr_playbooks` | Get playbook status |

### Exabeam Plugin
**Scope:** `exabeam`

| Query | Description |
|-------|-------------|
| `get_exabeam_incidents` | Get incident queue |
| `get_exabeam_notable` | Get notable users |
| `get_exabeam_timelines` | Get user timelines |
| `get_exabeam_watchlists` | Get watchlist members |
| `get_exabeam_rules` | Get correlation rules |
| `get_exabeam_models` | Get ML model status |
| `get_exabeam_data_lake` | Get Data Lake queries |
| `get_exabeam_parsers` | Get parser status |

### Securonix Plugin
**Scope:** `securonix`

| Query | Description |
|-------|-------------|
| `get_securonix_incidents` | Get incident list |
| `get_securonix_violations` | Get policy violations |
| `get_securonix_threats` | Get threat indicators |
| `get_securonix_watchlists` | Get watchlist status |
| `get_securonix_lookup` | Get lookup table data |
| `get_securonix_activity` | Get activity data |
| `get_securonix_risk` | Get risk scores |

### Sumo Logic Plugin
**Scope:** `sumologic`

| Query | Description |
|-------|-------------|
| `get_sumo_collectors` | Get collector status |
| `get_sumo_sources` | Get source configuration |
| `get_sumo_scheduled_views` | Get scheduled view status |
| `get_sumo_content` | Get content library |
| `get_sumo_cse_insights` | Get Cloud SIEM insights |
| `get_sumo_cse_signals` | Get signal data |
| `get_sumo_cse_entities` | Get entity inventory |

### Chronicle (Google) Plugin
**Scope:** `chronicle`

| Query | Description |
|-------|-------------|
| `get_chronicle_alerts` | Get security alerts |
| `get_chronicle_iocs` | Get IOC matches |
| `get_chronicle_assets` | Get asset data |
| `get_chronicle_events` | Get UDM events |
| `get_chronicle_rules` | Get YARA-L rules |
| `get_chronicle_reference_lists` | Get reference list data |
| `get_chronicle_retrohunts` | Get retrohunt status |

### Wazuh Plugin
**Scope:** `wazuh`

| Query | Description |
|-------|-------------|
| `get_wazuh_agents` | Get agent inventory |
| `get_wazuh_agent_status` | Get agent health |
| `get_wazuh_alerts` | Get security alerts |
| `get_wazuh_rules` | Get ruleset |
| `get_wazuh_decoders` | Get decoder list |
| `get_wazuh_sca` | Get SCA results |
| `get_wazuh_fim` | Get FIM events |
| `get_wazuh_vulnerability` | Get vulnerability data |
| `get_wazuh_syscollector` | Get inventory data |
| `get_wazuh_rootcheck` | Get rootkit detection |

---

## Networking & Firewalls

### Cisco IOS/IOS-XE Plugin
**Scope:** `cisco_ios`

| Query | Description |
|-------|-------------|
| `get_cisco_version` | Get IOS version |
| `get_cisco_interfaces` | Get interface status |
| `get_cisco_ip_route` | Get routing table |
| `get_cisco_arp` | Get ARP cache |
| `get_cisco_cdp_neighbors` | Get CDP neighbors |
| `get_cisco_lldp_neighbors` | Get LLDP neighbors |
| `get_cisco_bgp_summary` | Get BGP peer status |
| `get_cisco_ospf_neighbors` | Get OSPF neighbors |
| `get_cisco_eigrp_neighbors` | Get EIGRP neighbors |
| `get_cisco_spanning_tree` | Get STP status |
| `get_cisco_vlans` | Get VLAN database |
| `get_cisco_port_security` | Get port security status |
| `get_cisco_acls` | Get access list config |
| `get_cisco_cpu_memory` | Get CPU/memory utilization |
| `get_cisco_environment` | Get power/fan/temp |

### Palo Alto Networks Plugin
**Scope:** `paloalto`

| Query | Description |
|-------|-------------|
| `get_paloalto_system_info` | Get system/HA status |
| `get_paloalto_interfaces` | Get interface status |
| `get_paloalto_zones` | Get security zones |
| `get_paloalto_policies` | Get security policies |
| `get_paloalto_nat_rules` | Get NAT rules |
| `get_paloalto_address_objects` | Get address objects |
| `get_paloalto_service_objects` | Get service objects |
| `get_paloalto_url_filtering` | Get URL filtering profile |
| `get_paloalto_threats` | Get threat logs |
| `get_paloalto_traffic_logs` | Get traffic logs |
| `get_paloalto_globalprotect` | Get GP portal/gateway |
| `get_paloalto_sessions` | Get active sessions |
| `get_paloalto_arp` | Get ARP table |
| `get_paloalto_routes` | Get routing table |

### Fortinet FortiGate Plugin
**Scope:** `fortigate`

| Query | Description |
|-------|-------------|
| `get_fortigate_system_status` | Get system/HA status |
| `get_fortigate_interfaces` | Get interface status |
| `get_fortigate_policies` | Get firewall policies |
| `get_fortigate_addresses` | Get address objects |
| `get_fortigate_services` | Get service objects |
| `get_fortigate_ips_signatures` | Get IPS signature status |
| `get_fortigate_av_signatures` | Get AV signature status |
| `get_fortigate_vpn_ipsec` | Get IPSec tunnel status |
| `get_fortigate_vpn_ssl` | Get SSL VPN sessions |
| `get_fortigate_sessions` | Get session table |
| `get_fortigate_routes` | Get routing table |
| `get_fortigate_sdwan` | Get SD-WAN status |

### Juniper Junos Plugin
**Scope:** `junos`

| Query | Description |
|-------|-------------|
| `get_junos_version` | Get Junos version |
| `get_junos_interfaces` | Get interface status |
| `get_junos_routes` | Get routing table |
| `get_junos_bgp_summary` | Get BGP peer status |
| `get_junos_ospf_neighbors` | Get OSPF neighbors |
| `get_junos_chassis` | Get chassis status |
| `get_junos_alarms` | Get system alarms |
| `get_junos_security_policies` | Get SRX policies |
| `get_junos_nat` | Get NAT configuration |
| `get_junos_ipsec_sa` | Get IPSec SAs |
| `get_junos_lldp_neighbors` | Get LLDP neighbors |

### pfSense/OPNsense Plugin
**Scope:** `pfsense`

| Query | Description |
|-------|-------------|
| `get_pfsense_system` | Get system info |
| `get_pfsense_interfaces` | Get interface status |
| `get_pfsense_gateways` | Get gateway status |
| `get_pfsense_firewall_rules` | Get filter rules |
| `get_pfsense_nat_rules` | Get NAT/port forwards |
| `get_pfsense_dhcp_leases` | Get DHCP leases |
| `get_pfsense_openvpn` | Get OpenVPN status |
| `get_pfsense_ipsec` | Get IPSec status |
| `get_pfsense_services` | Get service status |
| `get_pfsense_traffic_shaper` | Get traffic shaping |

---

## Storage Systems

### NetApp ONTAP Plugin
**Scope:** `netapp`

| Query | Description |
|-------|-------------|
| `get_netapp_cluster_info` | Get cluster health |
| `get_netapp_nodes` | Get node status |
| `get_netapp_aggregates` | Get aggregate capacity |
| `get_netapp_volumes` | Get volume status |
| `get_netapp_luns` | Get LUN inventory |
| `get_netapp_qtrees` | Get qtree list |
| `get_netapp_snapshots` | Get snapshot schedule |
| `get_netapp_snapmirror` | Get SnapMirror status |
| `get_netapp_cifs_shares` | Get CIFS shares |
| `get_netapp_nfs_exports` | Get NFS exports |
| `get_netapp_iscsi_sessions` | Get iSCSI sessions |
| `get_netapp_fc_ports` | Get FC port status |
| `get_netapp_network_ports` | Get network ports |
| `get_netapp_cluster_peers` | Get cluster peers |

### Dell EMC PowerStore Plugin
**Scope:** `powerstore`

| Query | Description |
|-------|-------------|
| `get_powerstore_cluster` | Get cluster info |
| `get_powerstore_appliances` | Get appliance status |
| `get_powerstore_volumes` | Get volume list |
| `get_powerstore_volume_groups` | Get volume groups |
| `get_powerstore_hosts` | Get host mappings |
| `get_powerstore_replication` | Get replication sessions |
| `get_powerstore_snapshots` | Get snapshot policies |
| `get_powerstore_file_systems` | Get NAS file systems |
| `get_powerstore_alerts` | Get active alerts |

### Pure Storage Plugin
**Scope:** `purestorage`

| Query | Description |
|-------|-------------|
| `get_pure_array_info` | Get array status |
| `get_pure_volumes` | Get volume inventory |
| `get_pure_hosts` | Get host connections |
| `get_pure_host_groups` | Get host groups |
| `get_pure_protection_groups` | Get protection groups |
| `get_pure_snapshots` | Get snapshot list |
| `get_pure_replication` | Get replication status |
| `get_pure_network` | Get network config |
| `get_pure_alerts` | Get active alerts |
| `get_pure_capacity` | Get capacity metrics |

### MinIO Plugin
**Scope:** `minio`

| Query | Description |
|-------|-------------|
| `get_minio_server_info` | Get server status |
| `get_minio_buckets` | Get bucket list |
| `get_minio_bucket_policy` | Get bucket policies |
| `get_minio_users` | Get IAM users |
| `get_minio_policies` | Get IAM policies |
| `get_minio_service_accounts` | Get service accounts |
| `get_minio_replication` | Get bucket replication |
| `get_minio_lifecycle` | Get lifecycle rules |
| `get_minio_notifications` | Get event notifications |
| `get_minio_healing` | Get healing status |

### Ceph Plugin
**Scope:** `ceph`

| Query | Description |
|-------|-------------|
| `get_ceph_status` | Get cluster health |
| `get_ceph_osd_tree` | Get OSD topology |
| `get_ceph_osd_status` | Get OSD status |
| `get_ceph_pools` | Get pool statistics |
| `get_ceph_pg_status` | Get PG distribution |
| `get_ceph_mon_status` | Get monitor quorum |
| `get_ceph_mds_status` | Get MDS status |
| `get_ceph_rgw_status` | Get RadosGW status |
| `get_ceph_crush_map` | Get CRUSH rules |
| `get_ceph_df` | Get capacity usage |

---

## Virtualization Platforms

### VMware vSphere Plugin
**Scope:** `vsphere`

| Query | Description |
|-------|-------------|
| `get_vcenter_info` | Get vCenter version/status |
| `get_vsphere_datacenters` | Get datacenter list |
| `get_vsphere_clusters` | Get cluster inventory |
| `get_vsphere_hosts` | Get ESXi host status |
| `get_vsphere_vms` | Get VM inventory |
| `get_vsphere_vm_snapshots` | Get VM snapshots |
| `get_vsphere_datastores` | Get datastore capacity |
| `get_vsphere_networks` | Get network inventory |
| `get_vsphere_distributed_switches` | Get VDS config |
| `get_vsphere_resource_pools` | Get resource pools |
| `get_vsphere_templates` | Get VM templates |
| `get_vsphere_alarms` | Get triggered alarms |
| `get_vsphere_events` | Get recent events |
| `get_vsphere_tasks` | Get recent tasks |
| `get_vsphere_licenses` | Get license status |
| `get_vsphere_vsan_status` | Get vSAN health |
| `get_vsphere_nsx_status` | Get NSX integration |

### Microsoft Hyper-V Plugin
**Scope:** `hyperv`

| Query | Description |
|-------|-------------|
| `get_hyperv_hosts` | Get Hyper-V host status |
| `get_hyperv_vms` | Get VM inventory |
| `get_hyperv_vm_snapshots` | Get VM checkpoints |
| `get_hyperv_virtual_switches` | Get virtual switch config |
| `get_hyperv_virtual_disks` | Get VHD/VHDX list |
| `get_hyperv_replication` | Get Hyper-V Replica status |
| `get_hyperv_cluster` | Get failover cluster status |
| `get_hyperv_storage` | Get CSV status |
| `get_hyperv_network_adapters` | Get VM network adapters |

### Proxmox VE Plugin
**Scope:** `proxmox`

| Query | Description |
|-------|-------------|
| `get_proxmox_cluster_status` | Get cluster health |
| `get_proxmox_nodes` | Get node status |
| `get_proxmox_vms` | Get QEMU VMs |
| `get_proxmox_containers` | Get LXC containers |
| `get_proxmox_storage` | Get storage pools |
| `get_proxmox_networks` | Get network config |
| `get_proxmox_pools` | Get resource pools |
| `get_proxmox_ha_status` | Get HA manager status |
| `get_proxmox_tasks` | Get recent tasks |
| `get_proxmox_backups` | Get backup jobs |
| `get_proxmox_ceph_status` | Get Ceph integration |

### KVM/libvirt Plugin
**Scope:** `libvirt`

| Query | Description |
|-------|-------------|
| `get_libvirt_domains` | Get VM list and state |
| `get_libvirt_domain_info` | Get VM configuration |
| `get_libvirt_networks` | Get virtual networks |
| `get_libvirt_storage_pools` | Get storage pools |
| `get_libvirt_volumes` | Get storage volumes |
| `get_libvirt_interfaces` | Get host interfaces |
| `get_libvirt_node_info` | Get hypervisor info |
| `get_libvirt_capabilities` | Get host capabilities |

---

## Backup & Disaster Recovery

### Veeam Plugin
**Scope:** `veeam`

| Query | Description |
|-------|-------------|
| `get_veeam_jobs` | Get backup job status |
| `get_veeam_sessions` | Get recent sessions |
| `get_veeam_repositories` | Get repository capacity |
| `get_veeam_proxies` | Get proxy status |
| `get_veeam_protected_vms` | Get protected VM list |
| `get_veeam_restore_points` | Get restore point inventory |
| `get_veeam_replica_jobs` | Get replication status |
| `get_veeam_tape_jobs` | Get tape job status |
| `get_veeam_cloud_connect` | Get Cloud Connect status |
| `get_veeam_surebackup` | Get SureBackup results |
| `get_veeam_licensing` | Get license usage |

### Veritas NetBackup Plugin
**Scope:** `netbackup`

| Query | Description |
|-------|-------------|
| `get_netbackup_jobs` | Get job activity |
| `get_netbackup_policies` | Get policy status |
| `get_netbackup_clients` | Get client status |
| `get_netbackup_images` | Get backup images |
| `get_netbackup_media_servers` | Get media server status |
| `get_netbackup_storage_units` | Get storage unit capacity |
| `get_netbackup_disk_pools` | Get disk pool status |
| `get_netbackup_tape_drives` | Get tape drive status |
| `get_netbackup_alerts` | Get active alerts |

### Commvault Plugin
**Scope:** `commvault`

| Query | Description |
|-------|-------------|
| `get_commvault_jobs` | Get job status |
| `get_commvault_clients` | Get client inventory |
| `get_commvault_subclients` | Get subclient config |
| `get_commvault_storage_policies` | Get storage policies |
| `get_commvault_media_agents` | Get MA status |
| `get_commvault_libraries` | Get library inventory |
| `get_commvault_schedules` | Get schedule status |
| `get_commvault_alerts` | Get alert history |

### Cohesity Plugin
**Scope:** `cohesity`

| Query | Description |
|-------|-------------|
| `get_cohesity_cluster` | Get cluster health |
| `get_cohesity_nodes` | Get node status |
| `get_cohesity_protection_jobs` | Get job status |
| `get_cohesity_protection_sources` | Get source inventory |
| `get_cohesity_views` | Get view list |
| `get_cohesity_storage_domains` | Get storage domain stats |
| `get_cohesity_restore_tasks` | Get restore history |
| `get_cohesity_alerts` | Get active alerts |

### AWS Backup Plugin
**Scope:** `aws_backup`

| Query | Description |
|-------|-------------|
| `get_aws_backup_vaults` | Get backup vault list |
| `get_aws_backup_plans` | Get backup plan config |
| `get_aws_backup_jobs` | Get recent job status |
| `get_aws_backup_recovery_points` | Get recovery point list |
| `get_aws_backup_protected_resources` | Get protected resources |

---

## Service Mesh

### Istio Plugin
**Scope:** `istio`

| Query | Description |
|-------|-------------|
| `get_istio_version` | Get Istio version |
| `get_istio_proxy_status` | Get Envoy sidecar sync |
| `get_istio_virtual_services` | Get traffic routing |
| `get_istio_destination_rules` | Get load balancing config |
| `get_istio_gateways` | Get ingress/egress gateways |
| `get_istio_service_entries` | Get external services |
| `get_istio_sidecars` | Get sidecar config |
| `get_istio_peer_authentication` | Get mTLS status |
| `get_istio_authorization_policies` | Get authz policies |
| `get_istio_request_authentication` | Get JWT validation |
| `get_istio_telemetry` | Get telemetry config |
| `get_istio_envoy_config` | Get Envoy configuration |

### Linkerd Plugin
**Scope:** `linkerd`

| Query | Description |
|-------|-------------|
| `get_linkerd_version` | Get Linkerd version |
| `get_linkerd_check` | Get control plane health |
| `get_linkerd_stat` | Get traffic statistics |
| `get_linkerd_routes` | Get service routes |
| `get_linkerd_edges` | Get service dependencies |
| `get_linkerd_tap` | Get live traffic sample |
| `get_linkerd_profiles` | Get service profiles |
| `get_linkerd_multicluster` | Get multicluster links |

### Consul Connect Plugin
**Scope:** `consul`

| Query | Description |
|-------|-------------|
| `get_consul_members` | Get cluster members |
| `get_consul_services` | Get service catalog |
| `get_consul_health` | Get service health |
| `get_consul_kv` | Get KV metadata |
| `get_consul_acls` | Get ACL tokens/policies |
| `get_consul_intentions` | Get Connect intentions |
| `get_consul_config_entries` | Get service defaults |
| `get_consul_connect_proxies` | Get proxy status |
| `get_consul_mesh_gateways` | Get mesh gateway status |

---

## Serverless Platforms

### AWS Lambda Plugin
**Scope:** `lambda`

| Query | Description |
|-------|-------------|
| `get_lambda_functions` | Get function inventory |
| `get_lambda_function_config` | Get function configuration |
| `get_lambda_aliases` | Get function aliases |
| `get_lambda_versions` | Get function versions |
| `get_lambda_layers` | Get layer usage |
| `get_lambda_event_sources` | Get event source mappings |
| `get_lambda_concurrency` | Get concurrency settings |
| `get_lambda_metrics` | Get invocation metrics |
| `get_lambda_logs` | Get recent CloudWatch logs |

### Azure Functions Plugin
**Scope:** `azure_functions`

| Query | Description |
|-------|-------------|
| `get_azfunc_apps` | Get Function App list |
| `get_azfunc_functions` | Get function inventory |
| `get_azfunc_bindings` | Get trigger/binding config |
| `get_azfunc_slots` | Get deployment slots |
| `get_azfunc_keys` | Get function key metadata |
| `get_azfunc_metrics` | Get execution metrics |
| `get_azfunc_logs` | Get Application Insights logs |

### Google Cloud Functions Plugin
**Scope:** `gcf`

| Query | Description |
|-------|-------------|
| `get_gcf_functions` | Get function inventory |
| `get_gcf_config` | Get function configuration |
| `get_gcf_triggers` | Get event triggers |
| `get_gcf_metrics` | Get execution metrics |
| `get_gcf_logs` | Get Cloud Logging entries |

### Knative Plugin
**Scope:** `knative`

| Query | Description |
|-------|-------------|
| `get_knative_services` | Get Knative services |
| `get_knative_revisions` | Get service revisions |
| `get_knative_routes` | Get traffic split |
| `get_knative_configurations` | Get config status |
| `get_knative_triggers` | Get eventing triggers |
| `get_knative_brokers` | Get event brokers |
| `get_knative_sources` | Get event sources |

---

## CDN & Edge Computing

### Cloudflare Plugin
**Scope:** `cloudflare`

| Query | Description |
|-------|-------------|
| `get_cloudflare_zones` | Get zone inventory |
| `get_cloudflare_dns` | Get DNS records |
| `get_cloudflare_ssl` | Get SSL/TLS settings |
| `get_cloudflare_firewall_rules` | Get WAF rules |
| `get_cloudflare_rate_limits` | Get rate limiting |
| `get_cloudflare_page_rules` | Get page rules |
| `get_cloudflare_workers` | Get Workers config |
| `get_cloudflare_analytics` | Get traffic analytics |
| `get_cloudflare_cache_status` | Get cache statistics |
| `get_cloudflare_argo` | Get Argo status |
| `get_cloudflare_access` | Get Access policies |
| `get_cloudflare_spectrum` | Get Spectrum apps |

### Akamai Plugin
**Scope:** `akamai`

| Query | Description |
|-------|-------------|
| `get_akamai_properties` | Get property config |
| `get_akamai_hostnames` | Get edge hostnames |
| `get_akamai_certificates` | Get SSL certificates |
| `get_akamai_rules` | Get delivery rules |
| `get_akamai_behaviors` | Get caching behaviors |
| `get_akamai_origins` | Get origin config |
| `get_akamai_waf_policies` | Get WAF policies |
| `get_akamai_bot_manager` | Get bot detection |
| `get_akamai_traffic` | Get traffic reports |
| `get_akamai_errors` | Get error reports |

### Fastly Plugin
**Scope:** `fastly`

| Query | Description |
|-------|-------------|
| `get_fastly_services` | Get service config |
| `get_fastly_domains` | Get domain list |
| `get_fastly_backends` | Get origin backends |
| `get_fastly_vcl` | Get VCL snippets |
| `get_fastly_dictionaries` | Get edge dictionaries |
| `get_fastly_acls` | Get access control lists |
| `get_fastly_tls` | Get TLS configuration |
| `get_fastly_realtime_stats` | Get realtime metrics |
| `get_fastly_historical_stats` | Get historical data |
| `get_fastly_waf` | Get WAF status |

---

## APM & Distributed Tracing

### Dynatrace Plugin
**Scope:** `dynatrace`

| Query | Description |
|-------|-------------|
| `get_dynatrace_hosts` | Get monitored hosts |
| `get_dynatrace_processes` | Get process groups |
| `get_dynatrace_services` | Get service inventory |
| `get_dynatrace_applications` | Get RUM applications |
| `get_dynatrace_problems` | Get active problems |
| `get_dynatrace_events` | Get event feed |
| `get_dynatrace_synthetic` | Get synthetic monitors |
| `get_dynatrace_smartscape` | Get topology map |
| `get_dynatrace_slos` | Get SLO status |
| `get_dynatrace_davis` | Get AI insights |

### AppDynamics Plugin
**Scope:** `appdynamics`

| Query | Description |
|-------|-------------|
| `get_appd_applications` | Get application list |
| `get_appd_tiers` | Get application tiers |
| `get_appd_nodes` | Get node inventory |
| `get_appd_business_transactions` | Get BT list |
| `get_appd_backends` | Get backend services |
| `get_appd_health_rules` | Get health rule status |
| `get_appd_events` | Get event stream |
| `get_appd_errors` | Get error analytics |
| `get_appd_snapshots` | Get transaction snapshots |
| `get_appd_dashboards` | Get custom dashboards |

### Elastic APM Plugin
**Scope:** `elastic_apm`

| Query | Description |
|-------|-------------|
| `get_apm_services` | Get service inventory |
| `get_apm_transactions` | Get transaction types |
| `get_apm_spans` | Get span breakdown |
| `get_apm_errors` | Get error groups |
| `get_apm_metrics` | Get service metrics |
| `get_apm_service_map` | Get dependency map |
| `get_apm_anomalies` | Get ML anomalies |
| `get_apm_correlations` | Get failure correlations |

### Jaeger Plugin
**Scope:** `jaeger`

| Query | Description |
|-------|-------------|
| `get_jaeger_services` | Get service list |
| `get_jaeger_operations` | Get operations |
| `get_jaeger_traces` | Search traces |
| `get_jaeger_dependencies` | Get dependency DAG |
| `get_jaeger_spans` | Get span details |

### Zipkin Plugin
**Scope:** `zipkin`

| Query | Description |
|-------|-------------|
| `get_zipkin_services` | Get service list |
| `get_zipkin_spans` | Get span names |
| `get_zipkin_traces` | Search traces |
| `get_zipkin_dependencies` | Get dependency links |

---

## Log Management

### Elastic Stack (ELK) Plugin
**Scope:** `elk`

| Query | Description |
|-------|-------------|
| `get_elk_cluster_health` | Get cluster health |
| `get_elk_indices` | Get index list |
| `get_elk_data_streams` | Get data streams |
| `get_elk_ilm_policies` | Get ILM policies |
| `get_elk_transforms` | Get transform jobs |
| `get_elk_ingest_pipelines` | Get ingest pipelines |
| `get_elk_beats` | Get Beats agent status |
| `get_elk_logstash` | Get Logstash pipelines |
| `get_elk_fleet` | Get Fleet agents |

### Loki Plugin
**Scope:** `loki`

| Query | Description |
|-------|-------------|
| `get_loki_ready` | Get readiness status |
| `get_loki_config` | Get runtime config |
| `get_loki_series` | Get label series |
| `get_loki_labels` | Get label names |
| `get_loki_label_values` | Get label values |
| `get_loki_rules` | Get alerting rules |
| `get_loki_ring` | Get distributor ring |
| `get_loki_compactor` | Get compactor status |

### Fluentd/Fluent Bit Plugin
**Scope:** `fluentd`

| Query | Description |
|-------|-------------|
| `get_fluentd_config` | Get configuration |
| `get_fluentd_plugins` | Get loaded plugins |
| `get_fluentd_buffer_status` | Get buffer queue |
| `get_fluentd_metrics` | Get performance metrics |
| `get_fluentbit_health` | Get Fluent Bit health |
| `get_fluentbit_upstreams` | Get output status |
| `get_fluentbit_storage` | Get storage metrics |

### Vector Plugin
**Scope:** `vector`

| Query | Description |
|-------|-------------|
| `get_vector_health` | Get health status |
| `get_vector_graph` | Get pipeline graph |
| `get_vector_sources` | Get source status |
| `get_vector_transforms` | Get transform status |
| `get_vector_sinks` | Get sink status |
| `get_vector_metrics` | Get internal metrics |

---

## Configuration Management

### Ansible Plugin
**Scope:** `ansible`

| Query | Description |
|-------|-------------|
| `get_ansible_inventory` | Get host inventory |
| `get_ansible_playbooks` | Get playbook list |
| `get_ansible_roles` | Get role list |
| `get_ansible_collections` | Get installed collections |
| `get_ansible_tower_jobs` | Get AWX/Tower job status |
| `get_ansible_tower_templates` | Get job templates |
| `get_ansible_tower_inventories` | Get Tower inventories |
| `get_ansible_tower_projects` | Get project status |

### Puppet Plugin
**Scope:** `puppet`

| Query | Description |
|-------|-------------|
| `get_puppet_nodes` | Get node inventory |
| `get_puppet_reports` | Get recent reports |
| `get_puppet_facts` | Get node facts |
| `get_puppet_classes` | Get class assignments |
| `get_puppet_environments` | Get environments |
| `get_puppet_modules` | Get installed modules |
| `get_puppet_pe_services` | Get PE service status |
| `get_puppet_pdb_status` | Get PuppetDB status |

### Chef Plugin
**Scope:** `chef`

| Query | Description |
|-------|-------------|
| `get_chef_nodes` | Get node inventory |
| `get_chef_clients` | Get client list |
| `get_chef_cookbooks` | Get cookbook versions |
| `get_chef_environments` | Get environments |
| `get_chef_roles` | Get role definitions |
| `get_chef_data_bags` | Get data bag metadata |
| `get_chef_run_lists` | Get node run lists |
| `get_chef_compliance` | Get InSpec scan results |
| `get_chef_automate` | Get Automate status |

### SaltStack Plugin
**Scope:** `salt`

| Query | Description |
|-------|-------------|
| `get_salt_minions` | Get minion status |
| `get_salt_jobs` | Get job history |
| `get_salt_grains` | Get minion grains |
| `get_salt_pillar` | Get pillar metadata |
| `get_salt_states` | Get state definitions |
| `get_salt_runners` | Get runner modules |
| `get_salt_events` | Get event bus |
| `get_salt_keys` | Get key status |

### Terraform Cloud Plugin
**Scope:** `terraform`

| Query | Description |
|-------|-------------|
| `get_tfc_workspaces` | Get workspace inventory |
| `get_tfc_runs` | Get run history |
| `get_tfc_state_versions` | Get state versions |
| `get_tfc_variables` | Get variable metadata |
| `get_tfc_policies` | Get Sentinel policies |
| `get_tfc_policy_checks` | Get policy check results |
| `get_tfc_teams` | Get team configuration |
| `get_tfc_agents` | Get agent pool status |

---

## DNS & Domain Services

### BIND Plugin
**Scope:** `bind`

| Query | Description |
|-------|-------------|
| `get_bind_status` | Get server status |
| `get_bind_zones` | Get zone inventory |
| `get_bind_zone_records` | Get zone RRsets |
| `get_bind_statistics` | Get query statistics |
| `get_bind_cache` | Get cache statistics |
| `get_bind_rndc_status` | Get rndc status |

### CoreDNS Plugin
**Scope:** `coredns`

| Query | Description |
|-------|-------------|
| `get_coredns_config` | Get Corefile config |
| `get_coredns_metrics` | Get Prometheus metrics |
| `get_coredns_plugins` | Get plugin chain |
| `get_coredns_health` | Get health status |
| `get_coredns_cache` | Get cache statistics |

### PowerDNS Plugin
**Scope:** `powerdns`

| Query | Description |
|-------|-------------|
| `get_pdns_config` | Get server config |
| `get_pdns_zones` | Get zone list |
| `get_pdns_records` | Get RRsets |
| `get_pdns_statistics` | Get server stats |
| `get_pdns_servers` | Get recursor servers |

### AWS Route 53 Plugin
**Scope:** `route53`

| Query | Description |
|-------|-------------|
| `get_route53_hosted_zones` | Get hosted zones |
| `get_route53_records` | Get DNS records |
| `get_route53_health_checks` | Get health check status |
| `get_route53_traffic_policies` | Get traffic policies |
| `get_route53_resolver` | Get resolver endpoints |

---

## Email & Messaging

### Microsoft Exchange Plugin
**Scope:** `exchange`

| Query | Description |
|-------|-------------|
| `get_exchange_servers` | Get server inventory |
| `get_exchange_databases` | Get database status |
| `get_exchange_dag` | Get DAG health |
| `get_exchange_queues` | Get mail queue status |
| `get_exchange_connectors` | Get send/receive connectors |
| `get_exchange_transport_rules` | Get transport rules |
| `get_exchange_mailboxes` | Get mailbox statistics |
| `get_exchange_public_folders` | Get public folder stats |
| `get_exchange_certificates` | Get certificate status |
| `get_exchange_message_tracking` | Get message tracking |

### Postfix Plugin
**Scope:** `postfix`

| Query | Description |
|-------|-------------|
| `get_postfix_queue` | Get mail queue status |
| `get_postfix_config` | Get main.cf config |
| `get_postfix_virtual` | Get virtual mappings |
| `get_postfix_transport` | Get transport maps |
| `get_postfix_logs` | Get recent mail logs |
| `get_postfix_tls` | Get TLS statistics |

### Sendmail Plugin
**Scope:** `sendmail`

| Query | Description |
|-------|-------------|
| `get_sendmail_queue` | Get mail queue |
| `get_sendmail_stats` | Get mailstats output |
| `get_sendmail_config` | Get sendmail.cf (parsed) |
| `get_sendmail_aliases` | Get alias database |

### Dovecot Plugin
**Scope:** `dovecot`

| Query | Description |
|-------|-------------|
| `get_dovecot_config` | Get configuration |
| `get_dovecot_who` | Get active connections |
| `get_dovecot_stats` | Get protocol stats |
| `get_dovecot_replication` | Get replication status |

---

## Collaboration & Communication

### Microsoft Teams Plugin
**Scope:** `teams`

| Query | Description |
|-------|-------------|
| `get_teams_service_health` | Get service health |
| `get_teams_users` | Get user directory |
| `get_teams_teams` | Get team list |
| `get_teams_channels` | Get channel list |
| `get_teams_apps` | Get installed apps |
| `get_teams_policies` | Get meeting policies |
| `get_teams_call_quality` | Get call quality data |

### Slack Plugin
**Scope:** `slack`

| Query | Description |
|-------|-------------|
| `get_slack_workspace` | Get workspace info |
| `get_slack_users` | Get user directory |
| `get_slack_channels` | Get channel list |
| `get_slack_apps` | Get installed apps |
| `get_slack_user_groups` | Get user groups |
| `get_slack_audit_logs` | Get audit events |
| `get_slack_analytics` | Get usage analytics |

### Zoom Plugin
**Scope:** `zoom`

| Query | Description |
|-------|-------------|
| `get_zoom_users` | Get user list |
| `get_zoom_meetings` | Get meeting list |
| `get_zoom_webinars` | Get webinar list |
| `get_zoom_rooms` | Get Zoom Rooms status |
| `get_zoom_recordings` | Get cloud recordings |
| `get_zoom_reports` | Get usage reports |
| `get_zoom_dashboard` | Get dashboard metrics |

---

## ERP Systems

### SAP Plugin
**Scope:** `sap`

| Query | Description |
|-------|-------------|
| `get_sap_system_info` | Get system version/status |
| `get_sap_instances` | Get instance list |
| `get_sap_processes` | Get work process status |
| `get_sap_queues` | Get RFC queue status |
| `get_sap_users` | Get user directory |
| `get_sap_locks` | Get lock entries |
| `get_sap_dumps` | Get short dumps |
| `get_sap_jobs` | Get background job status |
| `get_sap_transports` | Get transport requests |
| `get_sap_idocs` | Get IDoc status |
| `get_sap_rfc_connections` | Get RFC destinations |
| `get_sap_hana_status` | Get HANA system status |
| `get_sap_hana_alerts` | Get HANA alerts |
| `get_sap_hana_replication` | Get system replication |

### Oracle E-Business Suite Plugin
**Scope:** `oracle_ebs`

| Query | Description |
|-------|-------------|
| `get_ebs_nodes` | Get application tier nodes |
| `get_ebs_services` | Get service status |
| `get_ebs_concurrent_managers` | Get CM status |
| `get_ebs_concurrent_requests` | Get request queue |
| `get_ebs_workflows` | Get workflow status |
| `get_ebs_users` | Get user list |
| `get_ebs_responsibilities` | Get responsibility assignments |
| `get_ebs_patches` | Get applied patches |
| `get_ebs_alerts` | Get alert status |

### Microsoft Dynamics 365 Plugin
**Scope:** `dynamics365`

| Query | Description |
|-------|-------------|
| `get_d365_organizations` | Get org instances |
| `get_d365_solutions` | Get installed solutions |
| `get_d365_users` | Get system users |
| `get_d365_security_roles` | Get role assignments |
| `get_d365_plugins` | Get plugin assemblies |
| `get_d365_workflows` | Get process definitions |
| `get_d365_system_jobs` | Get async job status |
| `get_d365_data_export` | Get export profiles |

---

## CRM Platforms

### Salesforce Plugin
**Scope:** `salesforce`

| Query | Description |
|-------|-------------|
| `get_sf_org_info` | Get org limits/usage |
| `get_sf_users` | Get user directory |
| `get_sf_profiles` | Get profiles |
| `get_sf_permission_sets` | Get permission sets |
| `get_sf_custom_objects` | Get object metadata |
| `get_sf_apex_classes` | Get Apex class inventory |
| `get_sf_flows` | Get Flow definitions |
| `get_sf_reports` | Get report list |
| `get_sf_dashboards` | Get dashboard list |
| `get_sf_installed_packages` | Get managed packages |
| `get_sf_sandbox_info` | Get sandbox inventory |
| `get_sf_login_history` | Get login history |
| `get_sf_api_usage` | Get API usage stats |
| `get_sf_deployment_status` | Get deployment history |

### HubSpot Plugin
**Scope:** `hubspot`

| Query | Description |
|-------|-------------|
| `get_hubspot_account` | Get account info |
| `get_hubspot_users` | Get user directory |
| `get_hubspot_pipelines` | Get deal pipelines |
| `get_hubspot_workflows` | Get automation workflows |
| `get_hubspot_forms` | Get form inventory |
| `get_hubspot_lists` | Get contact lists |
| `get_hubspot_properties` | Get custom properties |
| `get_hubspot_integrations` | Get connected apps |
| `get_hubspot_api_usage` | Get API rate limits |

### Zendesk Plugin
**Scope:** `zendesk`

| Query | Description |
|-------|-------------|
| `get_zendesk_account` | Get account info |
| `get_zendesk_users` | Get agent/admin list |
| `get_zendesk_groups` | Get support groups |
| `get_zendesk_views` | Get ticket views |
| `get_zendesk_triggers` | Get automation triggers |
| `get_zendesk_macros` | Get macro inventory |
| `get_zendesk_automations` | Get automations |
| `get_zendesk_slas` | Get SLA policies |
| `get_zendesk_apps` | Get installed apps |
| `get_zendesk_ticket_fields` | Get custom fields |

---

## Big Data & Analytics

### Apache Spark Plugin
**Scope:** `spark`

| Query | Description |
|-------|-------------|
| `get_spark_applications` | Get running applications |
| `get_spark_jobs` | Get job status |
| `get_spark_stages` | Get stage details |
| `get_spark_executors` | Get executor status |
| `get_spark_storage` | Get RDD storage |
| `get_spark_environment` | Get spark config |
| `get_spark_sql` | Get SQL execution stats |
| `get_spark_streaming` | Get streaming stats |

### Apache Hadoop/HDFS Plugin
**Scope:** `hadoop`

| Query | Description |
|-------|-------------|
| `get_hdfs_status` | Get cluster health |
| `get_hdfs_namenodes` | Get NameNode status |
| `get_hdfs_datanodes` | Get DataNode status |
| `get_hdfs_capacity` | Get storage capacity |
| `get_hdfs_blocks` | Get block report |
| `get_yarn_nodes` | Get NodeManager status |
| `get_yarn_applications` | Get running applications |
| `get_yarn_queues` | Get queue status |
| `get_hive_databases` | Get Hive metastore |
| `get_hive_queries` | Get HiveServer2 queries |

### Snowflake Plugin
**Scope:** `snowflake`

| Query | Description |
|-------|-------------|
| `get_snowflake_warehouses` | Get warehouse status |
| `get_snowflake_databases` | Get database list |
| `get_snowflake_schemas` | Get schema inventory |
| `get_snowflake_tables` | Get table metadata |
| `get_snowflake_users` | Get user directory |
| `get_snowflake_roles` | Get role hierarchy |
| `get_snowflake_stages` | Get stage list |
| `get_snowflake_pipes` | Get Snowpipe status |
| `get_snowflake_tasks` | Get task status |
| `get_snowflake_streams` | Get stream status |
| `get_snowflake_query_history` | Get query history |
| `get_snowflake_resource_monitors` | Get credit usage |

### Databricks Plugin
**Scope:** `databricks`

| Query | Description |
|-------|-------------|
| `get_databricks_workspaces` | Get workspace list |
| `get_databricks_clusters` | Get cluster status |
| `get_databricks_jobs` | Get job definitions |
| `get_databricks_runs` | Get job run history |
| `get_databricks_notebooks` | Get notebook inventory |
| `get_databricks_repos` | Get Git repos |
| `get_databricks_sql_warehouses` | Get SQL warehouse status |
| `get_databricks_mlflow` | Get MLflow experiments |
| `get_databricks_unity_catalog` | Get catalog metadata |

### ClickHouse Plugin
**Scope:** `clickhouse`

| Query | Description |
|-------|-------------|
| `get_clickhouse_cluster` | Get cluster topology |
| `get_clickhouse_databases` | Get database list |
| `get_clickhouse_tables` | Get table statistics |
| `get_clickhouse_parts` | Get partition/part info |
| `get_clickhouse_merges` | Get merge status |
| `get_clickhouse_mutations` | Get mutation status |
| `get_clickhouse_replication` | Get replication queue |
| `get_clickhouse_queries` | Get query log |
| `get_clickhouse_processes` | Get active queries |
| `get_clickhouse_settings` | Get server settings |

---

## Machine Learning Platforms

### Kubeflow Plugin
**Scope:** `kubeflow`

| Query | Description |
|-------|-------------|
| `get_kubeflow_pipelines` | Get pipeline definitions |
| `get_kubeflow_runs` | Get pipeline runs |
| `get_kubeflow_experiments` | Get experiments |
| `get_kubeflow_notebooks` | Get Jupyter notebooks |
| `get_kubeflow_serving` | Get KFServing models |
| `get_kubeflow_katib` | Get hyperparameter tuning |
| `get_kubeflow_training` | Get training jobs |

### MLflow Plugin
**Scope:** `mlflow`

| Query | Description |
|-------|-------------|
| `get_mlflow_experiments` | Get experiment list |
| `get_mlflow_runs` | Get run history |
| `get_mlflow_models` | Get registered models |
| `get_mlflow_model_versions` | Get model versions |
| `get_mlflow_metrics` | Get run metrics |
| `get_mlflow_artifacts` | Get artifact list |

### SageMaker Plugin
**Scope:** `sagemaker`

| Query | Description |
|-------|-------------|
| `get_sagemaker_notebooks` | Get notebook instances |
| `get_sagemaker_training_jobs` | Get training job status |
| `get_sagemaker_models` | Get model inventory |
| `get_sagemaker_endpoints` | Get endpoint status |
| `get_sagemaker_pipelines` | Get ML pipelines |
| `get_sagemaker_experiments` | Get experiments |
| `get_sagemaker_feature_groups` | Get feature store |
| `get_sagemaker_model_registry` | Get model packages |

### NVIDIA Triton Plugin
**Scope:** `triton`

| Query | Description |
|-------|-------------|
| `get_triton_health` | Get server health |
| `get_triton_models` | Get loaded models |
| `get_triton_model_config` | Get model configuration |
| `get_triton_statistics` | Get inference statistics |
| `get_triton_shared_memory` | Get shared memory status |
| `get_triton_cuda_memory` | Get GPU memory |

---

## API Gateways

### Kong Plugin
**Scope:** `kong`

| Query | Description |
|-------|-------------|
| `get_kong_status` | Get node status |
| `get_kong_services` | Get service inventory |
| `get_kong_routes` | Get route mappings |
| `get_kong_consumers` | Get consumer list |
| `get_kong_plugins` | Get plugin configuration |
| `get_kong_upstreams` | Get upstream targets |
| `get_kong_certificates` | Get SSL certificates |
| `get_kong_acls` | Get ACL groups |
| `get_kong_rate_limiting` | Get rate limit config |
| `get_kong_cluster` | Get cluster status |

### AWS API Gateway Plugin
**Scope:** `apigateway`

| Query | Description |
|-------|-------------|
| `get_apigw_rest_apis` | Get REST API inventory |
| `get_apigw_http_apis` | Get HTTP API inventory |
| `get_apigw_stages` | Get stage configuration |
| `get_apigw_resources` | Get resource definitions |
| `get_apigw_methods` | Get method config |
| `get_apigw_authorizers` | Get authorizers |
| `get_apigw_usage_plans` | Get usage plans |
| `get_apigw_api_keys` | Get API key metadata |
| `get_apigw_domain_names` | Get custom domains |
| `get_apigw_vpc_links` | Get VPC link status |

### Apigee Plugin
**Scope:** `apigee`

| Query | Description |
|-------|-------------|
| `get_apigee_organizations` | Get org list |
| `get_apigee_environments` | Get environment list |
| `get_apigee_apis` | Get API proxy inventory |
| `get_apigee_products` | Get API products |
| `get_apigee_developers` | Get developer list |
| `get_apigee_apps` | Get developer apps |
| `get_apigee_deployments` | Get deployment status |
| `get_apigee_target_servers` | Get backend targets |
| `get_apigee_kvm` | Get key-value map metadata |
| `get_apigee_analytics` | Get traffic analytics |

### Tyk Plugin
**Scope:** `tyk`

| Query | Description |
|-------|-------------|
| `get_tyk_status` | Get gateway status |
| `get_tyk_apis` | Get API definitions |
| `get_tyk_policies` | Get access policies |
| `get_tyk_keys` | Get API key metadata |
| `get_tyk_oauth_clients` | Get OAuth clients |
| `get_tyk_certificates` | Get certificate store |
| `get_tyk_analytics` | Get analytics data |

---

## Certificate Management

### Let's Encrypt/Certbot Plugin
**Scope:** `certbot`

| Query | Description |
|-------|-------------|
| `get_certbot_certificates` | Get certificate inventory |
| `get_certbot_renewals` | Get renewal status |
| `get_certbot_accounts` | Get ACME accounts |
| `get_certbot_hooks` | Get hook configuration |

### cert-manager Plugin
**Scope:** `certmanager`

| Query | Description |
|-------|-------------|
| `get_certmanager_certificates` | Get Certificate resources |
| `get_certmanager_issuers` | Get Issuer configuration |
| `get_certmanager_orders` | Get ACME order status |
| `get_certmanager_challenges` | Get challenge status |
| `get_certmanager_certificaterequests` | Get CSR status |

### Venafi Plugin
**Scope:** `venafi`

| Query | Description |
|-------|-------------|
| `get_venafi_certificates` | Get certificate inventory |
| `get_venafi_pending` | Get pending requests |
| `get_venafi_expiring` | Get expiring certificates |
| `get_venafi_policies` | Get policy folders |
| `get_venafi_ca` | Get CA configuration |

### DigiCert Plugin
**Scope:** `digicert`

| Query | Description |
|-------|-------------|
| `get_digicert_orders` | Get certificate orders |
| `get_digicert_certificates` | Get issued certificates |
| `get_digicert_domains` | Get validated domains |
| `get_digicert_organizations` | Get org validation |
| `get_digicert_users` | Get account users |

---

## Compliance & Governance

### AWS Config Plugin
**Scope:** `aws_config`

| Query | Description |
|-------|-------------|
| `get_config_rules` | Get compliance rules |
| `get_config_compliance` | Get compliance status |
| `get_config_conformance_packs` | Get conformance packs |
| `get_config_aggregators` | Get aggregator status |
| `get_config_resource_inventory` | Get discovered resources |

### Azure Policy Plugin
**Scope:** `azure_policy`

| Query | Description |
|-------|-------------|
| `get_policy_definitions` | Get policy definitions |
| `get_policy_assignments` | Get policy assignments |
| `get_policy_compliance` | Get compliance state |
| `get_policy_initiatives` | Get initiative definitions |
| `get_policy_exemptions` | Get policy exemptions |

### GCP Organization Policy Plugin
**Scope:** `gcp_orgpolicy`

| Query | Description |
|-------|-------------|
| `get_org_policies` | Get organization policies |
| `get_org_constraints` | Get constraint definitions |
| `get_security_marks` | Get SCC security marks |
| `get_access_context` | Get VPC-SC perimeters |

### Open Policy Agent Plugin
**Scope:** `opa`

| Query | Description |
|-------|-------------|
| `get_opa_policies` | Get loaded policies |
| `get_opa_data` | Get policy data |
| `get_opa_status` | Get bundle status |
| `get_opa_decision_logs` | Get decision log |
| `get_opa_metrics` | Get performance metrics |

### Prisma Cloud Plugin
**Scope:** `prismacloud`

| Query | Description |
|-------|-------------|
| `get_prisma_alerts` | Get security alerts |
| `get_prisma_policies` | Get policy library |
| `get_prisma_compliance` | Get compliance reports |
| `get_prisma_assets` | Get cloud asset inventory |
| `get_prisma_vulnerabilities` | Get vulnerability findings |
| `get_prisma_iam` | Get IAM analysis |

### Qualys Plugin
**Scope:** `qualys`

| Query | Description |
|-------|-------------|
| `get_qualys_hosts` | Get host inventory |
| `get_qualys_scans` | Get scan results |
| `get_qualys_vulnerabilities` | Get vulnerability list |
| `get_qualys_compliance` | Get compliance posture |
| `get_qualys_policies` | Get policy definitions |
| `get_qualys_asset_groups` | Get asset groups |

### Tenable Plugin
**Scope:** `tenable`

| Query | Description |
|-------|-------------|
| `get_tenable_scanners` | Get scanner inventory |
| `get_tenable_scans` | Get scan list |
| `get_tenable_assets` | Get asset inventory |
| `get_tenable_vulnerabilities` | Get vulnerability findings |
| `get_tenable_plugins` | Get plugin info |
| `get_tenable_agents` | Get Nessus agent status |
| `get_tenable_compliance` | Get compliance audits |

---

## Network Access Control (NAC)

### Cisco ISE Plugin
**Scope:** `cisco_ise`

| Query | Description |
|-------|-------------|
| `get_ise_deployment` | Get deployment status |
| `get_ise_nodes` | Get ISE node health |
| `get_ise_endpoints` | Get endpoint inventory |
| `get_ise_sessions` | Get active RADIUS sessions |
| `get_ise_authentications` | Get authentication logs |
| `get_ise_authorization_policies` | Get authz policy status |
| `get_ise_posture` | Get posture assessment results |
| `get_ise_profiling` | Get endpoint profiling |
| `get_ise_guest` | Get guest portal status |
| `get_ise_certificates` | Get certificate status |
| `get_ise_trustsec` | Get TrustSec SGT status |
| `get_ise_network_devices` | Get NAD inventory |

### Aruba ClearPass Plugin
**Scope:** `clearpass`

| Query | Description |
|-------|-------------|
| `get_clearpass_cluster` | Get cluster status |
| `get_clearpass_servers` | Get server health |
| `get_clearpass_endpoints` | Get endpoint inventory |
| `get_clearpass_sessions` | Get active sessions |
| `get_clearpass_authentications` | Get authentication log |
| `get_clearpass_enforcement` | Get enforcement policies |
| `get_clearpass_posture` | Get OnGuard status |
| `get_clearpass_onboard` | Get certificate status |
| `get_clearpass_guest` | Get guest accounts |
| `get_clearpass_insight` | Get analytics data |

### Forescout Plugin
**Scope:** `forescout`

| Query | Description |
|-------|-------------|
| `get_forescout_appliances` | Get appliance status |
| `get_forescout_hosts` | Get discovered hosts |
| `get_forescout_segments` | Get network segments |
| `get_forescout_policies` | Get policy status |
| `get_forescout_compliance` | Get compliance status |
| `get_forescout_actions` | Get remediation actions |
| `get_forescout_modules` | Get eyeExtend modules |
| `get_forescout_classifications` | Get device classifications |

### Portnox Plugin
**Scope:** `portnox`

| Query | Description |
|-------|-------------|
| `get_portnox_devices` | Get device inventory |
| `get_portnox_users` | Get user sessions |
| `get_portnox_compliance` | Get compliance status |
| `get_portnox_policies` | Get access policies |
| `get_portnox_alerts` | Get security alerts |
| `get_portnox_network` | Get network topology |

### PacketFence Plugin
**Scope:** `packetfence`

| Query | Description |
|-------|-------------|
| `get_pf_nodes` | Get node inventory |
| `get_pf_violations` | Get security violations |
| `get_pf_switches` | Get switch inventory |
| `get_pf_users` | Get user list |
| `get_pf_connections` | Get connection profiles |
| `get_pf_services` | Get service status |

---

## Privileged Access Management (PAM)

### CyberArk Privileged Access Plugin
**Scope:** `cyberark_pam`

| Query | Description |
|-------|-------------|
| `get_cyberark_vault` | Get Vault status |
| `get_cyberark_safes` | Get safe inventory |
| `get_cyberark_accounts` | Get account metadata |
| `get_cyberark_platforms` | Get platform definitions |
| `get_cyberark_policies` | Get master policies |
| `get_cyberark_psm_sessions` | Get PSM session list |
| `get_cyberark_psm_recordings` | Get recording metadata |
| `get_cyberark_cpm_status` | Get CPM sync status |
| `get_cyberark_pta_alerts` | Get PTA security alerts |
| `get_cyberark_aam` | Get Application Access Manager |
| `get_cyberark_conjur` | Get Conjur secrets metadata |

### BeyondTrust Plugin
**Scope:** `beyondtrust`

| Query | Description |
|-------|-------------|
| `get_bt_safes` | Get Password Safe inventory |
| `get_bt_managed_accounts` | Get managed accounts |
| `get_bt_sessions` | Get session recordings |
| `get_bt_requests` | Get access requests |
| `get_bt_policies` | Get access policies |
| `get_bt_ad_bridge` | Get AD Bridge status |
| `get_bt_privilege_management` | Get EPM policies |
| `get_bt_remote_support` | Get RS sessions |

### Delinea (Thycotic) Plugin
**Scope:** `delinea`

| Query | Description |
|-------|-------------|
| `get_ss_folders` | Get Secret Server folders |
| `get_ss_secrets` | Get secret metadata |
| `get_ss_users` | Get user inventory |
| `get_ss_roles` | Get role definitions |
| `get_ss_policies` | Get password policies |
| `get_ss_heartbeat` | Get heartbeat status |
| `get_ss_sessions` | Get session recordings |
| `get_ss_discovery` | Get discovery results |
| `get_privilege_manager` | Get PM endpoint status |

### HashiCorp Boundary Plugin
**Scope:** `boundary`

| Query | Description |
|-------|-------------|
| `get_boundary_scopes` | Get org/project scopes |
| `get_boundary_auth_methods` | Get auth method config |
| `get_boundary_users` | Get user inventory |
| `get_boundary_groups` | Get group memberships |
| `get_boundary_roles` | Get role grants |
| `get_boundary_targets` | Get target inventory |
| `get_boundary_host_catalogs` | Get host catalogs |
| `get_boundary_sessions` | Get active sessions |
| `get_boundary_credential_stores` | Get credential stores |

### Teleport Plugin
**Scope:** `teleport`

| Query | Description |
|-------|-------------|
| `get_teleport_cluster` | Get cluster status |
| `get_teleport_nodes` | Get SSH node inventory |
| `get_teleport_apps` | Get application inventory |
| `get_teleport_databases` | Get database inventory |
| `get_teleport_kubernetes` | Get Kubernetes clusters |
| `get_teleport_users` | Get user directory |
| `get_teleport_roles` | Get role definitions |
| `get_teleport_sessions` | Get active sessions |
| `get_teleport_audit` | Get audit events |
| `get_teleport_access_requests` | Get access request status |

### Wallix Bastion Plugin
**Scope:** `wallix`

| Query | Description |
|-------|-------------|
| `get_wallix_devices` | Get device inventory |
| `get_wallix_accounts` | Get target accounts |
| `get_wallix_users` | Get user directory |
| `get_wallix_groups` | Get group memberships |
| `get_wallix_authorizations` | Get authorization rules |
| `get_wallix_sessions` | Get session list |
| `get_wallix_recordings` | Get recording metadata |
| `get_wallix_approvals` | Get approval workflow |

### One Identity Safeguard Plugin
**Scope:** `safeguard`

| Query | Description |
|-------|-------------|
| `get_safeguard_appliances` | Get appliance cluster |
| `get_safeguard_assets` | Get asset inventory |
| `get_safeguard_accounts` | Get account inventory |
| `get_safeguard_users` | Get user directory |
| `get_safeguard_entitlements` | Get access policies |
| `get_safeguard_sessions` | Get session recordings |
| `get_safeguard_access_requests` | Get request queue |
| `get_safeguard_password_checkout` | Get checkout history |

---

## Vulnerability Management

### Rapid7 InsightVM Plugin
**Scope:** `insightvm`

| Query | Description |
|-------|-------------|
| `get_insightvm_sites` | Get site inventory |
| `get_insightvm_assets` | Get asset inventory |
| `get_insightvm_scans` | Get scan status |
| `get_insightvm_vulnerabilities` | Get vulnerability findings |
| `get_insightvm_exploits` | Get exploitable vulns |
| `get_insightvm_solutions` | Get remediation solutions |
| `get_insightvm_policies` | Get policy compliance |
| `get_insightvm_tags` | Get asset tags |
| `get_insightvm_reports` | Get report data |
| `get_insightvm_agents` | Get Insight Agent status |

### Qualys VMDR Plugin
**Scope:** `qualys_vmdr`

| Query | Description |
|-------|-------------|
| `get_qualys_assets` | Get asset inventory |
| `get_qualys_asset_groups` | Get asset groups |
| `get_qualys_scans` | Get scan schedules |
| `get_qualys_scan_results` | Get scan results |
| `get_qualys_vulnerabilities` | Get QID findings |
| `get_qualys_patches` | Get patch availability |
| `get_qualys_reports` | Get report templates |
| `get_qualys_tags` | Get asset tags |
| `get_qualys_trurisk` | Get TruRisk scores |

### Tenable.io Plugin
**Scope:** `tenable_io`

| Query | Description |
|-------|-------------|
| `get_tio_assets` | Get asset inventory |
| `get_tio_vulnerabilities` | Get vulnerability findings |
| `get_tio_scans` | Get scan status |
| `get_tio_scanners` | Get scanner inventory |
| `get_tio_agents` | Get Nessus Agent status |
| `get_tio_plugins` | Get plugin details |
| `get_tio_tags` | Get asset tags |
| `get_tio_groups` | Get access groups |
| `get_tio_exports` | Get export jobs |
| `get_tio_vpr` | Get VPR scores |
| `get_tio_asm` | Get Attack Surface data |

### Nessus Plugin
**Scope:** `nessus`

| Query | Description |
|-------|-------------|
| `get_nessus_server_info` | Get server status |
| `get_nessus_scans` | Get scan list |
| `get_nessus_scan_results` | Get scan results |
| `get_nessus_policies` | Get scan policies |
| `get_nessus_plugins` | Get plugin families |
| `get_nessus_folders` | Get folder structure |
| `get_nessus_agents` | Get linked agents |
| `get_nessus_agent_groups` | Get agent groups |

### Greenbone/OpenVAS Plugin
**Scope:** `openvas`

| Query | Description |
|-------|-------------|
| `get_openvas_status` | Get scanner status |
| `get_openvas_targets` | Get target list |
| `get_openvas_tasks` | Get scan tasks |
| `get_openvas_reports` | Get scan reports |
| `get_openvas_results` | Get vulnerability results |
| `get_openvas_nvts` | Get NVT feed status |
| `get_openvas_schedules` | Get scan schedules |
| `get_openvas_alerts` | Get alert definitions |

### Nexpose Plugin
**Scope:** `nexpose`

| Query | Description |
|-------|-------------|
| `get_nexpose_sites` | Get site inventory |
| `get_nexpose_assets` | Get asset inventory |
| `get_nexpose_scans` | Get scan history |
| `get_nexpose_vulnerabilities` | Get vulnerability data |
| `get_nexpose_policies` | Get policy compliance |
| `get_nexpose_engines` | Get scan engine status |
| `get_nexpose_reports` | Get report configurations |
| `get_nexpose_tags` | Get tag hierarchy |

### Snyk Plugin
**Scope:** `snyk`

| Query | Description |
|-------|-------------|
| `get_snyk_organizations` | Get org inventory |
| `get_snyk_projects` | Get project list |
| `get_snyk_issues` | Get vulnerability issues |
| `get_snyk_dependencies` | Get dependency graph |
| `get_snyk_licenses` | Get license issues |
| `get_snyk_ignores` | Get ignored issues |
| `get_snyk_test_results` | Get test results |
| `get_snyk_iac` | Get IaC findings |
| `get_snyk_code` | Get SAST findings |
| `get_snyk_container` | Get container findings |

### Wiz Plugin
**Scope:** `wiz`

| Query | Description |
|-------|-------------|
| `get_wiz_issues` | Get security issues |
| `get_wiz_vulnerabilities` | Get vulnerability findings |
| `get_wiz_inventory` | Get cloud inventory |
| `get_wiz_configurations` | Get misconfigurations |
| `get_wiz_secrets` | Get exposed secrets |
| `get_wiz_data` | Get data findings |
| `get_wiz_network` | Get network exposure |
| `get_wiz_containers` | Get container findings |
| `get_wiz_kubernetes` | Get K8s security |
| `get_wiz_iac` | Get IaC analysis |

### Orca Security Plugin
**Scope:** `orca`

| Query | Description |
|-------|-------------|
| `get_orca_alerts` | Get security alerts |
| `get_orca_assets` | Get cloud asset inventory |
| `get_orca_vulnerabilities` | Get vulnerability findings |
| `get_orca_compliance` | Get compliance status |
| `get_orca_data_risk` | Get data at risk |
| `get_orca_attack_paths` | Get attack path analysis |
| `get_orca_iam` | Get IAM findings |
| `get_orca_malware` | Get malware detections |

### Anchore Plugin
**Scope:** `anchore`

| Query | Description |
|-------|-------------|
| `get_anchore_images` | Get analyzed images |
| `get_anchore_vulnerabilities` | Get vulnerability findings |
| `get_anchore_policies` | Get policy bundles |
| `get_anchore_policy_eval` | Get policy evaluation |
| `get_anchore_registries` | Get registry credentials |
| `get_anchore_feeds` | Get feed sync status |
| `get_anchore_subscriptions` | Get tag subscriptions |

### Trivy Plugin
**Scope:** `trivy`

| Query | Description |
|-------|-------------|
| `get_trivy_image_scan` | Get container image scan |
| `get_trivy_fs_scan` | Get filesystem scan |
| `get_trivy_repo_scan` | Get repository scan |
| `get_trivy_k8s_scan` | Get Kubernetes scan |
| `get_trivy_sbom` | Get SBOM output |
| `get_trivy_db_status` | Get vulnerability DB status |

---

## Plugin Development Guidelines

### Scope Naming Convention
- Use lowercase with underscores for multi-word scopes
- Prefix cloud-specific plugins: `aws_`, `azure_`, `gcp_`
- Use product name for standalone plugins: `mysql`, `nginx`, `vault`

### Security Requirements
- All credential handling must use the credential redaction system
- Sensitive data (passwords, tokens, keys) must never appear in output
- API keys/tokens should be referenced by metadata only
- Network calls must respect configured timeouts and rate limits

### Query Design Principles
1. **Read-only**: No queries should modify system state
2. **Bounded output**: Implement pagination or limits for large datasets
3. **Timeout-aware**: Long-running queries should support cancellation
4. **Error handling**: Return structured errors with remediation hints
5. **Caching**: Consider caching for expensive operations

### Plugin Structure
```
internal/
  plugins/
    mysql/
      mysql.go          # Plugin registration
      mysql_linux.go    # Platform-specific collectors
      mysql_darwin.go
      mysql_windows.go
      mysql_test.go     # Unit tests
```

### Registration Example
```go
func RegisterMySQLTools(s *Server) {
    s.RegisterTool(Tool{
        Name:        "get_mysql_status",
        Description: "Get MySQL server status variables",
        InputSchema: InputSchema{
            Type: "object",
            Properties: map[string]Property{
                "host": {Type: "string", Description: "MySQL host"},
                "port": {Type: "integer", Description: "MySQL port", Default: 3306},
            },
        },
    }, "mysql", handler)
}
```

---

## Licensing

Enterprise plugins are licensed separately from the core MCP System Info server. Contact sales@example.com for:
- Individual plugin licenses
- Plugin bundles by category
- Site-wide enterprise licenses
- Custom plugin development

---

*Document Version: 1.0*
*Last Updated: January 2026*
