// SPDX-License-Identifier: MIT
// GA R431-R440 — SOURCE CANDIDATE — UNVERIFIED.
// Explicit absence of authenticated service/protocol/outcome evidence.
// These reason codes are not success, detection, or field-validation claims.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class ServiceExposureEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R431" => ("AIRFLOW_TARGET_AND_PROBE_PROVENANCE_UNAVAILABLE",
                    "An HTTP admin/DAG path does not establish an Airflow service identity, authenticated response, or malicious probe."),
                "R432" => ("CONSUL_NOMAD_TARGET_AND_PROBE_UNAVAILABLE",
                    "Consul/Nomad API-looking paths and ports do not prove target product identity or an unauthorized administrative probe."),
                "R433" => ("POSTGRES_AUTH_HANDSHAKE_UNAVAILABLE",
                    "No parsed PostgreSQL startup/authentication handshake, verified server identity, or login outcome is connected."),
                "R434" => ("MYSQL_AUTH_HANDSHAKE_UNAVAILABLE",
                    "No parsed MySQL handshake/login exchange, verified server identity, or authentication outcome is connected."),
                "R435" => ("MSSQL_TDS_LOGIN_PROVENANCE_UNAVAILABLE",
                    "TCP/1433 and SQL vocabulary do not prove a TDS LOGIN7 exchange or authentication attempt/outcome."),
                "R436" => ("MONGODB_WIRE_EXPOSURE_PROVENANCE_UNAVAILABLE",
                    "No parsed MongoDB wire request/response or verified externally accessible service is connected."),
                "R437" => ("REDIS_RESP_CONFIG_SET_UNAVAILABLE",
                    "Redis CONFIG SET requires attributed RESP command arguments and context, not a port or string in Info."),
                "R438" => ("REDIS_RESP_REPLICATION_UNAVAILABLE",
                    "No attributed Redis REPLICAOF/SLAVEOF command, replication-state change, or response provenance is connected."),
                "R439" => ("MEMCACHED_STATS_COMMAND_SEQUENCE_UNAVAILABLE",
                    "No parsed Memcached stats commands with independent source/flow sequence and response correlation are connected."),
                "R440" => ("ELASTIC_SNAPSHOT_TARGET_AND_RESPONSE_UNAVAILABLE",
                    "An HTTP /_snapshot request is not authenticated Elasticsearch identity, repository access, or probe outcome."),
                // GA R441-R450 — SOURCE CANDIDATE — UNVERIFIED.
                // Port, client-request and descriptor text cannot establish
                // protocol decoding, authenticated service identity, external
                // accessibility, or a server outcome.
                "R441" => ("CASSANDRA_CQL_NATIVE_FRAME_PROVENANCE_UNAVAILABLE",
                    "No attributed Cassandra CQL native frame, OPTIONS/STARTUP exchange, or verified target response is connected."),
                "R442" => ("ORACLE_TNS_HANDSHAKE_PROVENANCE_UNAVAILABLE",
                    "TCP/1521 and TNS vocabulary do not establish an Oracle listener exchange, service enumeration, or outcome."),
                "R443" => ("COUCHDB_TARGET_AND_RESPONSE_UNAVAILABLE",
                    "CouchDB-looking HTTP routes do not prove the target service, an admin probe, or access-control response."),
                "R444" => ("INFLUXDB_QUERY_ACCESS_OUTCOME_UNAVAILABLE",
                    "An HTTP query route or port does not prove InfluxDB identity, unauthenticated reachability, or query result."),
                "R445" => ("CLICKHOUSE_SQL_REQUEST_RESPONSE_UNAVAILABLE",
                    "No verified ClickHouse HTTP SQL request/response, target identity, or query authorization result is connected."),
                "R446" => ("NEO4J_BROWSER_TARGET_AND_RESPONSE_UNAVAILABLE",
                    "A /browser/ or /db/ path does not establish Neo4j identity, externally accessible UI, or authentication outcome."),
                "R447" => ("RABBITMQ_MANAGEMENT_TARGET_AND_RESPONSE_UNAVAILABLE",
                    "RabbitMQ-looking management routes are request shapes, not authenticated service identity or access outcome."),
                "R448" => ("KAFKA_BROKER_REQUEST_RESPONSE_UNAVAILABLE",
                    "TCP/9092 or Kafka text cannot prove an attributed Kafka request/response exchange or external authorization."),
                "R449" => ("ZOOKEEPER_FOUR_LETTER_COMMAND_UNAVAILABLE",
                    "Port 2181 or words such as ruok/stat do not prove an attributed four-letter command and server reply."),
                "R450" => ("NATS_CLIENT_SERVER_HANDSHAKE_UNAVAILABLE",
                    "NATS client, cluster and monitoring ports cannot prove an INFO/CONNECT exchange or external broker access."),
                // GA R451-R452 — SOURCE CANDIDATE — UNVERIFIED.
                "R451" => ("MQTT_ANONYMOUS_CONNECT_OUTCOME_UNAVAILABLE",
                    "The bounded MQTT parser observes some CONNECT frames but does not retain username/password flag provenance or a correlated CONNACK acceptance; anonymous login is not established."),
                "R452" => ("DATABASE_RESULT_EXPORT_CORRELATION_UNAVAILABLE",
                    "Transfer bytes and database-looking traffic do not establish a decoded query, result-set size, destination authorization or a correlated external export."),
                _ => null
            };
    }
}
