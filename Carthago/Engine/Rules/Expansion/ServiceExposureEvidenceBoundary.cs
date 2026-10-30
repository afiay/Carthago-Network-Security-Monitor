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
                _ => null
            };
    }
}
