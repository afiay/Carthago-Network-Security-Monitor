// SPDX-License-Identifier: MIT
// GA R441-R450 — SOURCE CANDIDATE — UNVERIFIED.
// 170 concrete authored xUnit invocations: 16 independent adversarial /
// benign / boundary variants plus one original-profile invariant per rule.
// ZERO tests executed; no native protocol or server-response provenance is
// fabricated by these fixtures.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch441450AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 8, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Name, string Reason, string Path, int Port, bool Http)[] Rules =
    {
            ("R441", "Cassandra CQL External Probe", "CASSANDRA_CQL_NATIVE_FRAME_PROVENANCE_UNAVAILABLE", "", 9042, false),
            ("R442", "Oracle TNS Enumeration", "ORACLE_TNS_HANDSHAKE_PROVENANCE_UNAVAILABLE", "", 1521, false),
            ("R443", "CouchDB Admin Probe", "COUCHDB_TARGET_AND_RESPONSE_UNAVAILABLE", "/_node/_local/_config", 5984, true),
            ("R444", "InfluxDB Query Endpoint Exposure", "INFLUXDB_QUERY_ACCESS_OUTCOME_UNAVAILABLE", "/query", 8086, true),
            ("R445", "ClickHouse HTTP SQL Probe", "CLICKHOUSE_SQL_REQUEST_RESPONSE_UNAVAILABLE", "/?query=SELECT%201", 8123, true),
            ("R446", "Neo4j Browser Exposure Probe", "NEO4J_BROWSER_TARGET_AND_RESPONSE_UNAVAILABLE", "/browser/", 7474, true),
            ("R447", "RabbitMQ Management Probe", "RABBITMQ_MANAGEMENT_TARGET_AND_RESPONSE_UNAVAILABLE", "/api/overview", 15672, true),
            ("R448", "Kafka Broker External Access", "KAFKA_BROKER_HANDSHAKE_UNAVAILABLE", "", 9092, false),
            ("R449", "Zookeeper Four Letter Word Probe", "ZOOKEEPER_FOUR_LETTER_COMMAND_UNAVAILABLE", "", 2181, false),
            ("R450", "NATS Broker External Access", "NATS_CLIENT_SERVER_HANDSHAKE_UNAVAILABLE", "", 4222, false),
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
        {
            foreach (var variation in new[]
            {
                "plausible", "descriptor-spoof", "approved-ops", "forged-audit",
                "tls-only", "missing-source", "malformed-target", "secret-placeholder",
                "wrong-direction", "wrong-protocol", "threshold-burst", "claimed-success",
                "duplicate-id", "spoofed-service-name", "fragmentary-native",
                "after-cooldown"
            })
            {
                yield return new object[]
                {
                    rule.Id, rule.Name, rule.Reason, rule.Path, rule.Port, rule.Http, variation
                };
            }
        }
    }

    private static TrafficRecord Observation(string path, int port, bool http)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "8.8.8.8",
            Destination = "10.94.2.10",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            SourcePort = 50321,
            DestinationPort = port,
            ApplicationProtocol = http ? "HTTP" : "TCP",
            HttpMethod = http ? "GET" : null,
            HttpUri = http ? path : null,
            HttpHost = http ? "service.example.test" : null,
            HttpRequestHeaders = http ? "User-Agent: ordinary-client" : null,
            Info = string.Empty,
            Length = 512,
            L4Len = 512
        };

    private static Task<RuleEvaluationResult> Evaluate(string id, TrafficRecord record, int seconds = 0)
    {
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
        return id switch
        {
            "R441" => new R441_CassandraCQLExternalProbeRule().EvaluateAsync(context).AsTask(),
            "R442" => new R442_OracleTNSEnumerationRule().EvaluateAsync(context).AsTask(),
            "R443" => new R443_CouchDBAdminProbeRule().EvaluateAsync(context).AsTask(),
            "R444" => new R444_InfluxDBQueryEndpointExposureRule().EvaluateAsync(context).AsTask(),
            "R445" => new R445_ClickHouseHTTPSQLProbeRule().EvaluateAsync(context).AsTask(),
            "R446" => new R446_Neo4jBrowserExposureProbeRule().EvaluateAsync(context).AsTask(),
            "R447" => new R447_RabbitMQManagementProbeRule().EvaluateAsync(context).AsTask(),
            "R448" => new R448_KafkaBrokerExternalAccessRule().EvaluateAsync(context).AsTask(),
            "R449" => new R449_ZookeeperFourLetterWordProbeRule().EvaluateAsync(context).AsTask(),
            "R450" => new R450_NATSBrokerExternalAccessRule().EvaluateAsync(context).AsTask(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
    }

    private static void AssertNoEvidencePromotion(RuleEvaluationResult result, string reason)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Clues_Do_Not_Prove_Native_Protocol_Service_Or_Outcome(
        string id, string name, string reason, string path, int port, bool http, string variation)
    {
        var record = Observation(path, port, http);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = name + " verified exploit and authenticated access";
                break;
            case "approved-ops":
                record.ProcessName = "approved-monitor.exe";
                record.Info = "scheduled backup, health check, message broker client, DBA migration";
                record.HttpUri = http ? "/health" : null;
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Verified-Product: " + name +
                    "\r\nX-Authenticated-Audit: true\r\nX-Server-Outcome: success";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpHost = null;
                record.HttpRequestHeaders = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "malformed-target":
                record.HttpUri = "/%ZZ/%00";
                record.HttpMethod = "INVALID";
                record.Info = "truncated native protocol frame";
                break;
            case "secret-placeholder":
                record.HttpUri = "/api/query?token=synthetic-not-a-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-do-not-log";
                break;
            case "wrong-direction":
                record.Source = "10.94.2.11";
                break;
            case "wrong-protocol":
                record.Protocol = "UDP";
                record.ApplicationProtocol = "UDP";
                record.IsTcp = false;
                record.IsUdp = true;
                break;
            case "threshold-burst":
                // R442 originally requires four observations. Repetition
                // must not invent an Oracle TNS handshake (or any producer).
                for (var i = 0; i < 5; i++)
                {
                    var intermediate = await Evaluate(id, Observation(path, port, http), i * 10);
                    AssertNoEvidencePromotion(intermediate, reason);
                }
                break;
            case "claimed-success":
                record.Info = name + " server accepted, HTTP 200, authentication succeeded";
                break;
            case "duplicate-id":
                var duplicate = Observation(path, port, http);
                duplicate.Id = record.Id;
                AssertNoEvidencePromotion(await Evaluate(id, duplicate, 20), reason);
                break;
            case "spoofed-service-name":
                record.HttpHost = "claimed-" + id.ToLowerInvariant() + ".example.test";
                record.ProcessName = name + "-server.exe";
                record.ApplicationProtocol = name;
                break;
            case "fragmentary-native":
                record.Info = "CQL OPTIONS; TNS CONNECT; Kafka ApiVersions; ZooKeeper ruok; NATS INFO";
                record.Length = 1;
                record.L4Len = 1;
                break;
            case "after-cooldown":
                // A claimed cooldown expiration cannot repair missing
                // protocol/server evidence or create a new alert.
                AssertNoEvidencePromotion(await Evaluate(id, Observation(path, port, http), 0), reason);
                AssertNoEvidencePromotion(await Evaluate(id, Observation(path, port, http), 31 * 60), reason);
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 62 * 60 : 60);
        if (variation == "missing-source")
        {
            Assert.False(result.Matched);
            Assert.Empty(result.Events);
            Assert.Contains(result.NoMatchReasons, item => item.Code == "MISSING_CORE_TELEMETRY");
        }
        else
        {
            AssertNoEvidencePromotion(result, reason);
        }
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R441", 1, 82, 15, 30 };
        yield return new object[] { "R442", 4, 82, 10, 30 };
        yield return new object[] { "R443", 1, 82, 15, 30 };
        yield return new object[] { "R444", 1, 82, 15, 30 };
        yield return new object[] { "R445", 1, 82, 15, 30 };
        yield return new object[] { "R446", 1, 82, 15, 30 };
        yield return new object[] { "R447", 1, 82, 15, 30 };
        yield return new object[] { "R448", 1, 82, 15, 30 };
        yield return new object[] { "R449", 1, 82, 15, 30 };
        yield return new object[] { "R450", 1, 82, 15, 30 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Confidence_Threshold_Window_And_Cooldown_Are_Unchanged(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = id switch
        {
            "R441" => new R441_CassandraCQLExternalProbeRule().PrecisionProfile,
            "R442" => new R442_OracleTNSEnumerationRule().PrecisionProfile,
            "R443" => new R443_CouchDBAdminProbeRule().PrecisionProfile,
            "R444" => new R444_InfluxDBQueryEndpointExposureRule().PrecisionProfile,
            "R445" => new R445_ClickHouseHTTPSQLProbeRule().PrecisionProfile,
            "R446" => new R446_Neo4jBrowserExposureProbeRule().PrecisionProfile,
            "R447" => new R447_RabbitMQManagementProbeRule().PrecisionProfile,
            "R448" => new R448_KafkaBrokerExternalAccessRule().PrecisionProfile,
            "R449" => new R449_ZookeeperFourLetterWordProbeRule().PrecisionProfile,
            "R450" => new R450_NATSBrokerExternalAccessRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
