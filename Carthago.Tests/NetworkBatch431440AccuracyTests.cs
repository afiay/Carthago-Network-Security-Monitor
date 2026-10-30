// SPDX-License-Identifier: MIT
// GA R431-R440 — SOURCE CANDIDATE — UNVERIFIED.
// 140 authored xUnit invocations: 13 adversarial cases + 1 profile
// invariant per rule; ZERO executed. No authenticated database/service
// evidence is manufactured by these fixtures.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch431440AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 7, 0, 0, DateTimeKind.Utc);

    public static IEnumerable<object[]> MissingProducerCases()
    {
        var rules = new (string Id, string Name, string Reason, string Path, int Port, bool Http)[]
        {
            ("R431", "Airflow Admin Endpoint Probe", "AIRFLOW_TARGET_AND_PROBE_PROVENANCE_UNAVAILABLE", "/api/v1/dags", 8080, true),
            ("R432", "Consul Nomad Admin Probe", "CONSUL_NOMAD_TARGET_AND_PROBE_UNAVAILABLE", "/v1/agent", 8500, true),
            ("R433", "PostgreSQL External Login Attempt", "POSTGRES_AUTH_HANDSHAKE_UNAVAILABLE", "", 5432, false),
            ("R434", "MySQL External Login Attempt", "MYSQL_AUTH_HANDSHAKE_UNAVAILABLE", "", 3306, false),
            ("R435", "MSSQL External Login Attempt", "MSSQL_TDS_LOGIN_PROVENANCE_UNAVAILABLE", "", 1433, false),
            ("R436", "MongoDB External Exposure Probe", "MONGODB_WIRE_EXPOSURE_PROVENANCE_UNAVAILABLE", "", 27017, false),
            ("R437", "Redis CONFIG SET Indicator", "REDIS_RESP_CONFIG_SET_UNAVAILABLE", "", 6379, false),
            ("R438", "Redis Replication Abuse Indicator", "REDIS_RESP_REPLICATION_UNAVAILABLE", "", 6379, false),
            ("R439", "Memcached Stats Enumeration", "MEMCACHED_STATS_COMMAND_SEQUENCE_UNAVAILABLE", "", 11211, false),
            ("R440", "Elasticsearch Snapshot Repository Probe", "ELASTIC_SNAPSHOT_TARGET_AND_RESPONSE_UNAVAILABLE", "/_snapshot", 9200, true)
        };
        foreach (var rule in rules)
        {
            foreach (var variation in new[]
            {
                "plausible", "descriptor-spoof", "benign-maintenance",
                "forged-audit", "tls-only", "missing-source", "malformed-path",
                "privacy-placeholder", "wrong-direction", "wrong-protocol",
                "repeated-threshold", "claimed-success", "duplicate-id"
            })
                yield return new object[]
                {
                    rule.Id, rule.Name, rule.Reason, rule.Path, rule.Port, rule.Http, variation
                };
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
            "R431" => new R431_AirflowAdminEndpointProbeRule().EvaluateAsync(context).AsTask(),
            "R432" => new R432_ConsulNomadAdminProbeRule().EvaluateAsync(context).AsTask(),
            "R433" => new R433_PostgreSQLExternalLoginAttemptRule().EvaluateAsync(context).AsTask(),
            "R434" => new R434_MySQLExternalLoginAttemptRule().EvaluateAsync(context).AsTask(),
            "R435" => new R435_MSSQLExternalLoginAttemptRule().EvaluateAsync(context).AsTask(),
            "R436" => new R436_MongoDBExternalExposureProbeRule().EvaluateAsync(context).AsTask(),
            "R437" => new R437_RedisCONFIGSETIndicatorRule().EvaluateAsync(context).AsTask(),
            "R438" => new R438_RedisReplicationAbuseIndicatorRule().EvaluateAsync(context).AsTask(),
            "R439" => new R439_MemcachedStatsEnumerationRule().EvaluateAsync(context).AsTask(),
            "R440" => new R440_ElasticsearchSnapshotRepositoryProbeRule().EvaluateAsync(context).AsTask(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Clues_Cannot_Prove_Service_Or_Protocol_Outcome(
        string id, string name, string reason, string path, int port, bool http, string variation)
    {
        var record = Observation(path, port, http);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = name + " verified compromise successful";
                break;
            case "benign-maintenance":
                record.ProcessName = "approved-monitor.exe";
                record.Info = "scheduled DBA backup, Airflow DAG inventory, health check";
                record.HttpUri = http ? "/health" : null;
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Authenticated-Audit: true\r\nX-Login-Outcome: success\r\nX-Product-Verified: " + name;
                record.Info = "verified audit log";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpRequestHeaders = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "malformed-path":
                record.HttpUri = "/%ZZ/../admin";
                record.Info = "malformed native protocol request";
                break;
            case "privacy-placeholder":
                record.HttpUri = "/_snapshot?token=synthetic-placeholder";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-placeholder-not-a-credential";
                break;
            case "wrong-direction":
                record.Source = "10.94.2.11";
                record.Destination = "10.94.2.10";
                break;
            case "wrong-protocol":
                record.Protocol = "UDP";
                record.ApplicationProtocol = "UDP";
                record.IsTcp = false;
                record.IsUdp = true;
                break;
            case "claimed-success":
                record.Info = name + " HTTP 200, authenticated login and command succeeded";
                break;
            case "repeated-threshold":
                // R439's original threshold is four. Independent traffic
                // without Memcached command provenance cannot reach it.
                for (var i = 0; i < 4; i++)
                {
                    var interim = await Evaluate(id, Observation(path, port, http), i * 10);
                    Assert.False(interim.Matched);
                    Assert.Empty(interim.Events);
                    Assert.Contains(interim.NoMatchReasons, item => item.Code == reason);
                }
                break;
            case "duplicate-id":
                var duplicateId = record.Id;
                var duplicate = Observation(path, port, http);
                duplicate.Id = duplicateId;
                var earlier = await Evaluate(id, duplicate, 20);
                Assert.False(earlier.Matched);
                Assert.Empty(earlier.Events);
                break;
        }

        var result = await Evaluate(id, record, variation == "repeated-threshold" ? 50 : 0);
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        if (variation != "missing-source")
            Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R431", 1, 82, 10, 30 };
        yield return new object[] { "R432", 1, 82, 10, 30 };
        yield return new object[] { "R433", 1, 82, 15, 30 };
        yield return new object[] { "R434", 1, 82, 15, 30 };
        yield return new object[] { "R435", 1, 82, 15, 30 };
        yield return new object[] { "R436", 1, 82, 15, 30 };
        yield return new object[] { "R437", 1, 82, 15, 30 };
        yield return new object[] { "R438", 1, 82, 15, 30 };
        yield return new object[] { "R439", 4, 82, 10, 30 };
        yield return new object[] { "R440", 1, 82, 15, 30 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Profile_And_Thresholds_Remain_Unchanged(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = id switch
        {
            "R431" => new R431_AirflowAdminEndpointProbeRule().PrecisionProfile,
            "R432" => new R432_ConsulNomadAdminProbeRule().PrecisionProfile,
            "R433" => new R433_PostgreSQLExternalLoginAttemptRule().PrecisionProfile,
            "R434" => new R434_MySQLExternalLoginAttemptRule().PrecisionProfile,
            "R435" => new R435_MSSQLExternalLoginAttemptRule().PrecisionProfile,
            "R436" => new R436_MongoDBExternalExposureProbeRule().PrecisionProfile,
            "R437" => new R437_RedisCONFIGSETIndicatorRule().PrecisionProfile,
            "R438" => new R438_RedisReplicationAbuseIndicatorRule().PrecisionProfile,
            "R439" => new R439_MemcachedStatsEnumerationRule().PrecisionProfile,
            "R440" => new R440_ElasticsearchSnapshotRepositoryProbeRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
