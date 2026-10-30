// SPDX-License-Identifier: MIT
// GA R521-R530 — SOURCE CANDIDATE — UNVERIFIED.
// 270 parameterized xUnit invocations AUTHORED; ZERO EXECUTED.
// 26 distinct synthetic variants and one profile invariant per rule.
// No trusted audit, decrypted traffic or real credential is fabricated.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch521530AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 16, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason)[] Rules =
    {
        ("R521", "HTTP_CONNECT_PROXY_PORT_POLICY_AND_SESSION_UNAVAILABLE"),
        ("R522", "WEBSOCKET_UPGRADE_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE"),
        ("R523", "DOMAIN_FRONTING_SNI_HTTP_AUTHORITY_CORRELATION_UNAVAILABLE"),
        ("R524", "ECH_PROVIDER_APPROVAL_AND_HANDSHAKE_PROVENANCE_UNAVAILABLE"),
        ("R525", "QUIC_CID_ROTATION_SESSION_BASELINE_UNAVAILABLE"),
        ("R526", "PACKET_SIZE_MIMICRY_CALIBRATED_BASELINE_UNAVAILABLE"),
        ("R527", "SLEEPY_BEACON_LONG_GAP_BASELINE_UNAVAILABLE"),
        ("R528", "USER_AGENT_DISTINCT_REQUEST_BASELINE_UNAVAILABLE"),
        ("R529", "SENSOR_HEARTBEAT_TRUSTED_HEALTH_PRODUCER_UNAVAILABLE"),
        ("R530", "SENSOR_CLOCK_SKEW_TRUSTED_METRIC_PRODUCER_UNAVAILABLE"),
    };

    private static readonly string[] Variations =
    {
        "plausible", "descriptor-spoof", "approved-admin", "forged-audit",
        "tls-only", "missing-source", "missing-destination", "malformed-target",
        "synthetic-secret", "inbound", "wrong-protocol", "threshold-burst",
        "claimed-success", "duplicate-id", "spoofed-process", "quic-cid-only",
        "ech-claim-only", "after-cooldown", "provider-lookalike", "request-only",
        "response-only", "host-sni-mismatch-unpaired", "out-of-order",
        "useragent-rotation", "heartbeat-prose", "clock-drift-prose"
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in Variations)
                yield return new object[] { rule.Id, rule.Reason, variation };
    }

    private static TrafficRecord Observation(string id)
    {
        var isHealth = id is "R529" or "R530";
        var isQuic = id == "R525";
        return new TrafficRecord
        {
            Id = Guid.Parse("a57f2d61-8f45-489a-9ef7-1b1d4c11b12a"),
            Source = "10.64.2.11",
            Destination = "203.0.113.20",
            IpVersion = 4,
            Protocol = isQuic ? "UDP" : "TCP",
            IsTcp = !isQuic,
            IsUdp = isQuic,
            SourcePort = 50321,
            DestinationPort = id == "R521" ? 9443 : 443,
            ApplicationProtocol = isHealth ? "platform-health" : isQuic ? "QUIC" : "HTTP",
            HttpMethod = id == "R521" ? "CONNECT" : "GET",
            HttpUri = id == "R521" ? "203.0.113.20:9443" : "/tunnel",
            HttpHost = id == "R522" ? "203.0.113.20" : "origin.example.test",
            HttpRequestHeaders = "Upgrade: websocket\r\nConnection: Upgrade",
            HttpUserAgent = "synthetic-client/1.0",
            Sni = "front.example.test",
            ProcessName = isHealth ? "sensor-agent.exe" : "synthetic-client.exe",
            ProcessId = 1234,
            IsQuic = isQuic,
            QuicVersion = isQuic ? "v1" : null,
            QuicConnectionIdHash = isQuic ? "synthetic-hash-1" : null,
            Info = id == "R529"
                ? "Carthago sensor health site=lab heartbeat missing overdue"
                : id == "R530"
                    ? "Carthago sensor health clock skew increasing above threshold"
                    : id + " synthetic claimed tunnel, beacon or anomaly",
            Length = 512,
            L4Len = 128
        };
    }

    private static PrecisionTelemetryDetectionRuleBase CreateRule(string id)
        => id switch
        {
            "R521" => new R521_HTTPCONNECTToNonProxyPortRule(),
            "R522" => new R522_WebSocketTunnelToIPLiteralRule(),
            "R523" => new R523_DomainFrontingHostSNIMismatchRule(),
            "R524" => new R524_ECHToUnapprovedProviderRule(),
            "R525" => new R525_QUICConnectionIDRotationBurstRule(),
            "R526" => new R526_PacketSizeMimicryBeaconRule(),
            "R527" => new R527_SleepyBeaconLongGapPatternRule(),
            "R528" => new R528_UserAgentRandomizationBurstRule(),
            "R529" => new R529_SensorHeartbeatMissingForSiteRule(),
            "R530" => new R530_SensorClockSkewIncreasingRule(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

    private static async Task<RuleEvaluationResult> Evaluate(
        PrecisionTelemetryDetectionRuleBase rule, TrafficRecord record, int seconds = 0)
        => await rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Epoch.AddSeconds(seconds)));

    private static void AssertBlocked(RuleEvaluationResult result, string code)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, reason => reason.Code == code);
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Clues_Cannot_Assert_Tunnel_Beacon_Or_Sensor_Health(
        string id, string reason, string variation)
    {
        var rule = CreateRule(id);
        var record = Observation(id);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info += " " + id + " validated unauthorized success";
                break;
            case "approved-admin":
                record.Info += " approved admin proxy, browser, backup or planned sensor maintenance";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Audit-Verified: true\r\nX-Sensor-Trusted: true\r\nX-Proxy-Unauthorized: true";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpHost = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "missing-destination":
                record.Destination = null;
                record.HttpHost = null;
                record.Sni = null;
                record.DnsQname = null;
                record.ProcessName = null;
                record.Info = null;
                record.HttpUri = null;
                break;
            case "malformed-target":
                record.HttpUri = "/%zz?token=[REDACTED]";
                record.Length = 1;
                record.L4Len = 0;
                break;
            case "synthetic-secret":
                record.HttpRequestHeaders = "Authorization: [REDACTED]\r\nX-Secret: [REDACTED]";
                record.HttpUri = "/?token=[REDACTED]";
                break;
            case "inbound":
                record.Source = "203.0.113.20";
                record.Destination = "10.64.2.11";
                break;
            case "wrong-protocol":
                record.Protocol = record.IsTcp ? "UDP" : "TCP";
                record.IsTcp = !record.IsTcp;
                record.IsUdp = !record.IsUdp;
                break;
            case "threshold-burst":
                for (var index = 0; index < 6; index++)
                {
                    var distinct = Observation(id);
                    distinct.Id = Guid.Parse($"a57f2d61-8f45-489a-9ef7-1b1d4c11b1{index:D2}");
                    AssertBlocked(await Evaluate(rule, distinct, index * 10), reason);
                }
                break;
            case "claimed-success":
                record.Info += " verified ECH accepted, WebSocket tunnel established, heartbeat lost";
                break;
            case "duplicate-id":
                AssertBlocked(await Evaluate(rule, Observation(id), 20), reason);
                break;
            case "spoofed-process":
                record.ProcessName = "trusted-sensor-proxy-agent.exe";
                record.ApplicationService = "verified-health-and-tunnel";
                break;
            case "quic-cid-only":
                record.IsQuic = true;
                record.QuicVersion = "v1";
                record.QuicConnectionIdHash = "synthetic-hash-2";
                break;
            case "ech-claim-only":
                record.Info += " ECH ClientHelloOuter accepted";
                record.Sni = "public.ech.example.test";
                break;
            case "after-cooldown":
                AssertBlocked(await Evaluate(rule, Observation(id), 0), reason);
                AssertBlocked(await Evaluate(rule, Observation(id), 40 * 60), reason);
                break;
            case "provider-lookalike":
                record.Sni = "proxy-trusted-lookalike.example.test";
                record.HttpHost = record.Sni;
                break;
            case "request-only":
                record.HttpMethod = "CONNECT";
                record.Info += " request only, no proxy response";
                break;
            case "response-only":
                record.HttpMethod = null;
                record.HttpUri = null;
                record.Info = "HTTP 200 label, no correlated request";
                break;
            case "host-sni-mismatch-unpaired":
                record.HttpHost = "unpaired-origin.example.test";
                record.Sni = "unpaired-front.example.test";
                record.Info += " two unrelated sessions claimed as one";
                break;
            case "out-of-order":
                AssertBlocked(await Evaluate(rule, Observation(id), 120), reason);
                break;
            case "useragent-rotation":
                for (var index = 0; index < 5; index++)
                {
                    var distinct = Observation(id);
                    distinct.HttpUserAgent = "synthetic-browser/" + index;
                    distinct.Id = Guid.Parse($"a57f2d61-8f45-489a-9ef7-1b1d4c11b1{index:D2}");
                    AssertBlocked(await Evaluate(rule, distinct, index * 5), reason);
                }
                break;
            case "heartbeat-prose":
                record.ApplicationProtocol = "platform-health";
                record.Info = "Carthago sensor health heartbeat missing overdue site=lab";
                break;
            case "clock-drift-prose":
                record.ApplicationProtocol = "platform-health";
                record.Info = "Carthago sensor health clock skew increasing exceeded 1000ms";
                break;
        }

        var result = await Evaluate(rule, record, variation == "out-of-order" ? 5 :
            variation == "after-cooldown" ? 80 * 60 : 60);
        if (id is not ("R529" or "R530") &&
            variation is "missing-source" or "missing-destination")
        {
            AssertBlocked(result, "MISSING_CORE_TELEMETRY");
        }
        else
        {
            AssertBlocked(result, reason);
        }
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        foreach (var rule in Rules)
            yield return new object[] { rule.Id };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Mode_Confidence_Threshold_Window_Cooldown_And_Maturity_Remain(string id)
    {
        var profile = CreateRule(id).PrecisionProfile;
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(id == "R529" ? 86 : id == "R530" ? 82 : 84,
            profile.MinimumConfidence);
        Assert.Equal(id is "R525" or "R528" ? 4 :
            id is "R526" or "R527" ? 3 : 1, profile.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(id is "R526" or "R527" ? 120 :
            id is "R525" or "R528" or "R529" or "R530" ? 10 : 20),
            profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(id == "R529" ? 20 :
            id == "R530" ? 30 : 35), profile.Cooldown);
        Assert.Equal(id is "R529" or "R530" ? RulePrecisionMaturity.Validated :
            RulePrecisionMaturity.Validated, profile.Maturity);
    }
}
