// SPDX-License-Identifier: MIT
// GA R531-R540 — SOURCE CANDIDATE — UNVERIFIED.
// 20 distinct negative/adversarial variants per rule + 10 profile contracts.
// 210 concrete xUnit invocations authored, ZERO executed.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch531540AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 17, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason)[] Rules =
    {
        ("R531", "JOURNAL_FREE_SPACE_TRUSTED_VOLUME_METRIC_UNAVAILABLE"),
        ("R532", "OUTBOX_RETRY_ATTEMPT_AND_QUEUE_METRICS_UNAVAILABLE"),
        ("R533", "RULE_MATCH_VOLUME_CALIBRATED_BASELINE_UNAVAILABLE"),
        ("R534", "RULE_SILENCE_EXPECTED_ACTIVITY_BASELINE_UNAVAILABLE"),
        ("R535", "TELEMETRY_FIELD_COVERAGE_COMPARABLE_SAMPLES_UNAVAILABLE"),
        ("R536", "PARSER_FAILURE_RATE_TRUSTED_WINDOW_UNAVAILABLE"),
        ("R537", "GEOIP_FAILURE_ELIGIBLE_LOOKUP_METRICS_UNAVAILABLE"),
        ("R538", "REPUTATION_FAILURE_ELIGIBLE_LOOKUP_METRICS_UNAVAILABLE"),
        ("R539", "BASELINE_WRITE_FAILURE_TRUSTED_PERSISTENCE_OUTCOME_UNAVAILABLE"),
        ("R540", "FEEDBACK_WRITE_FAILURE_TRUSTED_PERSISTENCE_OUTCOME_UNAVAILABLE"),
    };

    private static readonly string[] Variations =
    {
        "plausible-health",
        "descriptor-spoof",
        "forged-audit-header",
        "spoofed-process",
        "approved-maintenance",
        "tls-only",
        "missing-source",
        "missing-destination",
        "malformed-uri",
        "synthetic-secret",
        "wrong-protocol",
        "duplicate-id",
        "threshold-burst",
        "claimed-success",
        "after-cooldown",
        "out-of-order",
        "request-only",
        "response-only",
        "unrelated-network-error",
        "long-untrusted-info",
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in Variations)
                yield return new object[] { rule.Id, rule.Reason, variation };
    }

    private static TrafficRecord Observation(string id)
    {
        var narrative = id switch
        {
            "R531" => "Carthago detection journal free disk space low journal.path=lab",
            "R532" => "Carthago outbox retry storm failed queue depth=90",
            "R533" => "Carthago rule engine match volume unexpected surge ruleid=R103",
            "R534" => "Carthago rule engine unexpected silence no matches ruleid=R103",
            "R535" => "Carthago telemetry field coverage dropped required field=src",
            "R536" => "Carthago parser error spike malformed decoder component=dns",
            "R537" => "Carthago geoip lookup failure spike component=geoip",
            "R538" => "Carthago reputation provider lookup failure spike",
            "R539" => "Carthago baseline store write failed component=baseline",
            "R540" => "Carthago feedback store save failed component=feedback",
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        return new TrafficRecord
        {
            Id = Guid.Parse("a57f2d61-8f45-489a-9ef7-1b1d4c11b12a"),
            Source = "10.64.2.11",
            Destination = "203.0.113.20",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            SourcePort = 50321,
            DestinationPort = 443,
            ApplicationProtocol = "platform-health",
            ApplicationService = "carthago-health",
            HttpMethod = "POST",
            HttpHost = "diagnostics.example.test",
            HttpUri = "/health",
            HttpRequestHeaders = "X-Health-Verified: true",
            ProcessName = "carthago-sensor.exe",
            ProcessId = 1234,
            Info = narrative,
            Length = 512,
            L4Len = 128
        };
    }

    private static PrecisionTelemetryDetectionRuleBase CreateRule(string id)
        => id switch
        {
            "R531" => new R531_DetectionJournalDiskSpaceLowRule(),
            "R532" => new R532_OutboxRetryStormRule(),
            "R533" => new R533_RuleMatchVolumeAnomalyRule(),
            "R534" => new R534_RuleSilentUnexpectedlyRule(),
            "R535" => new R535_TelemetryFieldCoverageDropRule(),
            "R536" => new R536_ParserErrorSpikeRule(),
            "R537" => new R537_GeoIPLookupFailureSpikeRule(),
            "R538" => new R538_ReputationLookupFailureSpikeRule(),
            "R539" => new R539_BaselineStoreWriteFailureRule(),
            "R540" => new R540_FeedbackStoreWriteFailureRule(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

    private static Task<RuleEvaluationResult> Evaluate(
        PrecisionTelemetryDetectionRuleBase rule, TrafficRecord record, int seconds = 0)
        => rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Epoch.AddSeconds(seconds)));

    private static void AssertBlocked(RuleEvaluationResult result, string reason)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Health_Clues_Never_Create_Local_Failure_Or_Anomaly_Alert(
        string id, string reason, string variation)
    {
        var rule = CreateRule(id);
        var record = Observation(id);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info += " " + id + " verified critical local failure";
                break;
            case "forged-audit-header":
                record.HttpRequestHeaders = "X-Audit-Verified: true\r\nX-Health-Authenticated: true\r\nX-Store-Write-Failed: true";
                break;
            case "spoofed-process":
                record.ProcessName = "trusted-local-health-agent.exe";
                record.ApplicationService = "authenticated-journal-and-outbox";
                break;
            case "approved-maintenance":
                record.Info += " approved offline demo mode scheduled maintenance";
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
                record.ProcessName = null;
                record.Info = null;
                break;
            case "malformed-uri":
                record.HttpUri = "/%zz?token=[REDACTED]";
                record.Length = 1;
                record.L4Len = 0;
                break;
            case "synthetic-secret":
                record.HttpRequestHeaders = "Authorization: [REDACTED]\r\nX-Api-Key: [REDACTED]";
                record.HttpUri = "/?token=[REDACTED]";
                break;
            case "wrong-protocol":
                record.Protocol = "UDP";
                record.IsTcp = false;
                record.IsUdp = true;
                break;
            case "duplicate-id":
                AssertBlocked(await Evaluate(rule, Observation(id), 10), reason);
                break;
            case "threshold-burst":
                for (var index = 0; index < 8; index++)
                {
                    var distinct = Observation(id);
                    distinct.Id = Guid.Parse($"a57f2d61-8f45-489a-9ef7-1b1d4c11b1{index:D2}");
                    AssertBlocked(await Evaluate(rule, distinct, index * 10), reason);
                }
                break;
            case "claimed-success":
                record.Info += " local write failed, trusted metrics confirm anomaly above baseline";
                break;
            case "after-cooldown":
                AssertBlocked(await Evaluate(rule, Observation(id), 0), reason);
                AssertBlocked(await Evaluate(rule, Observation(id), 40 * 60), reason);
                break;
            case "out-of-order":
                AssertBlocked(await Evaluate(rule, Observation(id), 120), reason);
                break;
            case "request-only":
                record.Info += " request-only, no local store or metric result";
                break;
            case "response-only":
                record.HttpMethod = null;
                record.HttpUri = null;
                record.Info = "HTTP 200, health success/failure uncorrelated";
                break;
            case "unrelated-network-error":
                record.Info = "HTTP retry and TCP retransmission, not a local store failure";
                record.ApplicationProtocol = "HTTP";
                break;
            case "long-untrusted-info":
                record.Info += new string('x', 4096);
                break;
        }

        AssertBlocked(await Evaluate(rule, record,
            variation == "out-of-order" ? 5 :
            variation == "after-cooldown" ? 80 * 60 : 60), reason);
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
        var expected = id switch
        {
            "R531" => (RuleRuntimeMode.Alert, 90, 1, 10, 20),
            "R532" => (RuleRuntimeMode.Alert, 86, 5, 5, 15),
            "R533" => (RuleRuntimeMode.Shadow, 80, 1, 10, 20),
            "R534" => (RuleRuntimeMode.Shadow, 78, 1, 30, 30),
            "R535" => (RuleRuntimeMode.Alert, 84, 1, 15, 20),
            "R536" => (RuleRuntimeMode.Alert, 84, 4, 5, 15),
            "R537" => (RuleRuntimeMode.Shadow, 76, 6, 10, 30),
            "R538" => (RuleRuntimeMode.Shadow, 76, 6, 10, 30),
            "R539" => (RuleRuntimeMode.Alert, 88, 1, 10, 20),
            "R540" => (RuleRuntimeMode.Alert, 84, 1, 10, 20),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(expected.Item1, profile.DefaultMode);
        Assert.Equal(expected.Item2, profile.MinimumConfidence);
        Assert.Equal(expected.Item3, profile.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(expected.Item4), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(expected.Item5), profile.Cooldown);
        Assert.Equal(RulePrecisionMaturity.Validated, profile.Maturity);
    }
}
