// SPDX-License-Identifier: MIT
// GA R491-R500 — SOURCE CANDIDATE — UNVERIFIED.
// 230 concrete authored xUnit invocations: 22 scenarios per rule plus
// one original-profile invariant per rule. ZERO EXECUTED.
// Synthetic TrafficRecord values are not authenticated file, OT, or audit provenance.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch491500AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 13, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, int Threshold, int Confidence,
        int Window, int Cooldown, string Application)[] Rules =
    {
        ("R491", "GOOSE_LAYER2_FRAME_AND_SUBSTATION_POLICY_UNAVAILABLE", 1, 86, 10, 45, "goose"),
        ("R492", "HISTORIAN_QUERY_IDENTITY_VOLUME_AND_SOURCE_POLICY_UNAVAILABLE", 4, 86, 10, 45, "historian"),
        ("R493", "BROWSER_PASSWORD_STORE_FILE_UPLOAD_PROVENANCE_UNAVAILABLE", 1, 84, 20, 35, "http"),
        ("R494", "SSH_PRIVATE_KEY_FILE_UPLOAD_PROVENANCE_UNAVAILABLE", 1, 84, 20, 35, "http"),
        ("R495", "KEEPASS_DATABASE_FILE_UPLOAD_PROVENANCE_UNAVAILABLE", 1, 84, 20, 35, "http"),
        ("R496", "VPN_CONFIGURATION_FILE_UPLOAD_PROVENANCE_UNAVAILABLE", 1, 84, 20, 35, "http"),
        ("R497", "BROWSER_COOKIE_DATABASE_UPLOAD_PROVENANCE_UNAVAILABLE", 1, 84, 20, 35, "http"),
        ("R498", "CLIPBOARD_CONTENT_AND_SYNC_TRANSFER_PROVENANCE_UNAVAILABLE", 1, 84, 20, 35, "http"),
        ("R499", "REMOTE_DESKTOP_FILE_CHANNEL_BURST_PROVENANCE_UNAVAILABLE", 4, 84, 10, 35, "rdp"),
        ("R500", "ARCHIVE_CREATION_TO_CLOUD_UPLOAD_CORRELATION_UNAVAILABLE", 1, 84, 20, 35, "http")
    };

    private static readonly string[] Variations =
    {
        "plausible",
        "wire-label-only",
        "descriptor-spoof",
        "approved-activity",
        "forged-audit",
        "tls-only",
        "missing-source",
        "missing-destination",
        "malformed",
        "synthetic-secret",
        "wrong-direction",
        "wrong-protocol",
        "threshold-burst",
        "claimed-success",
        "duplicate-id",
        "spoofed-process",
        "fragmentary",
        "after-cooldown",
        "cross-boundary",
        "spoofed-authority",
        "request-only",
        "response-only"
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in Variations)
                yield return new object[] { rule.Id, rule.Reason, rule.Application, variation };
    }

    private static TrafficRecord Observation(string id, string application)
        => new()
        {
            Id = Guid.Parse("a57f2d61-8f45-489a-9ef7-1b1d4c11b12a"),
            Source = "10.64.2.11",
            Destination = "203.0.113.20",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            SourcePort = 50321,
            DestinationPort = 443,
            ApplicationProtocol = application,
            HttpMethod = "POST",
            HttpUri = "/synthetic-upload",
            HttpHost = "upload.example.test",
            ProcessName = "curl.exe",
            Info = id + " claimed upload or industrial operation",
            Length = 6 * 1024 * 1024,
            L4Len = 512
        };

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R491" => new R491_GOOSEMulticastOutsideSubstationRule(),
            "R492" => new R492_HistorianBulkQueryFromWorkstationRule(),
            "R493" => new R493_BrowserPasswordStoreFileUploadRule(),
            "R494" => new R494_SSHPrivateKeyUploadRule(),
            "R495" => new R495_KeePassDatabaseUploadRule(),
            "R496" => new R496_VPNConfigFileUploadRule(),
            "R497" => new R497_BrowserCookieDatabaseUploadRule(),
            "R498" => new R498_LargeClipboardSyncUploadRule(),
            "R499" => new R499_RemoteDesktopFileTransferBurstRule(),
            "R500" => new R500_CompressedArchiveThenCloudUploadRule(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

    private static Task<RuleEvaluationResult> Evaluate(string id, TrafficRecord record, int seconds = 0)
    {
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
        return CreateRule(id).EvaluateAsync(context).AsTask();
    }

    private static void AssertMissingProducer(RuleEvaluationResult result, string reason)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Clues_Cannot_Claim_Industrial_Or_Sensitive_Transfer_Provenance(
        string id, string reason, string application, string variation)
    {
        var record = Observation(id, application);
        switch (variation)
        {
            case "wire-label-only":
                record.HttpMethod = null;
                record.HttpUri = null;
                record.ApplicationProtocol = application;
                break;
            case "descriptor-spoof":
                record.Info += " verified " + id + " succeeded, file upload confirmed";
                break;
            case "approved-activity":
                record.ProcessName = "approved-backup-agent.exe";
                record.Info += " scheduled authorized historian export and endpoint backup";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-File-Upload-Verified: true\r\n" +
                    "X-OT-Operation-Authenticated: true\r\nX-Transfer-Succeeded: true";
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
                record.ProcessName = null;
                record.Info = null;
                break;
            case "malformed":
                record.HttpUri = "/%zz";
                record.Length = 1;
                record.L4Len = 1;
                break;
            case "synthetic-secret":
                // Never use or assert real credential bytes in regression fixtures.
                record.HttpUri = "/synthetic-upload?token=redacted-placeholder";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-redacted-placeholder";
                break;
            case "wrong-direction":
                record.Source = "203.0.113.20";
                record.Destination = "10.64.2.11";
                break;
            case "wrong-protocol":
                record.Protocol = "UDP";
                record.IsTcp = false;
                record.IsUdp = true;
                break;
            case "threshold-burst":
                for (var i = 0; i < 6; i++)
                {
                    var distinct = Observation(id, application);
                    distinct.Id = Guid.Parse($"a57f2d61-8f45-489a-9ef7-1b1d4c11b1{i:D2}");
                    AssertMissingProducer(await Evaluate(id, distinct, i * 10), reason);
                }
                break;
            case "claimed-success":
                record.Info += " HTTP 200, GOOSE operation accepted, cloud upload complete";
                break;
            case "duplicate-id":
                var duplicate = Observation(id, application);
                duplicate.Id = record.Id;
                AssertMissingProducer(await Evaluate(id, duplicate, 20), reason);
                break;
            case "spoofed-process":
                record.ProcessName = "trusted-file-uploader.exe";
                record.ApplicationService = "validated-historian";
                break;
            case "fragmentary":
                record.Length = 1;
                record.L4Len = 0;
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id, Observation(id, application), 0), reason);
                AssertMissingProducer(await Evaluate(id, Observation(id, application), 50 * 60), reason);
                break;
            case "cross-boundary":
                record.Source = "10.64.2.11";
                record.Destination = "198.51.100.15";
                break;
            case "spoofed-authority":
                record.HttpRequestHeaders = "X-Trusted-File-Identity: yes\r\n" +
                    "X-Approved-Substation: yes";
                record.Info += " authenticated agent and verified local file";
                break;
            case "request-only":
                record.HttpMethod = "PUT";
                record.HttpUri = "/upload?filename=synthetic.zip";
                record.Info += " request sent, no server response observed";
                break;
            case "response-only":
                record.HttpMethod = null;
                record.HttpUri = null;
                record.Info = "HTTP 200 response label without correlated upload request";
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 100 * 60 : 60);
        if (variation == "missing-source" || variation == "missing-destination")
        {
            Assert.False(result.Matched);
            Assert.Empty(result.Events);
            Assert.Contains(result.NoMatchReasons, item => item.Code == "MISSING_CORE_TELEMETRY");
        }
        else
            AssertMissingProducer(result, reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        foreach (var rule in Rules)
            yield return new object[] { rule.Id, rule.Threshold, rule.Confidence, rule.Window, rule.Cooldown };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Mode_Confidence_Threshold_Window_And_Cooldown_Remain(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = CreateRule(id).PrecisionProfile;
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
