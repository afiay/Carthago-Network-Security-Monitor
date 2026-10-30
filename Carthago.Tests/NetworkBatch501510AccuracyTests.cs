// SPDX-License-Identifier: MIT
// GA R501-R510 — SOURCE CANDIDATE — UNVERIFIED.
// 230 concrete xUnit invocations AUTHORED, ZERO EXECUTED:
// 22 distinct adversarial/benign/boundary cases + 1 profile invariant per rule.
// Synthetic TrafficRecord labels and forged headers are NOT authenticated uploads.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch501510AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 14, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, string Host, string Application,
        string Method, string Path, int Threshold, int Window)[] Rules =
    {
        ("R501", "MULTIPART_PART_FILENAME_ENTROPY_AND_UPLOAD_CORRELATION_UNAVAILABLE", "upload.example.test", "http", "POST", "/submit", 4, 10),
        ("R502", "DATA_URI_REQUEST_BODY_AND_UPLOAD_VOLUME_UNAVAILABLE", "upload.example.test", "http", "POST", "/submit?data=base64%2Csynthetic", 1, 20),
        ("R503", "PASTEBIN_POST_RESPONSE_AND_DISTINCT_BULK_UNAVAILABLE", "pastebin.com", "http", "POST", "/api/api_post.php", 4, 10),
        ("R504", "GIST_SECRET_CONTENT_AND_CREATE_OUTCOME_UNAVAILABLE", "api.github.com", "http", "POST", "/gists", 1, 20),
        ("R505", "DISCORD_ATTACHMENT_UPLOAD_AND_BURST_CORRELATION_UNAVAILABLE", "discord.com", "http", "POST", "/api/v10/channels/123/messages", 4, 10),
        ("R506", "TELEGRAM_DOCUMENT_UPLOAD_AND_BURST_CORRELATION_UNAVAILABLE", "api.telegram.org", "http", "POST", "/botSYNTHETIC/sendDocument", 4, 10),
        ("R507", "MEGA_UPLOAD_TRANSACTION_AND_OUTCOME_UNAVAILABLE", "mega.nz", "http", "POST", "/api", 1, 20),
        ("R508", "RCLONE_PROCESS_USERAGENT_AND_EGRESS_PROVENANCE_UNAVAILABLE", "storage.example.test", "http", "PUT", "/bucket/object", 1, 20),
        ("R509", "RSYNC_PUSH_DIRECTION_AND_REMOTE_OUTCOME_UNAVAILABLE", "rsync.example.test", "rsync", "CONNECT", "/push", 1, 20),
        ("R510", "S3_COMPATIBLE_ENDPOINT_IDENTITY_AND_UPLOAD_OUTCOME_UNAVAILABLE", "objects.example.test", "http", "PUT", "/bucket/object", 1, 20)
    };

    private static readonly string[] Variations =
    {
        "plausible",
        "descriptor-spoof",
        "approved-workflow",
        "forged-audit",
        "tls-only",
        "missing-source",
        "missing-destination",
        "malformed-target",
        "synthetic-secret",
        "inbound",
        "wrong-protocol",
        "threshold-burst",
        "claimed-success",
        "duplicate-id",
        "spoofed-process",
        "truncated-body",
        "after-cooldown",
        "provider-lookalike",
        "request-only",
        "response-only",
        "multipart-header-only",
        "oversized-packet"
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in Variations)
                yield return new object[] { rule.Id, rule.Reason, rule.Host, rule.Application, rule.Method, rule.Path, variation };
    }

    private static TrafficRecord Observation(string id, string host, string application, string method, string path)
        => new()
        {
            Id = Guid.Parse("a57f2d61-8f45-489a-9ef7-1b1d4c11b12a"),
            Source = "10.64.2.11",
            Destination = "203.0.113.20",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            SourcePort = 50321,
            DestinationPort = id == "R509" ? 873 : 443,
            ApplicationProtocol = application,
            HttpMethod = method,
            HttpUri = path,
            HttpHost = host,
            HttpUserAgent = id == "R508" ? "rclone/v1.0 (synthetic)" : "synthetic-client/1.0",
            ProcessName = id == "R509" ? "rsync.exe" : "curl.exe",
            Info = id + " claimed outbound file transfer",
            Length = 6 * 1024 * 1024,
            L4Len = 512
        };

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R501" => new R501_MultipartFormDataHighEntropyFilenameRule(),
            "R502" => new R502_DataURIBase64POSTLargeRule(),
            "R503" => new R503_PastebinRawPOSTBulkRule(),
            "R504" => new R504_GitHubGistSecretPostRule(),
            "R505" => new R505_DiscordAttachmentUploadBurstRule(),
            "R506" => new R506_TelegramDocumentExfilBurstRule(),
            "R507" => new R507_MegaNZUploadPatternRule(),
            "R508" => new R508_RcloneUserAgentEgressRule(),
            "R509" => new R509_RsyncExternalPushRule(),
            "R510" => new R510_S3CompatibleUnknownEndpointUploadRule(),
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
    public async Task Request_And_Process_Clues_Cannot_Prove_Upload_Content_Or_Outcome(
        string id, string reason, string host, string application, string method, string path, string variation)
    {
        var record = Observation(id, host, application, method, path);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info += " " + id + " confirmed malicious secret exfiltration";
                break;
            case "approved-workflow":
                record.ProcessName = "approved-backup-agent.exe";
                record.Info += " authorized backup, helpdesk ticket and developer workflow";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Upload-Verified: true\r\nX-Authenticated-Agent: true\r\nX-Object-Write-Succeeded: true";
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
            case "malformed-target":
                record.HttpUri = "/%zz?filename=synthetic";
                record.Length = 1;
                record.L4Len = 1;
                break;
            case "synthetic-secret":
                record.HttpUri = "/upload?token=[REDACTED]";
                record.HttpRequestHeaders = "Authorization: [REDACTED]";
                break;
            case "inbound":
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
                    var distinct = Observation(id, host, application, method, path);
                    distinct.Id = Guid.Parse($"a57f2d61-8f45-489a-9ef7-1b1d4c11b1{i:D2}");
                    AssertMissingProducer(await Evaluate(id, distinct, i * 10), reason);
                }
                break;
            case "claimed-success":
                record.Info += " HTTP 201, successful upload, file exfiltration complete";
                break;
            case "duplicate-id":
                AssertMissingProducer(await Evaluate(id, Observation(id, host, application, method, path), 20), reason);
                break;
            case "spoofed-process":
                record.ProcessName = "trusted-rclone.exe";
                record.ApplicationService = "authenticated-cloud-agent";
                break;
            case "truncated-body":
                record.Length = 1;
                record.L4Len = 0;
                record.HttpRequestHeaders = "Content-Type: multipart/form-data; boundary=synthetic";
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id, Observation(id, host, application, method, path)), reason);
                AssertMissingProducer(await Evaluate(id, Observation(id, host, application, method, path), 40 * 60), reason);
                break;
            case "provider-lookalike":
                record.HttpHost = "api-github-discord-mega.example.test";
                record.Sni = "api-github-discord-mega.example.test";
                break;
            case "request-only":
                record.HttpMethod = "PUT";
                record.Info += " request submitted; no correlated response";
                break;
            case "response-only":
                record.HttpMethod = null;
                record.HttpUri = null;
                record.Info = "HTTP 200 response label without a correlated request";
                break;
            case "multipart-header-only":
                record.HttpRequestHeaders = "Content-Type: multipart/form-data; boundary=synthetic\r\nContent-Disposition: form-data; filename=synthetic.txt";
                break;
            case "oversized-packet":
                record.Length = 32 * 1024 * 1024;
                record.L4Len = 512;
                record.Info += " packet length is not a completed upload volume";
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 80 * 60 : 60);
        if (variation is "missing-source" or "missing-destination")
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
            yield return new object[] { rule.Id, rule.Threshold, rule.Window };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Mode_Confidence_Threshold_Window_And_Cooldown_Remain(
        string id, int threshold, int windowMinutes)
    {
        var profile = CreateRule(id).PrecisionProfile;
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(84, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(35), profile.Cooldown);
    }
}
