using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.CloudSaas;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class CloudSaasPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionCloudRules()
    {
        yield return new object[] { new R104_FirstTimeCloudStorageUploadRule() };
        yield return new object[] { new R105_LargeUploadToPersonalCloudProviderRule() };
        yield return new object[] { new R106_UploadAfterInternalSweepRule() };
        yield return new object[] { new R107_ExfiltrationSplitAcrossManyDestinationsRule() };
        yield return new object[] { new R108_ExcessiveUploadRatioPerHostRule() };
        yield return new object[] { new R109_SuspiciousGitHubGitLabRawAccessRule() };
        yield return new object[] { new R110_TelegramDiscordSlackAPIEgressRule() };
        yield return new object[] { new R111_PasteSiteFileDropServiceEgressRule() };
        yield return new object[] { new R112_SaaSExportLikeTrafficPatternRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionCloudRules))]
    public async Task Precision_cloud_rules_return_no_match_without_web_or_cloud_telemetry(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.2.0.10",
            Destination = "203.0.113.10",
            DestinationPort = 443,
            Protocol = "TCP",
            IsTcp = true,
            Length = 512
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionCloudRules))]
    public async Task Precision_cloud_rules_return_no_match_for_anytext_only_input(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.2.0.20",
            Destination = "203.0.113.20",
            DestinationPort = 443,
            Protocol = "TCP",
            IsTcp = true,
            Info = "dropbox upload export webhook raw.githubusercontent.com pastebin",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R104_matches_first_seen_cloud_upload_and_not_repeat_to_same_provider()
    {
        var rule = new R104_FirstTimeCloudStorageUploadRule();
        var source = UniqueInternalIp();
        var first = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: source,
            destination: "198.51.100.10",
            host: "dropbox.com",
            method: "POST",
            uri: "/upload",
            bytes: 700_000,
            process: "powershell.exe",
            headers: "Content-Disposition: form-data; filename=finance.zip")));
        var second = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: source,
            destination: "198.51.100.10",
            host: "dropbox.com",
            method: "POST",
            uri: "/upload",
            bytes: 700_000,
            process: "powershell.exe",
            headers: "Content-Disposition: form-data; filename=finance.zip"), new DateTime(2026, 4, 29, 12, 5, 0, DateTimeKind.Utc)));

        var evt = AssertSingleEvent(first, "R104", SeverityLevel.Medium, 0.70);
        AssertEvidence(evt, "cloud.host", "cloud.providerRoot", "baseline.reason", "matched_conditions");
        Assert.False(second.Matched);
    }

    [Fact]
    public async Task R105_matches_large_upload_to_personal_cloud_provider()
    {
        var rule = new R105_LargeUploadToPersonalCloudProviderRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.20",
            destination: "198.51.100.20",
            host: "mega.nz",
            method: "POST",
            uri: "/upload",
            bytes: 3_200_000,
            process: "curl.exe",
            headers: "Content-Disposition: form-data; filename=archive.7z")));

        var evt = AssertSingleEvent(result, "R105", SeverityLevel.High, 0.78);
        AssertEvidence(evt, "cloud.totalUploadBytes", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R105_ignores_small_browser_post_to_enterprise_sync_host()
    {
        var rule = new R105_LargeUploadToPersonalCloudProviderRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.21",
            destination: "198.51.100.21",
            host: "docs.google.com",
            method: "POST",
            uri: "/document/d/12345/edit",
            bytes: 400_000,
            process: "chrome.exe",
            headers: "Content-Type: application/json")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R106_matches_upload_after_internal_sweep()
    {
        var rule = new R106_UploadAfterInternalSweepRule();
        var baseTime = new DateTime(2026, 4, 29, 13, 0, 0, DateTimeKind.Utc);
        for (var index = 0; index < 4; index++)
        {
            var sweepRecord = CreateWebRecord(
                source: "10.2.1.30",
                destination: $"10.2.9.{10 + index}",
                host: string.Empty,
                method: null,
                uri: null,
                bytes: 8_192,
                process: "wmic.exe",
                destinationPort: 445);
            var sweepResult = await rule.EvaluateAsync(CreateContext(sweepRecord, baseTime.AddMinutes(index)));
            Assert.False(sweepResult.Matched);
        }

        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.30",
            destination: "198.51.100.30",
            host: "file.io",
            method: "POST",
            uri: "/upload",
            bytes: 900_000,
            process: "powershell.exe",
            headers: "Content-Disposition: form-data; filename=ops.db"), baseTime.AddMinutes(8)));

        var evt = AssertSingleEvent(result, "R106", SeverityLevel.Critical, 0.80);
        AssertEvidence(evt, "sweep.distinctTargets", "sweep.lastObservedUtc", "matched_conditions");
    }

    [Fact]
    public async Task R106_ignores_upload_when_internal_sweep_threshold_not_met()
    {
        var rule = new R106_UploadAfterInternalSweepRule();
        var baseTime = new DateTime(2026, 4, 29, 13, 30, 0, DateTimeKind.Utc);
        for (var index = 0; index < 2; index++)
        {
            await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.1.31",
                destination: $"10.2.8.{20 + index}",
                host: string.Empty,
                method: null,
                uri: null,
                bytes: 4_096,
                process: "wmic.exe",
                destinationPort: 445), baseTime.AddMinutes(index)));
        }

        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.31",
            destination: "198.51.100.31",
            host: "file.io",
            method: "POST",
            uri: "/upload",
            bytes: 900_000,
            process: "powershell.exe"), baseTime.AddMinutes(6)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R107_matches_split_exfiltration_across_many_destinations()
    {
        var rule = new R107_ExfiltrationSplitAcrossManyDestinationsRule();
        var baseTime = new DateTime(2026, 4, 29, 14, 0, 0, DateTimeKind.Utc);
        var hosts = new[] { "file.io", "gofile.io", "transfer.sh", "mega.nz", "dropbox.com", "pastebin.com" };
        RuleEvaluationResult? last = null;

        for (var index = 0; index < hosts.Length; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.1.40",
                destination: $"198.51.100.{40 + index}",
                host: hosts[index],
                method: "POST",
                uri: "/upload",
                bytes: 1_100_000,
                process: "curl.exe",
                headers: $"Content-Disposition: form-data; filename=chunk-{index}.bin"), baseTime.AddMinutes(index)));
        }

        var evt = AssertSingleEvent(last!, "R107", SeverityLevel.High, 0.78);
        AssertEvidence(evt, "cloud.totalUploadBytes", "cloud.distinctDestinations", "count", "matched_conditions");
    }

    [Fact]
    public async Task R107_ignores_low_volume_browsing_spread()
    {
        var rule = new R107_ExfiltrationSplitAcrossManyDestinationsRule();
        var baseTime = new DateTime(2026, 4, 29, 14, 30, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 8; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.1.41",
                destination: $"198.51.100.{80 + index}",
                host: $"site{index}.example",
                method: "GET",
                uri: "/index.html",
                bytes: 80_000,
                process: "chrome.exe"), baseTime.AddMinutes(index)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R108_matches_high_outbound_ratio_per_provider()
    {
        var rule = new R108_ExcessiveUploadRatioPerHostRule();
        var baseTime = new DateTime(2026, 4, 29, 15, 0, 0, DateTimeKind.Utc);

        await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "198.51.100.50",
            destination: "10.2.1.50",
            host: "dropbox.com",
            method: "HTTP/200",
            uri: "/download/chunk",
            bytes: 1_000_000,
            process: "dropbox.exe"), baseTime));

        RuleEvaluationResult? last = null;
        for (var index = 0; index < 4; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.1.50",
                destination: "198.51.100.50",
                host: "dropbox.com",
                method: "POST",
                uri: "/upload",
                bytes: 2_500_000,
                process: "curl.exe",
                headers: "Content-Disposition: form-data; filename=dataset.bin"), baseTime.AddMinutes(index + 1)));
        }

        var evt = AssertSingleEvent(last!, "R108", SeverityLevel.High, 0.80);
        AssertEvidence(evt, "cloud.outboundBytes", "cloud.inboundBytes", "cloud.uploadRatio", "matched_conditions");
    }

    [Fact]
    public async Task R108_ignores_balanced_bidirectional_provider_volume()
    {
        var rule = new R108_ExcessiveUploadRatioPerHostRule();
        var baseTime = new DateTime(2026, 4, 29, 15, 30, 0, DateTimeKind.Utc);

        await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "198.51.100.51",
            destination: "10.2.1.51",
            host: "dropbox.com",
            method: "HTTP/200",
            uri: "/download/chunk",
            bytes: 4_000_000,
            process: "dropbox.exe"), baseTime));

        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.51",
            destination: "198.51.100.51",
            host: "dropbox.com",
            method: "POST",
            uri: "/upload",
            bytes: 5_000_000,
            process: "chrome.exe",
            headers: "Content-Disposition: form-data; filename=notes.bin"), baseTime.AddMinutes(1)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R109_matches_scripted_raw_payload_access()
    {
        var rule = new R109_SuspiciousGitHubGitLabRawAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.60",
            destination: "198.51.100.60",
            host: "raw.githubusercontent.com",
            method: "GET",
            uri: "/org/repo/main/payload.ps1",
            bytes: 700_000,
            process: "powershell.exe")));

        var evt = AssertSingleEvent(result, "R109", SeverityLevel.High, 0.72);
        AssertEvidence(evt, "host.classifier", "http.uri", "matched_conditions");
    }

    [Fact]
    public async Task R109_ignores_repository_browse_views()
    {
        var rule = new R109_SuspiciousGitHubGitLabRawAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.61",
            destination: "198.51.100.61",
            host: "github.com",
            method: "GET",
            uri: "/org/repo/blob/main/README.md",
            bytes: 40_000,
            process: "chrome.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R110_matches_chat_webhook_egress()
    {
        var rule = new R110_TelegramDiscordSlackAPIEgressRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.70",
            destination: "198.51.100.70",
            host: "hooks.slack.com",
            method: "POST",
            uri: "/services/T000/B000/secret",
            bytes: 220_000,
            process: "curl.exe",
            headers: "Content-Disposition: form-data; filename=ops.log")));

        var evt = AssertSingleEvent(result, "R110", SeverityLevel.High, 0.78);
        AssertEvidence(evt, "host.classifier", "matched_conditions", "cloud.providerRoot");
    }

    [Fact]
    public async Task R110_ignores_generic_collaboration_traffic()
    {
        var rule = new R110_TelegramDiscordSlackAPIEgressRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.71",
            destination: "198.51.100.71",
            host: "teams.microsoft.com",
            method: "GET",
            uri: "/_",
            bytes: 32_000,
            process: "teams.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R111_matches_file_drop_upload()
    {
        var rule = new R111_PasteSiteFileDropServiceEgressRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.80",
            destination: "198.51.100.80",
            host: "file.io",
            method: "POST",
            uri: "/upload",
            bytes: 450_000,
            process: "powershell.exe",
            headers: "Content-Disposition: form-data; filename=customer.csv")));

        var evt = AssertSingleEvent(result, "R111", SeverityLevel.High, 0.80);
        AssertEvidence(evt, "cloud.host", "http.uri", "matched_conditions");
    }

    [Fact]
    public async Task R111_ignores_public_paste_read()
    {
        var rule = new R111_PasteSiteFileDropServiceEgressRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.81",
            destination: "198.51.100.81",
            host: "pastebin.com",
            method: "GET",
            uri: "/abcd1234",
            bytes: 20_000,
            process: "chrome.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R112_matches_saas_export_like_api_call()
    {
        var rule = new R112_SaaSExportLikeTrafficPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.90",
            destination: "198.51.100.90",
            host: "acme.salesforce.com",
            method: "POST",
            uri: "/services/data/v60.0/jobs/export",
            bytes: 900_000,
            process: "powershell.exe",
            headers: "Content-Type: application/json",
            info: "bulk export csv backup request")));

        var evt = AssertSingleEvent(result, "R112", SeverityLevel.High, 0.78);
        AssertEvidence(evt, "cloud.providerRoot", "http.uri", "matched_conditions");
    }

    [Fact]
    public async Task R112_ignores_generic_saas_api_without_export_semantics()
    {
        var rule = new R112_SaaSExportLikeTrafficPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.1.91",
            destination: "198.51.100.91",
            host: "acme.atlassian.net",
            method: "GET",
            uri: "/rest/api/3/search",
            bytes: 120_000,
            process: "chrome.exe",
            headers: "Accept: application/json")));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_cloud_rules_register_rule_owned_precision_profiles()
    {
        _ = new R104_FirstTimeCloudStorageUploadRule();
        _ = new R106_UploadAfterInternalSweepRule();
        _ = new R109_SuspiciousGitHubGitLabRawAccessRule();

        var r104 = RulePrecisionCatalog.GetProfile("R104", "CloudSaas", SeverityLevel.Medium);
        var r106 = RulePrecisionCatalog.GetProfile("R106", "CloudSaas", SeverityLevel.Critical);
        var r109 = RulePrecisionCatalog.GetProfile("R109", "CloudSaas", SeverityLevel.Medium);

        Assert.Contains(RuleTelemetryKind.Baseline, r104.RequiredTelemetry);
        Assert.Equal(4, r106.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(10), r109.Window);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateWebRecord(
        string source,
        string destination,
        string host,
        string? method,
        string? uri,
        int bytes,
        string process,
        string? headers = null,
        string? info = null,
        int destinationPort = 443)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = "TCP",
            ApplicationProtocol = "HTTP",
            ApplicationService = "HTTPS",
            HttpMethod = method,
            HttpHost = string.IsNullOrWhiteSpace(host) ? null : host,
            HttpUri = uri,
            HttpRequestHeaders = headers,
            Info = info,
            Length = bytes,
            L4Len = bytes,
            IsTcp = true,
            ProcessName = process
        };

    private static DetectionEvent AssertSingleEvent(RuleEvaluationResult result, string ruleId, SeverityLevel minimumSeverity, double minimumConfidence)
    {
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(ruleId, evt.RuleId);
        Assert.True(evt.ConfidenceScore >= minimumConfidence, $"Expected confidence >= {minimumConfidence:F2} but got {evt.ConfidenceScore:F2}.");
        Assert.True(evt.Severity >= minimumSeverity);
        Assert.NotNull(evt.StructuredEvidence);
        return evt;
    }

    private static void AssertEvidence(DetectionEvent evt, params string[] expectedKeys)
    {
        var keys = evt.StructuredEvidence!.Items.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expected in expectedKeys)
            Assert.Contains(expected, keys);
    }

    private static string UniqueInternalIp()
    {
        var bytes = Guid.NewGuid().ToByteArray();
        return $"10.{64 + (bytes[0] % 64)}.{bytes[1]}.{Math.Max(1, (int)bytes[2])}";
    }
}
