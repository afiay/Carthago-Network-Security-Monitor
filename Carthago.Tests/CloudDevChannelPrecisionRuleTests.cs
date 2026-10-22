using System;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class CloudDevChannelPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionCloudDevChannelRules()
    {
        yield return new object[] { new R218_DiscordWebhookFileUploadRule() };
        yield return new object[] { new R219_TelegramBotApiSendDocumentRule() };
        yield return new object[] { new R220_PasteServiceHighVolumePostRule() };
        yield return new object[] { new R221_RemoteDesktopSaasToolBeaconRule() };
        yield return new object[] { new R222_UnauthorizedOverlayNetworkEgressRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionCloudDevChannelRules))]
    public async Task Precision_clouddev_channel_rules_return_no_match_without_context(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.41.0.10",
            Destination = "198.51.100.10",
            Protocol = "TCP",
            ApplicationProtocol = "TCP",
            ApplicationService = "TCP",
            Length = 64,
            L4Len = 64,
            Info = "noisy text only"
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R218_matches_discord_webhook_upload()
    {
        var rule = new R218_DiscordWebhookFileUploadRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.41.1.10",
            destination: "162.159.128.233",
            destinationPort: 443,
            host: "discord.com",
            method: "POST",
            uri: "/api/webhooks/123456/SECRET",
            headers: "Host: discord.com\r\nContent-Type: multipart/form-data; boundary=abc",
            info: "payload_json={\"content\":\"artifact\"}; filename=secret.zip; attachments[0]",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe",
            length: 90_000)));

        var evt = AssertSingleEvent(result, "R218", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "host.classifier", "matched_conditions");
    }

    [Fact]
    public async Task R218_ignores_discord_desktop_client_post()
    {
        var rule = new R218_DiscordWebhookFileUploadRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.41.1.11",
            destination: "162.159.128.234",
            destinationPort: 443,
            host: "discord.com",
            method: "POST",
            uri: "/api/webhooks/123456/SECRET",
            headers: "Host: discord.com\r\nContent-Type: application/json",
            info: "{\"content\":\"hello\"}",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "discord.exe",
            length: 20_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R219_matches_telegram_senddocument()
    {
        var rule = new R219_TelegramBotApiSendDocumentRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.41.1.20",
            destination: "149.154.167.220",
            destinationPort: 443,
            host: "api.telegram.org",
            method: "POST",
            uri: "/bot123456:ABC/sendDocument",
            headers: "Host: api.telegram.org\r\nContent-Type: multipart/form-data; boundary=abc",
            info: "name=\"document\"; filename=archive.zip; sendDocument",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "powershell.exe",
            length: 85_000)));

        var evt = AssertSingleEvent(result, "R219", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "host.classifier", "matched_conditions");
    }

    [Fact]
    public async Task R219_ignores_telegram_sendmessage()
    {
        var rule = new R219_TelegramBotApiSendDocumentRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.41.1.21",
            destination: "149.154.167.221",
            destinationPort: 443,
            host: "api.telegram.org",
            method: "POST",
            uri: "/bot123456:ABC/sendMessage",
            headers: "Host: api.telegram.org\r\nContent-Type: application/json",
            info: "{\"text\":\"hello\"}",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "telegram.exe",
            length: 10_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R220_matches_paste_post_burst()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        var baseTime = new DateTime(2026, 4, 30, 17, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 5; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.41.1.30",
                destination: "198.51.100.130",
                destinationPort: 443,
                host: "pastebin.com",
                method: "POST",
                uri: $"/api/api_post.php?id={index}",
                headers: "Host: pastebin.com\r\nContent-Type: application/x-www-form-urlencoded",
                info: "api_dev_key=key&api_option=paste&api_paste_code=secret",
                service: "HTTPS",
                protocol: "HTTPS",
                process: "curl.exe",
                length: 90_000), baseTime.AddSeconds(index * 20)));
        }

        var evt = AssertSingleEvent(last!, "R220", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "count", "matched_conditions");
    }

    [Fact]
    public async Task R220_ignores_paste_landing_page_view()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.41.1.31",
            destination: "198.51.100.131",
            destinationPort: 443,
            host: "pastebin.com",
            method: "GET",
            uri: "/",
            headers: "Host: pastebin.com",
            info: "landing page",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "chrome.exe",
            length: 12_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R221_matches_remote_desktop_saas_beacon()
    {
        var rule = new R221_RemoteDesktopSaasToolBeaconRule();
        var baseTime = new DateTime(2026, 4, 30, 17, 20, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 4; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateFlowRecord(
                source: "10.41.1.40",
                destination: "203.0.113.40",
                destinationPort: 443,
                host: "relay.anydesk.com",
                protocol: "TLS",
                service: "RemoteSupport",
                info: "anydesk relay heartbeat",
                process: "anydesk.exe",
                length: 8_000), baseTime.AddSeconds(index * 30)));
        }

        var evt = AssertSingleEvent(last!, "R221", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "vendor", "signal", "count", "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R221_ignores_browser_visit_to_vendor_site()
    {
        var rule = new R221_RemoteDesktopSaasToolBeaconRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateFlowRecord(
            source: "10.41.1.41",
            destination: "203.0.113.41",
            destinationPort: 443,
            host: "www.teamviewer.com",
            protocol: "HTTPS",
            service: "HTTPS",
            info: "landing page",
            process: "chrome.exe",
            length: 20_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R222_matches_overlay_network_egress()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule();
        var baseTime = new DateTime(2026, 4, 30, 17, 40, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateFlowRecord(
                source: "10.41.1.50",
                destination: "198.51.100.50",
                destinationPort: 7844,
                host: "region1.argotunnel.com",
                protocol: "QUIC",
                service: "Tunnel",
                info: "cloudflared tunnel keepalive",
                process: "cloudflared.exe",
                length: 7_000), baseTime.AddSeconds(index * 30)));
        }

        var evt = AssertSingleEvent(last!, "R222", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "vendor", "signal", "count", "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R222_ignores_generic_cloudflare_browsing()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateFlowRecord(
            source: "10.41.1.51",
            destination: "104.16.132.229",
            destinationPort: 443,
            host: "www.cloudflare.com",
            protocol: "HTTPS",
            service: "HTTPS",
            info: "documentation page",
            process: "chrome.exe",
            length: 24_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_clouddev_channel_rules_register_rule_owned_precision_profiles()
    {
        _ = new R218_DiscordWebhookFileUploadRule();
        _ = new R219_TelegramBotApiSendDocumentRule();
        _ = new R220_PasteServiceHighVolumePostRule();
        _ = new R221_RemoteDesktopSaasToolBeaconRule();
        _ = new R222_UnauthorizedOverlayNetworkEgressRule();

        var r218 = RulePrecisionCatalog.GetProfile("R218", "CloudDev", SeverityLevel.High);
        var r220 = RulePrecisionCatalog.GetProfile("R220", "CloudDev", SeverityLevel.High);
        var r221 = RulePrecisionCatalog.GetProfile("R221", "CloudDev", SeverityLevel.Medium);
        var r222 = RulePrecisionCatalog.GetProfile("R222", "CloudDev", SeverityLevel.High);

        Assert.Equal(RuleRuntimeMode.Alert, r218.DefaultMode);
        Assert.Equal(5, r220.Threshold);
        Assert.Equal(4, r221.Threshold);
        Assert.Contains(RuleTelemetryKind.Process, r222.RequiredTelemetry);
        Assert.Equal(RuleRuntimeMode.Alert, r222.DefaultMode);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 30, 17, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateWebRecord(
        string source,
        string destination,
        int destinationPort,
        string host,
        string method,
        string uri,
        string headers,
        string info,
        string service,
        string protocol,
        string? process = null,
        int length = 2048)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            HttpHost = host,
            HttpMethod = method,
            HttpUri = uri,
            HttpRequestHeaders = headers,
            Info = info,
            ProcessName = process,
            IsTcp = true,
            Length = length,
            L4Len = length
        };

    private static TrafficRecord CreateFlowRecord(
        string source,
        string destination,
        int destinationPort,
        string host,
        string protocol,
        string service,
        string info,
        string? process = null,
        int length = 2048)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            HttpHost = host,
            Sni = host,
            Info = info,
            ProcessName = process,
            IsTcp = true,
            Length = length,
            L4Len = length
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
}
