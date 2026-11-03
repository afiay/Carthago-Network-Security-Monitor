// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed.
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R686R695AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 3, 23, 0, 0, DateTimeKind.Utc);

    private static IDetectionRule Rule(string id) => id switch
    {
        "R686" => new R686_BitsadminDirectIpCleartextHttpGetRule(),
        "R687" => new R687_CertutilDirectIpCleartextHttpGetRule(),
        "R688" => new R688_WgetDirectIpCleartextHttpGetRule(),
        "R689" => new R689_CurlFileSharingServiceHostEgressRule(),
        "R690" => new R690_CurlSuspiciousExtensionCleartextHttpGetRule(),
        "R691" => new R691_SmbListenerPublicClientSynAckEvidenceRule(),
        "R692" => new R692_OutlookExternalWebDavOrSmbAttemptRule(),
        "R693" => new R693_SnippingToolExternalRemoteResourceAttemptRule(),
        "R694" => new R694_NpsNpcProcessExternalTcpEgressRule(),
        "R695" => new R695_IoxProcessExternalTcpEgressRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Http(string process, string host = "8.8.8.8", string uri = "/payload.exe", string method = "GET")
        => new()
        {
            Id = Guid.NewGuid(), Source = "10.1.2.20", Destination = "8.8.8.8", IpVersion = 4,
            Protocol = "TCP", IsTcp = true, SourcePort = 52001, DestinationPort = 80,
            L4Len = 240, Length = 280, ApplicationProtocol = "HTTP", HttpMethod = method,
            HttpUri = uri, HttpHost = host, HttpUserAgent = "Tool/1.0",
            ProcessId = 4242, ProcessName = process
        };

    private static TrafficRecord Tcp(string process, string destination = "8.8.8.8", int port = 443, ushort flags = 0x02)
        => new()
        {
            Id = Guid.NewGuid(), Source = "10.1.2.20", Destination = destination, IpVersion = 4,
            Protocol = "TCP", IsTcp = true, SourcePort = 52002, DestinationPort = port,
            L4Len = flags is 0x02 or 0x12 ? 0 : 120, Length = flags is 0x02 or 0x12 ? 40 : 160,
            TcpFlags = flags, ProcessId = 4242, ProcessName = process
        };

    [Theory]
    [InlineData("R686", "bitsadmin.exe")]
    [InlineData("R687", "certutil.exe")]
    [InlineData("R688", "wget.exe")]
    public async Task DirectIpGetRequiresExactProcessIpHostAndPublicDestination(string id, string process)
    {
        Assert.True((await Rule(id).EvaluateAsync(At(Http(process)))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Http("chrome.exe")))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Http(process, "download.example")))).Matched);
        Assert.False((await Rule(id).EvaluateAsync(At(Http(process, method: "POST")))).Matched);
        var inside = Http(process); inside.Destination = "10.1.2.40"; inside.HttpHost = "10.1.2.40";
        Assert.False((await Rule(id).EvaluateAsync(At(inside))).Matched);
        var noPid = Http(process); noPid.ProcessId = 0;
        Assert.False((await Rule(id).EvaluateAsync(At(noPid))).Matched);
    }

    [Fact]
    public async Task CurlFileSharingHostAllowsExactHttpOrTlsHostOnly()
    {
        var http = Http("curl.exe", "gofile.io", "/file.bin");
        Assert.True((await Rule("R689").EvaluateAsync(At(http))).Matched);
        var fake = Http("curl.exe", "gofile.io.evil.test", "/file.bin");
        Assert.False((await Rule("R689").EvaluateAsync(At(fake))).Matched);
        var tls = Tcp("curl.exe", port: 443, flags: 0x18);
        tls.TlsVersion = "TLS1.3"; tls.Sni = "cdn.discordapp.com"; tls.L4Len = 120; tls.Length = 170;
        Assert.True((await Rule("R689").EvaluateAsync(At(tls))).Matched);
        var browser = Tcp("chrome.exe", port: 443, flags: 0x18);
        browser.TlsVersion = "TLS1.3"; browser.Sni = "cdn.discordapp.com"; browser.L4Len = 120; browser.Length = 170;
        Assert.False((await Rule("R689").EvaluateAsync(At(browser))).Matched);
    }

    [Fact]
    public async Task CurlSuspiciousExtensionRequiresGetAndProcess()
    {
        Assert.True((await Rule("R690").EvaluateAsync(At(Http("curl.exe", "files.example", "/drop/update.ps1")))).Matched);
        Assert.False((await Rule("R690").EvaluateAsync(At(Http("curl.exe", "files.example", "/images/logo.png")))).Matched);
        Assert.False((await Rule("R690").EvaluateAsync(At(Http("chrome.exe", "files.example", "/drop/update.ps1")))).Matched);
        Assert.False((await Rule("R690").EvaluateAsync(At(Http("curl.exe", "files.example", "/drop/update.ps1", "POST")))).Matched);
    }

    [Fact]
    public async Task SmbListenerSynAckRequiresPrivateServerPublicClientAndPort445()
    {
        var response = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = "10.1.2.40", Destination = "8.8.8.8", IpVersion = 4,
            Protocol = "TCP", IsTcp = true, SourcePort = 445, DestinationPort = 53000,
            TcpFlags = 0x12, L4Len = 0, Length = 40
        };
        Assert.True((await Rule("R691").EvaluateAsync(At(response))).Matched);
        var syn = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = "10.1.2.40", Destination = "8.8.8.8", IpVersion = 4,
            Protocol = "TCP", IsTcp = true, SourcePort = 445, DestinationPort = 53000,
            TcpFlags = 0x02, L4Len = 0, Length = 40
        };
        Assert.False((await Rule("R691").EvaluateAsync(At(syn))).Matched);
        response.Id = Guid.NewGuid(); response.Destination = "10.1.2.50";
        Assert.False((await Rule("R691").EvaluateAsync(At(response))).Matched);
    }

    [Fact]
    public async Task OutlookRemoteResourceNeedsOutlookAndExternalDavOrSmb()
    {
        var smb = Tcp("outlook.exe", port: 445);
        Assert.True((await Rule("R692").EvaluateAsync(At(smb))).Matched);
        var chrome = Tcp("chrome.exe", port: 445);
        Assert.False((await Rule("R692").EvaluateAsync(At(chrome))).Matched);
        var dav = Http("outlook.exe", "dav.example", "/webdav/test");
        dav.HttpMethod = "PROPFIND"; dav.ApplicationProtocol = "HTTP";
        Assert.True((await Rule("R692").EvaluateAsync(At(dav))).Matched);
        var inside = Tcp("outlook.exe", "10.1.2.50", 445);
        Assert.False((await Rule("R692").EvaluateAsync(At(inside))).Matched);
    }

    [Fact]
    public async Task SnippingToolRemoteResourceNeedsExactProcessAndSmbOrHttp()
    {
        Assert.True((await Rule("R693").EvaluateAsync(At(Tcp("snippingtool.exe", port: 445)))).Matched);
        Assert.True((await Rule("R693").EvaluateAsync(At(Http("snippingtool.exe", "8.8.8.8", "/remote/image.png")))).Matched);
        Assert.False((await Rule("R693").EvaluateAsync(At(Tcp("explorer.exe", port: 445)))).Matched);
        Assert.False((await Rule("R693").EvaluateAsync(At(Http("chrome.exe", "8.8.8.8", "/remote/image.png")))).Matched);
    }

    [Theory]
    [InlineData("R694", "npc.exe")]
    [InlineData("R695", "iox.exe")]
    public async Task NamedTunnelToolRequiresPositivePidAndExternalTcp(string id, string process)
    {
        var flow = Tcp(process, port: 8443, flags: 0x18); flow.L4Len = 100; flow.Length = 140;
        Assert.True((await Rule(id).EvaluateAsync(At(flow))).Matched);
        var noPid = Tcp(process, port: 8443, flags: 0x18); noPid.L4Len = 100; noPid.Length = 140; noPid.ProcessId = 0;
        Assert.False((await Rule(id).EvaluateAsync(At(noPid))).Matched);
        var other = Tcp("chrome.exe", port: 8443, flags: 0x18); other.L4Len = 100; other.Length = 140;
        Assert.False((await Rule(id).EvaluateAsync(At(other))).Matched);
        var internalPeer = Tcp(process, "10.1.2.50", 8443, 0x18); internalPeer.L4Len = 100; internalPeer.Length = 140;
        Assert.False((await Rule(id).EvaluateAsync(At(internalPeer))).Matched);
    }

    [Fact]
    public async Task DuplicateOutOfOrderCooldownAndOutcomeScope()
    {
        var rule = Rule("R686");
        var first = Http("bitsadmin.exe");
        var evt = Assert.Single((await rule.EvaluateAsync(At(first, 10))).Events);
        var serialized = JsonSerializer.Serialize(evt);
        Assert.Contains("direct_ip_http_get_only_unknown", serialized);
        Assert.DoesNotContain("successful download", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.False((await rule.EvaluateAsync(At(first, 11))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http("bitsadmin.exe"), 9))).Matched);
        var suppressed = await rule.EvaluateAsync(At(Http("bitsadmin.exe"), 12));
        Assert.True(suppressed.Suppressed); Assert.Empty(suppressed.Events);
        Assert.True((await rule.EvaluateAsync(At(Http("bitsadmin.exe"), 611))).Matched);
    }

    [Theory]
    [InlineData("R686")]
    [InlineData("R687")]
    [InlineData("R688")]
    [InlineData("R689")]
    [InlineData("R690")]
    [InlineData("R691")]
    [InlineData("R692")]
    [InlineData("R693")]
    [InlineData("R694")]
    [InlineData("R695")]
    public void RegistryContainsExactlyOneCandidateShadowRule(string id)
    {
        var found = Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == id));
        var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
        Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
    }
}
