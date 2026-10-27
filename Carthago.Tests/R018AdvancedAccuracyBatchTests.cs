// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R018: complete HTTP/1.1 request evidence for an absent Host header.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R018AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R018_HttpToIpLiteralWithoutHostHeaderRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R018AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Request(string info = "GET /health HTTP/1.1\r\nUser-Agent: sensor\r\n\r\n",
        string destination = "8.8.8.8")
        => new() { Source = "10.18.0.2", Destination = destination, DestinationPort = 8080,
            Protocol = "HTTP", Length = 150, Info = info };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Complete_Http11_Request_Without_Host_Produces_Review_Candidate()
    {
        var evt = Assert.Single((await See(Request())).Events);
        Assert.Equal("R018", evt.RuleId);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Contains("HTTP/1.1", evt.Description);
    }

    [Fact]
    public async Task Structured_Request_And_Observed_Empty_Host_Field_Are_Sufficient()
    {
        var r = Request("");
        r.HttpMethod = "POST";
        r.HttpUri = "/submit";
        r.HttpRequestHeaders = "User-Agent: internal-agent\r\n";
        var evt = Assert.Single((await See(r)).Events);
        Assert.Equal("R018", evt.RuleId);
    }

    [Fact]
    public async Task Host_Header_Or_Structured_Host_Excludes_The_Finding()
    {
        Assert.False((await See(Request("GET / HTTP/1.1\r\nHost: 8.8.8.8\r\n\r\n"))).Matched);
        var structured = Request(); structured.HttpHost = "8.8.8.8";
        Assert.False((await See(structured)).Matched);
        var headers = Request(""); headers.HttpMethod = "GET"; headers.HttpUri = "/";
        headers.HttpRequestHeaders = "Host: example.net\r\n";
        Assert.False((await See(headers)).Matched);
    }

    [Fact]
    public async Task Http2_Authority_And_Alternative_Authority_Evidence_Are_Not_Hostless()
    {
        var authority = Request(); authority.HttpRequestHeaders = ":authority: example.net\r\n";
        Assert.False((await See(authority)).Matched);
        var http2 = Request("GET / HTTP/2\r\n\r\n");
        Assert.False((await See(http2)).Matched);
    }

    [Fact]
    public async Task Incomplete_Headers_Cannot_Prove_That_Host_Is_Missing()
    {
        Assert.False((await See(Request("GET / HTTP/1.1\r\nUser-Agent: truncated"))).Matched);
        Assert.False((await See(Request("GET / HTTP/1.1"))).Matched);
    }

    [Fact]
    public async Task Http10_Legitimately_Omits_Host_And_Response_Text_Is_Not_A_Request()
    {
        Assert.False((await See(Request("GET / HTTP/1.0\r\n\r\n"))).Matched);
        Assert.False((await See(Request("HTTP/1.1 200 OK\r\n\r\n"))).Matched);
        Assert.False((await See(Request("Documentation mentions GET / HTTP/1.1\r\n\r\n"))).Matched);
    }

    [Fact]
    public async Task Conflicting_Method_Or_Uri_And_Encrypted_Transport_Are_Excluded()
    {
        var method = Request(); method.HttpMethod = "POST";
        var uri = Request(); uri.HttpUri = "/other";
        var tls = Request(); tls.TlsVersion = "TLS 1.3";
        var quic = Request(); quic.IsQuic = true;
        foreach (var r in new[] { method, uri, tls, quic })
            Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Invalid_Source_Destination_Port_Or_Transport_Are_Excluded()
    {
        var badSource = Request(); badSource.Source = "unknown";
        var hostname = Request(destination: "example.net");
        var noPort = Request(); noPort.DestinationPort = null;
        var udp = Request(); udp.Protocol = "UDP";
        var empty = Request(); empty.Length = 0;
        foreach (var r in new[] { badSource, hostname, noPort, udp, empty })
            Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Cooldown_Uses_Attributed_Source_And_Destination()
    {
        Assert.True((await See(Request())).Matched);
        var duplicate = await See(Request(), 1);
        Assert.True(duplicate.Suppressed);
        Assert.Empty(duplicate.Events);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Request(destination: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
