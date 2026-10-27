// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R019: attributed HTTP request-target length and entropy, not header text.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R019AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R019_EncodedLongUriRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R019AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Request(string uri = "/health", string source = "10.19.0.2")
        => new() { Source = source, Destination = "8.8.8.8", DestinationPort = 80,
            Protocol = "HTTP", Length = 2400, HttpMethod = "GET", HttpUri = uri };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Long_Structured_Uri_Produces_High_Severity_Candidate_Without_Leaking_Path()
    {
        var uri = "/secret-" + new string('x', 2100);
        var evt = Assert.Single((await See(Request(uri))).Events);
        Assert.Equal("R019", evt.RuleId);
        Assert.Equal(uri.Length, evt.Count);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.DoesNotContain("secret-", evt.Description);
    }

    [Fact]
    public async Task Raw_Http_Request_Line_Uses_Uri_Rather_Than_Headers()
    {
        var uri = "/" + new string('q', 2100);
        var r = Request(); r.HttpMethod = null; r.HttpUri = null;
        r.Protocol = "TCP"; r.Info = "GET " + uri + " HTTP/1.1\r\nHost: example.net\r\n\r\n";
        Assert.Equal(uri.Length, Assert.Single((await See(r)).Events).Count);
    }

    [Fact]
    public async Task High_Entropy_Encoded_Chunk_Is_Medium_Severity_Candidate()
    {
        var token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var evt = Assert.Single((await See(Request("/?data=" + token + token))).Events);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Contains("high-entropy chunk", evt.Description);
        Assert.DoesNotContain(token, evt.Description);
    }

    [Fact]
    public async Task Very_Long_Headers_With_Short_Uri_Are_Not_Anomalous_Uris()
    {
        var r = Request(); r.HttpMethod = null; r.HttpUri = null;
        r.Info = "GET /ok HTTP/1.1\r\nX-Long: " + new string('x', 6000) + "\r\n\r\n";
        Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Response_Lines_And_Prose_Containing_Http_Versions_Are_Not_Requests()
    {
        var r = Request(); r.HttpMethod = null; r.HttpUri = null;
        r.Info = "HTTP/1.1 200 OK\r\nX-Token: " + new string('a', 3000) + "\r\n\r\n";
        Assert.False((await See(r)).Matched);
        r.Info = "Documentation: GET /" + new string('b', 3000) + " HTTP/1.1";
        Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Contradictory_Structured_And_Raw_Uris_Cannot_Be_Combined()
    {
        var r = Request("/" + new string('x', 2200));
        r.Info = "GET /short HTTP/1.1\r\nHost: example.net\r\n\r\n";
        Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Ordinary_Uri_And_Low_Entropy_Repetition_Are_Negative_Controls()
    {
        Assert.False((await See(Request("/index.html"))).Matched);
        Assert.False((await See(Request("/?data=" + new string('a', 120)))).Matched);
    }

    [Fact]
    public async Task Unattributed_Encrypted_And_Non_Http_Flows_Are_Rejected()
    {
        var missing = Request("/" + new string('x', 2200)); missing.Source = null;
        var tls = Request("/" + new string('x', 2200)); tls.TlsVersion = "TLS 1.3";
        var udp = Request("/" + new string('x', 2200)); udp.Protocol = "UDP";
        var noPort = Request("/" + new string('x', 2200)); noPort.DestinationPort = null;
        foreach (var r in new[] { missing, tls, udp, noPort })
            Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Repeat_Is_Suppressed_But_Different_Source_Is_Independent()
    {
        var uri = "/" + new string('x', 2200);
        Assert.True((await See(Request(uri))).Matched);
        var repeat = await See(Request(uri), 1);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);
        Assert.Equal("10.19.0.3", Assert.Single((await See(Request(uri, "10.19.0.3"), 1)).Events).SourceIp);
    }
}
