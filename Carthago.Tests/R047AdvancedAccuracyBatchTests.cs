// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R047AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R047_HttpBasicAuthToIpLiteralRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 8, 0, 0, DateTimeKind.Utc);
    public R047AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Http(string headers = "Host: 8.8.8.8\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n")
        => new() { Source = "10.47.0.2", Destination = "8.8.8.8", Protocol = "HTTP",
            DestinationPort = 80, HttpMethod = "GET", HttpHost = "8.8.8.8",
            HttpRequestHeaders = headers, Length = 200 };

    [Fact] public async Task Captured_Basic_Header_To_Ip_Host_Matches_Without_Secret()
    {
        var e = Assert.Single((await See(Http())).Events);
        Assert.Equal("R047", e.RuleId);
        Assert.DoesNotContain("dXNlcjpwYXNz", e.Description);
        Assert.DoesNotContain("user:pass", e.Description);
    }
    [Fact] public async Task Http_Host_With_Valid_Port_Remains_Ip_Literal()
    {
        var r = Http("Host: 8.8.8.8:80\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n");
        r.HttpHost = "8.8.8.8:80";
        Assert.True((await See(r)).Matched);
    }
    [Fact] public async Task Authorization_In_Info_Or_Response_Does_Not_Prove_Exposure()
    {
        var r = Http(""); r.Info = "GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz";
        Assert.False((await See(r)).Matched);
        r = Http(); r.HttpMethod = null;
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Missing_Malformed_And_Duplicate_Auth_Are_Excluded()
    {
        Assert.False((await See(Http("Host: 8.8.8.8\r\n\r\n"))).Matched);
        Assert.False((await See(Http("Host: 8.8.8.8\r\nAuthorization: Bearer dXNlcjpwYXNz\r\n"))).Matched);
        Assert.False((await See(Http("Host: 8.8.8.8\r\nAuthorization: Basic dXNlcjpwYXNz\r\nAuthorization: Basic dXNlcjpwYXNz\r\n"))).Matched);
    }
    [Fact] public async Task Hostname_Or_Contradictory_Host_Is_Not_Ip_Literal_Auth()
    {
        var r = Http("Host: dns.google\r\nAuthorization: Basic dXNlcjpwYXNz\r\n");
        r.HttpHost = "dns.google"; Assert.False((await See(r)).Matched);
        r = Http("Host: 1.1.1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n");
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Wrong_Transport_Nonpublic_Endpoint_And_Empty_Length_Excluded()
    {
        var r = Http(); r.Protocol = "SMTP"; Assert.False((await See(r)).Matched);
        r = Http(); r.Destination = "192.168.1.2"; Assert.False((await See(r)).Matched);
        r = Http(); r.Length = 0; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Repeated_Observed_Credential_Is_Suppressed()
    {
        Assert.True((await See(Http())).Matched);
        Assert.True((await See(Http(), 1)).Suppressed);
    }
}