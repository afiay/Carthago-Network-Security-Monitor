// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R250AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch246250Context.Sample(250);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch246250Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R250_LargeHttpPostToIpLiteralRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Ip_Literal_Declared_Large_Request_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Named_Host_Is_Not_Ip_Literal() {
        var r = Sample(); r.HttpHost = "upload.example";
        r.HttpRequestHeaders = "Host: upload.example\nContent-Length: 20971520";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Below_Declared_Length_Threshold_Is_Benign() {
        var r = Sample(); r.HttpRequestHeaders = "Host: 198.51.100.250\nContent-Length: 1024";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoofing_Cannot_Supply_Declared_Body() {
        var r = Sample(); r.HttpRequestHeaders = "Host: 198.51.100.250";
        r.Info = "Content-Length: 20971520";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Content_Length_Is_Rejected() {
        var r = Sample(); r.HttpRequestHeaders += "\nContent-Length: 20971520";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Host_Header_Is_Rejected() {
        var r = Sample(); r.HttpRequestHeaders = "Host: other.example\nContent-Length: 20971520";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Get_Download_Is_Not_An_Upload() {
        var r = Sample(); r.HttpMethod = "GET"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Rejected() {
        var rule = new R250_LargeHttpPostToIpLiteralRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Host_Path_And_Info_Are_Redacted() {
        var r = Sample(); r.HttpUri = "/upload/private-secret-marker";
        r.Info = "password=private-secret-marker";
        var result = await new R250_LargeHttpPostToIpLiteralRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("private-secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.250", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R250_LargeHttpPostToIpLiteralRule().PrecisionProfile;
        Assert.Equal(83, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

}
