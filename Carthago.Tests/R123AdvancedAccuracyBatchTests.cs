// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R123AdvancedAccuracyBatchTests
{
    private readonly R123_SuspiciousVpnLoginPathRule _rule = new();
    [Fact] public async Task External_Vpn_Portal_Login_Is_Candidate()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Vpn()))).Matched);
    }
    [Fact] public async Task Generic_Idp_Login_With_Vpn_Info_Is_Not_Sufficient()
    {
        var r = NetworkBatch121125Context.Vpn(); r.HttpHost = "login.example.com"; r.HttpUri = "/login";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Missing_Http_Method_Fails_Closed()
    {
        var r = NetworkBatch121125Context.Vpn(); r.HttpMethod = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Udp_Or_Sni_Fails_Closed()
    {
        var r = NetworkBatch121125Context.Vpn(); r.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
        var s = NetworkBatch121125Context.Vpn(); s.Sni = "different.example.com";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(s))).Matched);
    }
    [Fact] public async Task Static_Documentation_Page_Remains_Benign()
    {
        var r = NetworkBatch121125Context.Vpn(); r.HttpUri = "/docs/vpn/login.js";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Vpn_Portal_Remains_Benign()
    {
        var r = NetworkBatch121125Context.Vpn(); r.Destination = "10.123.1.30"; r.HttpHost = "vpn.internal";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Secret_Path_Segments_Are_Not_Exported()
    {
        const string secret = "vpn-private-path-123";
        var r = NetworkBatch121125Context.Vpn(); r.HttpUri = "/remote/login/" + secret + "?token=hidden";
        var result = await _rule.EvaluateAsync(NetworkBatch121125Context.At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
}
