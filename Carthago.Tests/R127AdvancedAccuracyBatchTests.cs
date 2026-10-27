// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;
namespace Carthago.Tests;

public sealed class R127AdvancedAccuracyBatchTests
{
    private readonly R127_AdminPortalAccessFromInternetRule _rule = new();
    [Fact] public async Task External_Visitor_To_Admin_Portal_Matches()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Web()))).Matched);
    }
    [Fact] public async Task Internal_Only_Admin_Does_Not_Match()
    {
        var r = NetworkBatch126130Context.Web(); r.Source = "10.127.1.11";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Ordinary_Login_And_Adminish_Substring_Are_Not_Portal()
    {
        var r = NetworkBatch126130Context.Web("/login");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var a = NetworkBatch126130Context.Web("/administrator-guide");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(a))).Matched);
    }
    [Fact] public async Task Appliance_Management_Is_Reserved_For_R128()
    {
        var r = NetworkBatch126130Context.Web("/admin", "fortigate-edge.example.test");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Missing_Method_And_Contradictory_Udp_Fail_Closed()
    {
        var r = NetworkBatch126130Context.Web(); r.HttpMethod = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var u = NetworkBatch126130Context.Web(); u.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(u))).Matched);
    }
    [Fact] public async Task Mismatched_Sni_And_Documentation_Are_Suppressed()
    {
        var r = NetworkBatch126130Context.Web(); r.Sni = "different.example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var d = NetworkBatch126130Context.Web("/docs/admin");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(d))).Matched);
    }
    [Fact] public async Task Secret_Route_Segment_Is_Not_Persisted_And_Shadow_Remains()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        var r = NetworkBatch126130Context.Web("/admin/private-secret-127?access_token=private");
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Events);
        Assert.DoesNotContain("private-secret-127", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-127", StringComparison.Ordinal));
    }
}
