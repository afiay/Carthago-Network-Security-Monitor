// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;
namespace Carthago.Tests;

public sealed class R128AdvancedAccuracyBatchTests
{
    private readonly R128_NetworkApplianceManagementExposureRule _rule = new();
    private static Carthago.Models.TrafficRecord Appliance(string path = "/admin")
        => NetworkBatch126130Context.Web(path, "fortigate-edge.example.test");
    [Fact] public async Task Vendor_Attributed_Management_Portal_Matches()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch126130Context.At(Appliance()))).Matched);
    }
    [Fact] public async Task Generic_Software_Admin_Is_Not_Appliance()
    {
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Web()))).Matched);
    }
    [Fact] public async Task Vendor_Documentation_Is_Not_Management()
    {
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(Appliance("/docs/admin")))).Matched);
    }
    [Fact] public async Task Unrelated_Host_With_Vendor_Text_In_Info_Does_Not_Match()
    {
        var r = NetworkBatch126130Context.Web(); r.Info = "fortigate firewall admin";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Only_And_Udp_Contradictions_Fail_Closed()
    {
        var r = Appliance(); r.Source = "10.128.1.10";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var u = Appliance(); u.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(u))).Matched);
    }
    [Fact] public async Task Sni_And_Method_Attribution_Required()
    {
        var r = Appliance(); r.Sni = "other.example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var m = Appliance(); m.HttpMethod = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(m))).Matched);
    }
    [Fact] public async Task Management_Secret_Path_Is_Redacted_And_Shadow_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        var r = Appliance("/admin/private-secret-128?token=private");
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Events);
        Assert.DoesNotContain("private-secret-128", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-128", StringComparison.Ordinal));
    }
}
