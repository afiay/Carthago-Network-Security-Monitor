// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;
namespace Carthago.Tests;

public sealed class R126AdvancedAccuracyBatchTests
{
    private readonly R126_ExternalSshBruteCandidateRule _rule = new();
    [Fact] public async Task Eight_Independent_Failed_Ssh_Events_Match()
    {
        for (int i = 0; i < 7; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Ssh(), i))).Matched);
        var result = await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Ssh(), 7));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "8");
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Reach_Threshold()
    {
        var r = NetworkBatch126130Context.Ssh();
        for (int i = 0; i < 9; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r, i))).Matched);
    }
    [Fact] public async Task Successful_Ssh_Is_Not_Brute_Force()
    {
        var r = NetworkBatch126130Context.Ssh(); r.Info = "Accepted password for user=alice";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Port_And_Info_Without_Transport_Attribution_Fail_Closed()
    {
        var r = NetworkBatch126130Context.Ssh(); r.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var s = NetworkBatch126130Context.Ssh(); s.ApplicationService = "HTTP"; s.ApplicationProtocol = "HTTP";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(s))).Matched);
    }
    [Fact] public async Task Internal_Only_And_Udp_Contradictions_Are_Benign()
    {
        var r = NetworkBatch126130Context.Ssh(); r.Source = "10.126.1.10";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var u = NetworkBatch126130Context.Ssh(); u.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(u))).Matched);
    }
    [Fact] public async Task Failed_Burst_Expires_Outside_Two_Minutes()
    {
        for (int i = 0; i < 7; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Ssh(), i))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Ssh(), 130))).Matched);
    }
    [Fact] public async Task Secret_And_Default_Shadow_Policy_Are_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        var r = NetworkBatch126130Context.Ssh(); r.Info += " password=private-secret-126";
        for (int i = 0; i < 7; i++)
            await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Ssh(), i));
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r, 8))).Events);
        Assert.DoesNotContain("private-secret-126", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-126", StringComparison.Ordinal));
    }
}
