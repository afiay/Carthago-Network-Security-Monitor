// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;
public sealed class R137AdvancedAccuracyBatchTests
{
    private readonly R137_PasswordResetOrEnrollmentSpikeRule _rule = new();
    [Fact] public async Task Eight_Independent_Reset_Submissions_Match()
    {
        for (var i = 0; i < 7; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery(), i * 10))).Matched);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery(), 70))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "8");
    }
    [Fact] public async Task Eight_Get_Page_Views_Do_Not_Count()
    {
        for (var i = 0; i < 8; i++)
        {
            var r = NetworkBatch136140Context.Recovery(); r.HttpMethod = "GET";
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r, i))).Matched);
        }
    }
    [Fact] public async Task Reset_Words_In_Unrelated_Posts_Are_Not_Actions()
    {
        for (var i = 0; i < 8; i++)
        {
            var r = NetworkBatch136140Context.Recovery("/api/search"); r.Info = "reset password submit";
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r, i))).Matched);
        }
    }
    [Fact] public async Task Duplicate_Packet_Id_Cannot_Manufacture_Threshold()
    {
        var r = NetworkBatch136140Context.Recovery();
        for (var i = 0; i < 12; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r, i))).Matched);
    }
    [Fact] public async Task Different_Hosts_Cannot_Fill_One_Window()
    {
        for (var i = 0; i < 7; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery(), i))).Matched);
        var other = NetworkBatch136140Context.Recovery();
        other.HttpHost = "other.example.test"; other.Sni = "other.example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(other, 8))).Matched);
    }
    [Fact] public async Task Expired_Window_Does_Not_Retain_Seven_Old_Events()
    {
        for (var i = 0; i < 7; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery(), i))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery(), 360))).Matched);
    }
    [Fact] public async Task Udp_And_Missing_Tcp_Are_Not_Recovery_Requests()
    {
        var a = NetworkBatch136140Context.Recovery(); a.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(a))).Matched);
        var b = NetworkBatch136140Context.Recovery(); b.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(b))).Matched);
    }
    [Fact] public async Task Enrollment_Is_Detected_Without_Leaking_Route_And_Shadow_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(72, _rule.PrecisionProfile.MinimumConfidence);
        for (var i = 0; i < 7; i++)
            await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery("/mfa/enroll?ticket=private-secret-137"), i));
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Recovery("/mfa/enroll?ticket=private-secret-137"), 7))).Events);
        Assert.DoesNotContain("private-secret-137", evt.Evidence);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "matched_conditions" && x.Value.Contains("enrollment_route"));
    }
}
