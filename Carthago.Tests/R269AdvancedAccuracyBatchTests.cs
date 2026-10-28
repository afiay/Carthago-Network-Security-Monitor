// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R269AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch266270Context.Sample(269);
    private static RuleEvaluationContext At(TrafficRecord r, double s = 0) => NetworkBatch266270Context.At(r, s);
    private static async Task<bool> Hit(R269_SecurityToolUpdateBlockIndicatorRule rule, TrafficRecord r, double s = 0)
        => (await rule.EvaluateAsync(At(r, s))).Matched;
    [Fact] public async Task Three_Distinct_Servfail_Responses_Are_Resolution_Failure_Candidate() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample();
        Assert.False(await Hit(rule, r)); Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 1));
        Assert.True(await Hit(rule, NetworkBatch266270Context.Copy(r), 2));
    }
    [Fact] public async Task Two_Responses_Are_Below_Threshold() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample();
        Assert.False(await Hit(rule, r)); Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 1));
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Inflate_Count() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample();
        Assert.False(await Hit(rule, r)); Assert.False(await Hit(rule, r, 1));
        Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 2));
    }
    [Fact] public async Task Out_Of_Order_Response_Is_Rejected() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample();
        Assert.False(await Hit(rule, r, 10));
        Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 9));
        Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 11));
    }
    [Fact] public async Task Nxdomain_Is_Not_Proof_Of_Update_Blocking() {
        var r = Sample(); r.DnsRcode = "NXDOMAIN"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Successful_Response_Is_Not_A_Failure() {
        var r = Sample(); r.DnsRcode = "NOERROR"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Lookalike_Domain_Is_Rejected() {
        var r = Sample(); r.DnsQname = "definitionupdates.microsoft.com.evil.test";
        Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Info_Spoof_Does_Not_Create_Dns_Failure() {
        var r = Sample(); r.DnsRcode = null; r.Info = "security update blocked SERVFAIL";
        Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Dns_Query_Is_Not_A_Failure_Response() {
        var r = Sample(); r.DnsIsResponse = false; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Contradictory_Http_Metadata_Is_Rejected() {
        var r = Sample(); r.HttpMethod = "GET"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Independent_Resolvers_Do_Not_Accumulate() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample();
        Assert.False(await Hit(rule, r));
        var other = NetworkBatch266270Context.Copy(r); other.Source = "1.1.1.1";
        Assert.False(await Hit(rule, other, 1));
        Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 2));
    }
    [Fact] public async Task Expired_Responses_Do_Not_Count() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample();
        Assert.False(await Hit(rule, r));
        Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 1900));
        Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 1901));
    }
    [Fact] public async Task Evidence_Does_Not_Contain_Raw_Info() {
        var rule = new R269_SecurityToolUpdateBlockIndicatorRule(); var r = Sample(); r.Info = "secret-marker";
        Assert.False(await Hit(rule, r)); Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 1));
        var evt = Assert.Single((await rule.EvaluateAsync(At(NetworkBatch266270Context.Copy(r), 2))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Confidence_Mode_And_Threshold_Unchanged() {
        var p = new R269_SecurityToolUpdateBlockIndicatorRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence); Assert.Equal(3, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
