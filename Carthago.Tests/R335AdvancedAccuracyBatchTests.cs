// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R335AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()
    {
        var r = NetworkBatch321325Context.Sample();
        r.ApplicationProtocol = "SMB"; r.Protocol = "TCP"; r.IsTcp = true; r.IsUdp = false; r.DestinationPort = 445; r.HttpMethod = null; r.HttpHost = null; r.HttpUri = null;
        return r;
    }

    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, double seconds = 0)
        => await new R335_LSARPCSAMREnumerationPatternRule().EvaluateAsync(NetworkBatch321325Context.At(record, seconds));

    private static void AssertFailClosed(RuleEvaluationResult result)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, reason =>
            reason.Code == "RPC_ENUMERATION_AUDIT_UNAVAILABLE" && reason.Category == RuleNoMatchReasonCategory.InsufficientEvidence);
    }

    [Theory]
    [InlineData("samr")]
    [InlineData("lsarpc")]
    [InlineData("EnumDomainUsers")]
    [InlineData("LookupNames")]
    [InlineData("samr enumeration")]
    [InlineData("rpc bind")]
    public async Task Behavior_Indicator_Without_Authenticated_Outcome_Fails_Closed(string indicator)
    {
        var r = Sample();
        r.ApplicationProtocol = "SMB"; r.Protocol = "TCP"; r.IsTcp = true; r.IsUdp = false; r.DestinationPort = 445; r.HttpMethod = null; r.HttpHost = null; r.HttpUri = null; r.Info = indicator;
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Descriptor_Info_Spoof_Does_Not_Produce_An_Event()
    {
        var r = Sample(); r.Info = "R335 authenticated success Critical matched";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Duplicate_Record_Does_Not_Manufacture_An_Outcome()
    {
        var r = Sample(); var rule = new R335_LSARPCSAMREnumerationPatternRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r)));
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 1)));
    }

    [Fact] public async Task Out_Of_Order_Observations_Do_Not_Manufacture_An_Outcome()
    {
        var r = Sample(); var rule = new R335_LSARPCSAMREnumerationPatternRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 30)));
        r.Id = Guid.NewGuid();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 1)));
    }

    [Fact] public async Task Independent_Sources_Do_Not_Cross_Correlate()
    {
        var r = Sample(); var rule = new R335_LSARPCSAMREnumerationPatternRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r)));
        r.Id = Guid.NewGuid(); r.Source = "198.51.100.20";
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 2)));
    }

    [Fact] public async Task Missing_Source_Does_Not_Produce_An_Event()
    {
        var r = Sample(); r.Source = null;
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Contradictory_Transport_Does_Not_Produce_An_Event()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Secret_Bearing_Text_Is_Not_Emitted()
    {
        var r = Sample();
        r.Info = "Authorization: Bearer private-secret R335";
        r.HttpUri = "/?access_token=private-secret";
        r.HttpRequestHeaders = "Authorization: Bearer private-secret";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public void Confidence_Threshold_And_Default_Mode_Are_Preserved()
    {
        var p = new R335_LSARPCSAMREnumerationPatternRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
