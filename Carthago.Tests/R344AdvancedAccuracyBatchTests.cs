// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R344AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()
    {
        var r = NetworkBatch321325Context.Sample();
        r.Protocol = "TCP"; r.IsTcp = true; r.IsUdp = false;
        r.DestinationPort = 135;
        r.ApplicationProtocol = "DCERPC";
        r.HttpMethod = null;
        r.HttpHost = null;
        r.HttpUri = null;
        return r;
    }

    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, double seconds = 0)
        => await new R344_WMIEventSubscriptionRemotePatternRule().EvaluateAsync(NetworkBatch321325Context.At(record, seconds));

    private static void AssertFailClosed(RuleEvaluationResult result)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, reason =>
            reason.Code == "WMI_SUBSCRIPTION_AUDIT_UNAVAILABLE" && reason.Category == RuleNoMatchReasonCategory.InsufficientEvidence);
    }

    [Theory]
    [InlineData("__EventFilter")]
    [InlineData("CommandLineEventConsumer")]
    [InlineData("__FilterToConsumerBinding")]
    [InlineData("wmiprvse")]
    [InlineData("WMI event subscription")]
    [InlineData("IWbemServices PutInstance")]
    public async Task Apparent_Protocol_Indicator_Without_Trusted_Outcome_Fails_Closed(string indicator)
    {
        var r = Sample(); r.Info = indicator;
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Spoofed_Info_Claim_Does_Not_Emit()
    {
        var r = Sample(); r.Info = "R344 authenticated critical verified attack";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Duplicate_Id_Does_Not_Manufacture_Outcome()
    {
        var r = Sample(); var rule = new R344_WMIEventSubscriptionRemotePatternRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r)));
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 1)));
    }

    [Fact] public async Task Out_Of_Order_Observations_Do_Not_Manufacture_Outcome()
    {
        var r = Sample(); var rule = new R344_WMIEventSubscriptionRemotePatternRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 30)));
        r.Id = Guid.NewGuid();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 1)));
    }

    [Fact] public async Task Independent_Sources_Do_Not_Cross_Correlate()
    {
        var r = Sample(); var rule = new R344_WMIEventSubscriptionRemotePatternRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r)));
        r.Id = Guid.NewGuid(); r.Source = "198.51.100.20";
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 2)));
    }

    [Fact] public async Task Missing_Source_Fails_Closed()
    {
        var r = Sample(); r.Source = null;
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Contradictory_Typed_Transport_Fails_Closed()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Secret_Bearing_Metadata_Is_Not_Emitted()
    {
        var r = Sample();
        r.Info = "Authorization: Bearer private-secret";
        r.HttpUri = "/?access_token=private-secret";
        r.HttpRequestHeaders = "Authorization: Bearer private-secret";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public void Confidence_Threshold_And_Default_Mode_Remain_Unchanged()
    {
        var p = new R344_WMIEventSubscriptionRemotePatternRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
