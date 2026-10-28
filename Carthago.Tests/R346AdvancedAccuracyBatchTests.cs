// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R346AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()
    {
        var r = NetworkBatch321325Context.Sample();
        r.Protocol = "TCP"; r.IsTcp = true; r.IsUdp = false;
        r.DestinationPort = 1433;
        r.ApplicationProtocol = "TDS";
        r.HttpMethod = null; r.HttpHost = null; r.HttpUri = null;
        return r;
    }

    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, double seconds = 0)
        => await new R346_MSSQLXpCmdshellUseIndicatorRule().EvaluateAsync(NetworkBatch321325Context.At(record, seconds));

    private static void AssertFailClosed(RuleEvaluationResult result)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, reason =>
            reason.Code == "MSSQL_COMMAND_AUDIT_UNAVAILABLE" && reason.Category == RuleNoMatchReasonCategory.InsufficientEvidence);
    }

    [Theory]
    [InlineData("xp_cmdshell")]
    [InlineData("EXEC master..xp_cmdshell")]
    [InlineData("sp_configure xp_cmdshell")]
    [InlineData("mssql command shell")]
    [InlineData("TDS SQL batch")]
    [InlineData("SQL Server xp_cmdshell")]
    public async Task Protocol_Text_Without_Authenticated_Operation_Fails_Closed(string indicator)
    {
        var r = Sample(); r.Info = indicator;
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Info_Spoofed_Authenticated_Outcome_Fails_Closed()
    {
        var r = Sample(); r.Info = "R346 Critical verified authenticated success";
        AssertFailClosed(await Evaluate(r));
    }

    [Fact] public async Task Duplicate_Record_Id_Does_Not_Manufacture_Outcome()
    {
        var r = Sample(); var rule = new R346_MSSQLXpCmdshellUseIndicatorRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r)));
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 1)));
    }

    [Fact] public async Task Out_Of_Order_Records_Do_Not_Manufacture_Outcome()
    {
        var r = Sample(); var rule = new R346_MSSQLXpCmdshellUseIndicatorRule();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 30)));
        r.Id = Guid.NewGuid();
        AssertFailClosed(await rule.EvaluateAsync(NetworkBatch321325Context.At(r, 1)));
    }

    [Fact] public async Task Different_Sources_Do_Not_Cross_Correlate()
    {
        var r = Sample(); var rule = new R346_MSSQLXpCmdshellUseIndicatorRule();
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
        var p = new R346_MSSQLXpCmdshellUseIndicatorRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
