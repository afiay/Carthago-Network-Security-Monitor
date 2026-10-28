// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R233AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch231235Context.Sample(233);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch231235Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R233_PrinterAdminProtocolExternalAccessRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Printer_Admin_Http_On_631_Across_Segment_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Normal_Print_Job_Is_Not_Administration()
    {
        var r = Sample(); r.HttpUri = "/printers/queue/jobs";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Pjl_Without_Parsed_Admin_Path_Is_Rejected()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "@PJL printer admin";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Same_Subnet_Approved_Print_Server_Traffic_Is_Suppressed()
    {
        var r = Sample(); r.Destination = "10.231.0.200";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Wrong_Port_And_Tls_Contradiction_Are_Rejected()
    {
        var r = Sample(); r.DestinationPort = 443; r.TlsVersion = "TLS1.3";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Adminish_Substring_Is_Not_Admin_Route()
    {
        var r = Sample(); r.HttpUri = "/administration-guide";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Produce_Second_Match()
    {
        var rule = new R233_PrinterAdminProtocolExternalAccessRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Secret_Query_And_Info_Are_Not_Persisted()
    {
        var r = Sample(); r.HttpUri = "/admin/settings?password=secret-printer-marker";
        r.Info = "token=private-printer-marker";
        var x = await new R233_PrinterAdminProtocolExternalAccessRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        var evt = Assert.Single(x.Events);
        Assert.DoesNotContain("secret-printer-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            e => e.Value.Contains("private-printer-marker", StringComparison.Ordinal));
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Floor()
    {
        var p = new R233_PrinterAdminProtocolExternalAccessRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
