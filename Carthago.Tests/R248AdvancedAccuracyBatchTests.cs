// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R248AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch246250Context.Sample(248);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch246250Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R248_FtpUploadToExternalHostRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Stor_Request_Matches() => Assert.True(await Hit(Sample()));
    [Fact] public async Task Parsed_Append_Request_Matches() {
        var r = Sample(); r.ApplicationProtocol = "ftp.appe"; Assert.True(await Hit(r));
    }
    [Fact] public async Task Ftp_List_Is_Not_An_Upload() {
        var r = Sample(); r.ApplicationProtocol = "ftp.list"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoofing_Cannot_Supply_Stor() {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "STOR secrets.zip";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Server_Response_Direction_Is_Not_An_Upload() {
        var r = Sample(); r.SourcePort = 21; r.DestinationPort = 51000;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Excluded() {
        var r = Sample(); r.Destination = "10.248.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Udp_Is_Rejected() {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Rejected() {
        var rule = new R248_FtpUploadToExternalHostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Info_And_Host_Are_Redacted() {
        var r = Sample(); r.Info = "password=ftp-secret-marker";
        var result = await new R248_FtpUploadToExternalHostRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("ftp-secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.248", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("198.51.100.248", StringComparison.Ordinal));
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R248_FtpUploadToExternalHostRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

}
