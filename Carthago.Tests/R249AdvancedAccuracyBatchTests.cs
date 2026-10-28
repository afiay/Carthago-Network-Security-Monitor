// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R249AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch246250Context.Sample(249);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch246250Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R249_SmbUploadToExternalHostRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Smb2_Write_Request_Matches() => Assert.True(await Hit(Sample()));
    [Fact] public async Task Smb_Create_Without_Write_Is_Not_Enough() {
        var r = Sample(); r.ApplicationProtocol = "smb2.create.request"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Port_Only_Info_Spoofing_Is_Not_Enough() {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "SMB WRITE request";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Smb2_Response_Is_Not_Write_Request() {
        var r = Sample(); r.ApplicationProtocol = "smb2.write.response"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Smb_Write_Is_Excluded() {
        var r = Sample(); r.Destination = "10.249.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Wrong_Port_Is_Rejected() {
        var r = Sample(); r.DestinationPort = 1445; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Tls_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Rejected() {
        var rule = new R249_SmbUploadToExternalHostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Packet_Info_And_Destination_Are_Redacted() {
        var r = Sample(); r.Info = "password=smb-secret-marker";
        var result = await new R249_SmbUploadToExternalHostRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("smb-secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.249", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R249_SmbUploadToExternalHostRule().PrecisionProfile;
        Assert.Equal(86, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

}
