// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R252AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch251255Context.Sample(252);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch251255Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R252_HighEntropyOutboundUriPathRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_High_Entropy_Upload_Path_Matches() => Assert.True(await Hit(Sample()));
    [Fact] public async Task Ordinary_Readable_Path_Is_Benign() {
        var r = Sample(); r.HttpUri = "/upload/images/normal-photo.jpg"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Browser_Client_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "chrome.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Only_Token_Is_Not_Path_Evidence() {
        var r = Sample(); r.Info = r.HttpUri; r.HttpUri = "/upload/file";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Get_Request_Is_Not_Upload() {
        var r = Sample(); r.HttpMethod = "GET"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Is_Rejected() {
        var rule = new R252_HighEntropyOutboundUriPathRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Is_Rejected() {
        var rule = new R252_HighEntropyOutboundUriPathRule();
        Assert.True((await rule.EvaluateAsync(At(Sample(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task High_Entropy_Token_Is_Redacted() {
        var r = Sample(); var token = r.HttpUri!.Split('/')[2];
        var result = await new R252_HighEntropyOutboundUriPathRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(token, evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item =>
            item.Value.Contains(token, StringComparison.Ordinal));
    }
    [Fact] public void Original_Shadow_Mode_And_Confidence_Are_Preserved() {
        var p = new R252_HighEntropyOutboundUriPathRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
