// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R251AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch251255Context.Sample(251);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch251255Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R251_MultipartUploadToUnknownDomainRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Multipart_Request_First_Observed_Domain_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Plain_Form_Post_Is_Not_Multipart() {
        var r = Sample(); r.HttpRequestHeaders = "Host: new-upload.example\nContent-Type: application/x-www-form-urlencoded";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoofing_Cannot_Provide_Multipart() {
        var r = Sample(); r.HttpRequestHeaders = "Host: new-upload.example";
        r.Info = "multipart/form-data; boundary=BoundaryXYZ123";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Cloud_Root_Is_Not_Unknown() {
        var r = Sample(); r.HttpHost = "uploads.dropbox.com";
        r.HttpRequestHeaders = "Host: uploads.dropbox.com\nContent-Type: multipart/form-data; boundary=BoundaryXYZ123";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Ip_Literal_Is_Not_Unknown_Domain() {
        var r = Sample(); r.HttpHost = "198.51.100.251";
        r.HttpRequestHeaders = "Host: 198.51.100.251\nContent-Type: multipart/form-data; boundary=BoundaryXYZ123";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Rejected() {
        var r = Sample(); r.Destination = "10.251.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Is_Rejected() {
        var rule = new R251_MultipartUploadToUnknownDomainRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Domain_Already_Observed_By_Instance_Does_Not_Retrigger() {
        var rule = new R251_MultipartUploadToUnknownDomainRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Independent_Source_Has_Its_Own_First_Observation() {
        var rule = new R251_MultipartUploadToUnknownDomainRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        var r = Sample(); r.Source = "10.251.0.20";
        Assert.True((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Contradictory_Host_Header_Is_Rejected() {
        var r = Sample(); r.HttpRequestHeaders = "Host: different.example\nContent-Type: multipart/form-data; boundary=BoundaryXYZ123";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Host_And_Info_Are_Redacted() {
        var r = Sample(); r.Info = "password=private-marker";
        var result = await new R251_MultipartUploadToUnknownDomainRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("new-upload.example", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("private-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R251_MultipartUploadToUnknownDomainRule().PrecisionProfile;
        Assert.Equal(84, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
