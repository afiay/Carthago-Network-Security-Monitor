// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R253AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch251255Context.Sample(253);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch251255Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R253_Base64BlobInHttpPostRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Encoded_Query_On_Automated_Upload_Matches() => Assert.True(await Hit(Sample()));
    [Fact] public async Task Jwt_Authorization_Header_Alone_Is_Benign() {
        var r = Sample(); r.HttpUri = "/upload";
        r.HttpRequestHeaders = "Host: encoded.example\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.signature";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoofing_Cannot_Provide_Encoded_Query() {
        var r = Sample(); r.Info = r.HttpUri; r.HttpUri = "/upload";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Short_Encoded_Query_Is_Benign() {
        var r = Sample(); r.HttpUri = "/upload?data=YWJj"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Unrelated_Query_Parameter_Is_Benign() {
        var r = Sample(); r.HttpUri = r.HttpUri!.Replace("?data=", "?token=");
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Trusted_Process_Is_Rejected() {
        var r = Sample(); r.ProcessName = null; r.HttpUserAgent = "curl/8.0";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Rejected() {
        var rule = new R253_Base64BlobInHttpPostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Raw_Encoded_Value_Is_Not_In_Evidence() {
        var r = Sample(); var token = r.HttpUri!.Split('=')[1];
        var result = await new R253_Base64BlobInHttpPostRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(token, evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item =>
            item.Value.Contains(token, StringComparison.Ordinal));
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R253_Base64BlobInHttpPostRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
