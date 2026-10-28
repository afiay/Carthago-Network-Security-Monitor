// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R246AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch246250Context.Sample(246);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch246250Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R246_SourceCodeArchiveUploadRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Source_Archive_Upload_Request_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Ordinary_Archive_Is_Not_Source_Code_Evidence() {
        var r = Sample(); r.HttpUri = "/upload/photos.zip"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Generic_Project_Text_Without_Archive_Is_Benign() {
        var r = Sample(); r.HttpUri = "/upload/project.txt"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoofing_Does_Not_Supply_Filename() {
        var r = Sample(); r.HttpUri = "/upload/data.zip"; r.Info = "repo-source.zip";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Official_Git_Client_Publishing_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "git.exe"; r.HttpHost = "github.com";
        r.HttpRequestHeaders = "Host: github.com\nContent-Length: 4096";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Sync_Client_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "onedrive.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Realert() {
        var rule = new R246_SourceCodeArchiveUploadRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Packet_Is_Rejected() {
        var rule = new R246_SourceCodeArchiveUploadRule();
        Assert.True((await rule.EvaluateAsync(At(Sample(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Sensitive_Filename_And_Info_Are_Not_Persisted() {
        var r = Sample(); r.Info = "password=private-marker";
        var result = await new R246_SourceCodeArchiveUploadRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("project-src.zip", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("private-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item =>
            item.Value.Contains("project-src.zip", StringComparison.Ordinal)
            || item.Value.Contains("private-marker", StringComparison.Ordinal));
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R246_SourceCodeArchiveUploadRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

}
