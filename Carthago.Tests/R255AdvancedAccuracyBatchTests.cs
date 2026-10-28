// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R255AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch251255Context.Sample(255);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch251255Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R255_OffHoursBulkEgressIndicatorRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task OffHours_Automated_Large_Declared_Request_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Utc_Business_Hours_Are_Benign() {
        var r = Sample();
        var result = await new R255_OffHoursBulkEgressIndicatorRule().EvaluateAsync(At(r, -12 * 3600));
        Assert.False(result.Matched);
    }
    [Fact] public async Task Small_Declared_Body_Is_Benign() {
        var r = Sample(); r.HttpRequestHeaders = "Host: uploads.example\nContent-Length: 1024";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoofing_Does_Not_Provide_Bulk_Bytes() {
        var r = Sample(); r.HttpRequestHeaders = "Host: uploads.example";
        r.Info = "Content-Length: 262144000";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Unattributed_Process_Is_Rejected() {
        var r = Sample(); r.ProcessName = null; r.HttpUserAgent = "curl/8.0";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Backup_Client_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "veeamagent.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Is_Rejected() {
        var rule = new R255_OffHoursBulkEgressIndicatorRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Raw_Upload_Path_Is_Redacted() {
        var r = Sample(); r.HttpUri = "/api/upload/private-secret-marker";
        var result = await new R255_OffHoursBulkEgressIndicatorRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("private-secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R255_OffHoursBulkEgressIndicatorRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
