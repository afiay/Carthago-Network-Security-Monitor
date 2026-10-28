// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R256AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch256260Context.Sample(256);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch256260Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R256_InternalDataStagingServerBehaviorRule().EvaluateAsync(At(r))).Matched;
    private static async Task<bool> Burst(R256_InternalDataStagingServerBehaviorRule rule, int count)
    {
        bool hit = false;
        for (var i = 0; i < count; i++)
            hit = (await rule.EvaluateAsync(At(Sample(), i))).Matched;
        return hit;
    }
    [Fact] public async Task Six_Distinct_Archive_Named_Internal_Requests_Match()
        => Assert.True(await Burst(new R256_InternalDataStagingServerBehaviorRule(), 6));
    [Fact] public async Task Five_Requests_Are_Below_Threshold()
        => Assert.False(await Burst(new R256_InternalDataStagingServerBehaviorRule(), 5));
    [Fact] public async Task Ordinary_File_Share_Path_Is_Benign() {
        var r = Sample(); r.HttpUri = "/files/report.txt"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Cannot_Supply_Archive_Path() {
        var r = Sample(); r.HttpUri = "/files/report.txt"; r.Info = "source_backup.tar.gz";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task External_Destination_Is_Not_Internal_Staging() {
        var r = Sample(); r.Destination = "198.51.100.56"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Backup_Process_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "veeamagent.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Repeated_Same_Packet_Id_Does_Not_Count() {
        var rule = new R256_InternalDataStagingServerBehaviorRule(); var r = Sample();
        for (var i = 0; i < 9; i++)
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Requests_Are_Rejected() {
        var rule = new R256_InternalDataStagingServerBehaviorRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 20))).Matched);
        for (var i = 1; i < 6; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
    }
    [Fact] public async Task Independent_Sources_Do_Not_Combine() {
        var rule = new R256_InternalDataStagingServerBehaviorRule();
        for (var i = 0; i < 6; i++) {
            var r = Sample(); if (i % 2 == 0) r.Source = "10.56.0.11";
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Missing_Declared_Size_Is_Rejected() {
        var r = Sample(); r.HttpRequestHeaders = "Host: staging.internal.example";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Path_And_Info_Secrets_Are_Redacted() {
        var rule = new R256_InternalDataStagingServerBehaviorRule();
        RuleEvaluationResult result = RuleEvaluationResult.NoMatch("R256");
        for (var i = 0; i < 6; i++) {
            var r = Sample(); r.HttpUri = "/private-secret-marker/source_backup.tar.gz";
            r.Info = "password=private-secret-marker";
            result = await rule.EvaluateAsync(At(r, i));
        }
        Assert.True(result.Matched);
        Assert.DoesNotContain("private-secret-marker", Assert.Single(result.Events).Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Existing_Alert_Confidence_And_Threshold_Remain() {
        var p = new R256_InternalDataStagingServerBehaviorRule().PrecisionProfile;
        Assert.Equal(80, p.MinimumConfidence); Assert.Equal(6, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
