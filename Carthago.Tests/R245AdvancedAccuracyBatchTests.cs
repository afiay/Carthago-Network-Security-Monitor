// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R245AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch241245Context.Sample(245);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch241245Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R245_SensitiveFileExtensionUploadRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_External_Upload_Request_With_Exact_Filename_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Info_Only_Filename_Is_Not_An_Upload()
    {
        var r = Sample(); r.HttpUri = "/api/upload"; r.Info = "secret credentials.pem backup.zip";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Download_Method_Does_Not_Establish_Upload()
    {
        var r = Sample(); r.HttpMethod = "GET"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected()
    {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Not_External_Egress()
    {
        var r = Sample(); r.Destination = "10.243.0.200"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Content_Length_Cannot_Prove_Declared_Body()
    {
        var r = Sample(); r.HttpRequestHeaders = "Host: uploads.example";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Sync_Client_Is_Suppressed()
    {
        var r = Sample(); r.ProcessName = "onedrive.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Realert()
    {
        var rule = new R245_SensitiveFileExtensionUploadRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Is_Rejected()
    {
        var rule = new R245_SensitiveFileExtensionUploadRule(); var first = Sample();
        Assert.True((await rule.EvaluateAsync(At(first, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Sensitive_Request_Path_And_Info_Are_Redacted()
    {
        var r = Sample(); r.Info = "password=super-private-marker";
        var result = await new R245_SensitiveFileExtensionUploadRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("super-private-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("credentials.pem", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("customers_dump", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("backup_2026.zip", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("super-private-marker", StringComparison.Ordinal)
                || item.Value.Contains("credentials.pem", StringComparison.Ordinal)
                || item.Value.Contains("customers_dump", StringComparison.Ordinal)
                || item.Value.Contains("backup_2026.zip", StringComparison.Ordinal));
    }
    [Fact] public void Existing_Alert_Mode_And_Confidence_Floor()
    {
        var p = new R245_SensitiveFileExtensionUploadRule().PrecisionProfile;
        Assert.Equal(83, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

}
