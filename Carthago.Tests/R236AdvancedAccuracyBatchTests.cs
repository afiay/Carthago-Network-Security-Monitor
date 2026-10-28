// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R236AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch236240Context.Sample(236);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch236240Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R236_IotFirmwareUpdateOverCleartextRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Parsed_Device_Firmware_Get_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Ordinary_Binary_Download_Is_Benign()
    { var r = Sample(); r.HttpUri = "/downloads/tool.bin"; Assert.False(await Hit(r)); }
    [Fact] public async Task Info_Firmware_Claim_Does_Not_Replace_Parsed_Route()
    { var r = Sample(); r.HttpUri = "/index.html"; r.Info = "firmware update.bin"; Assert.False(await Hit(r)); }
    [Fact] public async Task Unknown_Device_Process_Does_Not_Prove_Iot()
    { var r = Sample(); r.ProcessName = null; Assert.False(await Hit(r)); }
    [Fact] public async Task Tls_Contradiction_Is_Not_Cleartext()
    { var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r)); }
    [Fact] public async Task Post_Is_Not_Artifact_Download()
    { var r = Sample(); r.HttpMethod = "POST"; Assert.False(await Hit(r)); }
    [Fact] public async Task Query_Only_Firmware_Name_Is_Not_Artifact()
    { var r = Sample(); r.HttpUri = "/search?q=/firmware/router.bin"; Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Id_Does_Not_Match_Twice()
    { var rule = new R236_IotFirmwareUpdateOverCleartextRule(); var r = Sample();
      Assert.True((await rule.EvaluateAsync(At(r))).Matched);
      Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched); }
    [Fact] public async Task Secret_Query_And_Info_Are_Redacted()
    { var r = Sample(); r.HttpUri += "?token=private-firmware-marker"; r.Info = "password=secret-firmware-marker";
      var result = await new R236_IotFirmwareUpdateOverCleartextRule().EvaluateAsync(At(r));
      Assert.True(result.Matched); var e = Assert.Single(result.Events);
      Assert.DoesNotContain("private-firmware-marker", e.Evidence ?? "", StringComparison.Ordinal);
      Assert.DoesNotContain(e.StructuredEvidence!.Items, i => i.Value.Contains("secret-firmware-marker", StringComparison.Ordinal)); }
    [Fact] public void Original_Alert_Mode_And_Floor()
    { var p = new R236_IotFirmwareUpdateOverCleartextRule().PrecisionProfile;
      Assert.Equal(84, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode); }
}
