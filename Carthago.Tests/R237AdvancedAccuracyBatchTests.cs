// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R237AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch236240Context.Sample(237);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch236240Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R237_IotDefaultWebAdminAccessRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Parsed_Device_Login_Cgi_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Generic_Admin_Is_Not_Default_Device_Route()
    { var r = Sample(); r.HttpUri = "/admin"; Assert.False(await Hit(r)); }
    [Fact] public async Task Info_Default_Credential_Spoof_Does_Not_Qualify()
    { var r = Sample(); r.HttpUri = "/"; r.Info = "router password=admin"; Assert.False(await Hit(r)); }
    [Fact] public async Task Missing_Device_Attribution_Is_Rejected()
    { var r = Sample(); r.ProcessName = null; Assert.False(await Hit(r)); }
    [Fact] public async Task Lookalike_Login_Cgi_Path_Is_Benign()
    { var r = Sample(); r.HttpUri = "/login.cgi.txt"; Assert.False(await Hit(r)); }
    [Fact] public async Task Wrong_Transport_Is_Rejected()
    { var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; Assert.False(await Hit(r)); }
    [Fact] public async Task Tls_Contradiction_Is_Rejected()
    { var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Id_Does_Not_Match_Twice()
    { var rule = new R237_IotDefaultWebAdminAccessRule(); var r = Sample();
      Assert.True((await rule.EvaluateAsync(At(r))).Matched);
      Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched); }
    [Fact] public async Task Query_Secret_And_Info_Not_In_Evidence()
    { var r = Sample(); r.HttpUri += "?password=secret-admin-marker"; r.Info = "token=private-admin-marker";
      var result = await new R237_IotDefaultWebAdminAccessRule().EvaluateAsync(At(r));
      Assert.True(result.Matched); var e = Assert.Single(result.Events);
      Assert.DoesNotContain("secret-admin-marker", e.Evidence ?? "", StringComparison.Ordinal);
      Assert.DoesNotContain(e.StructuredEvidence!.Items, i => i.Value.Contains("private-admin-marker", StringComparison.Ordinal)); }
    [Fact] public void Original_Alert_Mode_And_Floor()
    { var p = new R237_IotDefaultWebAdminAccessRule().PrecisionProfile;
      Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode); }
}
