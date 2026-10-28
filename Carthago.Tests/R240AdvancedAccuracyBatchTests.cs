// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R240AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch236240Context.Sample(240);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch236240Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R240_ModbusWriteFunctionRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Parsed_Modbus_Write_Request_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Modbus_Read_Is_Benign()
    { var r = Sample(); r.ApplicationProtocol = "modbus"; Assert.False(await Hit(r)); }
    [Fact] public async Task Info_Write_Function_Spoof_Is_Rejected()
    { var r = Sample(); r.ApplicationProtocol = "modbus"; r.Info = "write multiple registers"; Assert.False(await Hit(r)); }
    [Fact] public async Task Port_Only_Does_Not_Prove_Write()
    { var r = Sample(); r.ApplicationProtocol = null; Assert.False(await Hit(r)); }
    [Fact] public async Task Wrong_Direction_Response_Is_Rejected()
    { var r = Sample(); r.SourcePort = 502; r.DestinationPort = 51000; Assert.False(await Hit(r)); }
    [Fact] public async Task Tls_Contradiction_Is_Rejected()
    { var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r)); }
    [Fact] public async Task Udp_Contradiction_Is_Rejected()
    { var r = Sample(); r.Protocol = "UDP"; r.IsTcp = false; r.IsUdp = true; Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Id_Does_Not_Match_Twice()
    { var rule = new R240_ModbusWriteFunctionRule(); var r = Sample();
      Assert.True((await rule.EvaluateAsync(At(r))).Matched);
      Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched); }
    [Fact] public async Task Packet_Info_Secret_Is_Not_Persisted()
    { var r = Sample(); r.Info = "password=secret-modbus-marker";
      var result = await new R240_ModbusWriteFunctionRule().EvaluateAsync(At(r));
      Assert.True(result.Matched); var e = Assert.Single(result.Events);
      Assert.DoesNotContain("secret-modbus-marker", e.Evidence ?? "", StringComparison.Ordinal);
      Assert.DoesNotContain(e.StructuredEvidence!.Items, i => i.Value.Contains("secret-modbus-marker", StringComparison.Ordinal)); }
    [Fact] public void Original_Alert_Mode_And_Floor()
    { var p = new R240_ModbusWriteFunctionRule().PrecisionProfile;
      Assert.Equal(90, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode); }
}
