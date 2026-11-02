// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R570AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 12, 0, 0, DateTimeKind.Utc);
    private const string SyntheticBasic = "YWRtaW46YWRtaW4="; // Synthetic admin:admin, never a real secret.
    private static readonly byte[] WriteBytes = { 0, 1, 0, 0, 0, 6, 1, 6, 0, 1, 0, 2 };
    private static readonly byte[] ReadBytes = { 0, 1, 0, 0, 0, 6, 1, 3, 0, 1, 0, 2 };

    private static TrafficRecord Packet(string source, string destination, int sourcePort,
        int destinationPort, byte[] payload)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64;
        frame[9] = 6;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        frame[32] = 0x50;
        frame[33] = 0x18;
        payload.CopyTo(frame, 40);
        var parsed = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
        Assert.NotNull(parsed);
        return parsed!;
    }

    private static TrafficRecord Http(string source = "10.12.1.10", string target = "10.22.2.20",
        string path = "/admin", string credential = SyntheticBasic, string extra = "")
        => Packet(source, target, 51001, 80, Encoding.ASCII.GetBytes(
            "GET " + path + " HTTP/1.1\r\nHost: plc.lab.internal\r\nAuthorization: Basic "
            + credential + "\r\n" + extra + "\r\n"));

    private static TrafficRecord Modbus(string source = "10.12.1.10", string target = "10.22.2.20",
        byte[]? bytes = null, int port = 502)
        => Packet(source, target, 51002, port, bytes ?? WriteBytes);

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));


    [Fact] public async Task ParsedModbusWriteThenHttpDefaultAdminMatches()
    {
        var rule = new R570_ModbusWriteThenDefaultBasicAdminRule();
        Assert.False((await rule.EvaluateAsync(At(Modbus()))).Matched);
        var result = await rule.EvaluateAsync(At(Http(), 20));
        Assert.True(result.Matched);
        Assert.Equal("R570", Assert.Single(result.Events).RuleId);
    }
    [Fact] public async Task ReverseOrderAndEqualTimeDoNotMatch()
    {
        var reversed = new R570_ModbusWriteThenDefaultBasicAdminRule();
        Assert.False((await reversed.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await reversed.EvaluateAsync(At(Modbus(), 1))).Matched);
        var equal = new R570_ModbusWriteThenDefaultBasicAdminRule();
        Assert.False((await equal.EvaluateAsync(At(Modbus()))).Matched);
        Assert.False((await equal.EvaluateAsync(At(Http()))).Matched);
    }
    [Fact] public async Task ReadRequestAndWrongPeerNeverSeed()
    {
        var rule = new R570_ModbusWriteThenDefaultBasicAdminRule();
        Assert.False((await rule.EvaluateAsync(At(Modbus(bytes: ReadBytes)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(source: "10.12.1.11"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 3))).Matched);
    }
    [Fact] public async Task OrdinaryCredentialsAndNonAdminRoutesAreBenign()
    {
        foreach (var http in new[] { Http(credential: "YWRtaW46c3Ryb25n"), Http(path: "/status") })
        {
            var rule = new R570_ModbusWriteThenDefaultBasicAdminRule();
            Assert.False((await rule.EvaluateAsync(At(Modbus()))).Matched);
            Assert.False((await rule.EvaluateAsync(At(http, 1))).Matched);
        }
    }
    [Fact] public async Task ExpiryAndDuplicateIdsFailClosed()
    {
        var late = new R570_ModbusWriteThenDefaultBasicAdminRule();
        Assert.False((await late.EvaluateAsync(At(Modbus()))).Matched);
        Assert.False((await late.EvaluateAsync(At(Http(), 121))).Matched);
        var duplicate = new R570_ModbusWriteThenDefaultBasicAdminRule();
        var modbus = Modbus(); var http = Http(); http.Id = modbus.Id;
        Assert.False((await duplicate.EvaluateAsync(At(modbus))).Matched);
        Assert.False((await duplicate.EvaluateAsync(At(http, 1))).Matched);
    }
    [Fact] public async Task EventDoesNotExposeSensitiveInfo()
    {
        var rule = new R570_ModbusWriteThenDefaultBasicAdminRule();
        var modbus = Modbus(); modbus.Info = "private-secret-marker";
        Assert.False((await rule.EvaluateAsync(At(modbus))).Matched);
        var evt = Assert.Single((await rule.EvaluateAsync(At(Http(), 1))).Events);
        var json = JsonSerializer.Serialize(evt);
        Assert.DoesNotContain("private-secret-marker", json);
        Assert.DoesNotContain(SyntheticBasic, json);
    }
    [Fact] public void RegistryContainsCandidateShadowRuleExactlyOnce()
    {
        var rule = Assert.IsType<R570_ModbusWriteThenDefaultBasicAdminRule>(
            Assert.Single(RuleRegistry.CreateDefaultRules().Where(x => x.Descriptor.RuleId == "R570")));
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
    }
}
