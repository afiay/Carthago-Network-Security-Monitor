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

public sealed class R563AdvancedAccuracyBatchTests
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

    [Fact]
    public void ActualPacketHandlerClassifiesBothShapesAndRedactsDefaultCredential()
    {
        var http = Http();
        var write = Modbus();
        Assert.True(http.HttpBasicDefaultCredentialObserved);
        Assert.Equal("HTTP", http.ApplicationProtocol);
        Assert.Contains("Authorization: [REDACTED]", http.HttpRequestHeaders);
        Assert.DoesNotContain(SyntheticBasic, http.HttpRequestHeaders);
        Assert.Equal("modbus.write", write.ApplicationProtocol);
        Assert.False(write.HttpBasicDefaultCredentialObserved);
    }

    [Fact]
    public async Task OrderedHttpDefaultThenModbusWriteMatchesOneShadowCandidate()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var result = await rule.EvaluateAsync(At(Modbus(), 35));
        Assert.True(result.Matched);
        var detected = Assert.Single(result.Events);
        Assert.Equal("R563", detected.RuleId);
        Assert.Equal(SeverityLevel.High, detected.Severity);
        Assert.Equal(1, detected.Count);
        Assert.Equal(120, detected.WindowSeconds);
    }

    [Fact]
    public async Task BenignModbusReadDoesNotCompleteTheSequence()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(bytes: ReadBytes), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(bytes: ReadBytes), 20))).Matched);
    }

    [Fact]
    public async Task NonDefaultAndDuplicateAuthorizationNeverCreateSeed()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        var other = Http(credential: "YWRtaW46bm90LWRlZmF1bHQ=");
        var duplicate = Http(extra: "Authorization: Bearer synthetic\r\n");
        Assert.False(other.HttpBasicDefaultCredentialObserved);
        Assert.False(duplicate.HttpBasicDefaultCredentialObserved);
        Assert.False((await rule.EvaluateAsync(At(other))).Matched);
        Assert.False((await rule.EvaluateAsync(At(duplicate, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(), 2))).Matched);
    }

    [Fact]
    public async Task MissingAdminPathOrDifferentDestinationNeverCompletes()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Http(path: "/docs")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(target: "10.22.2.21"), 30))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Modbus(), 40))).Matched);
    }

    [Fact]
    public async Task SameSubnetCommissioningAndDifferentClientFailClosed()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Http(target: "10.12.1.20")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(target: "10.12.1.20"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(source: "10.12.1.11"), 4))).Matched);
    }

    [Fact]
    public async Task ReverseOrderAndEqualTimestampsDoNotCount()
    {
        var reverse = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await reverse.EvaluateAsync(At(Modbus()))).Matched);
        Assert.False((await reverse.EvaluateAsync(At(Http(), 1))).Matched);
        var equal = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await equal.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await equal.EvaluateAsync(At(Modbus()))).Matched);
    }

    [Fact]
    public async Task TimeoutAndOutOfOrderDoNotCompletePair()
    {
        var expired = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await expired.EvaluateAsync(At(Http()))).Matched);
        Assert.False((await expired.EvaluateAsync(At(Modbus(), 121))).Matched);
        var backwards = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await backwards.EvaluateAsync(At(Http(), 30))).Matched);
        Assert.False((await backwards.EvaluateAsync(At(Modbus(), 10))).Matched);
    }

    [Fact]
    public async Task DuplicatePacketIdCannotAdvanceSequence()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        var request = Http();
        var write = Modbus();
        write.Id = request.Id;
        Assert.False((await rule.EvaluateAsync(At(request))).Matched);
        Assert.False((await rule.EvaluateAsync(At(write, 2))).Matched);
    }

    [Fact]
    public async Task ImportCannotForgeParserOnlyHttpCredentialEvidence()
    {
        var fake = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"HttpBasicDefaultCredentialObserved\":true,\"ApplicationProtocol\":\"HTTP\",\"Source\":\"10.12.1.10\"}");
        Assert.NotNull(fake);
        Assert.False(fake.HttpBasicDefaultCredentialObserved);
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(fake))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Modbus(), 2))).Matched);
    }

    [Fact]
    public async Task ContradictoryTlsAndPortOnlyLabelsFailClosed()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        var https = Http(); https.TlsVersion = "TLS1.3";
        var portOnly = Modbus(); portOnly.ApplicationProtocol = null;
        Assert.False((await rule.EvaluateAsync(At(https))).Matched);
        Assert.False((await rule.EvaluateAsync(At(portOnly, 2))).Matched);
        var proper = Http(); proper.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(proper, 3))).Matched);
    }

    [Fact]
    public async Task RepeatedCompletePairDuringCooldownIsSuppressed()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Modbus(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Http(), 2))).Matched);
        var second = await rule.EvaluateAsync(At(Modbus(), 3));
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);
    }

    [Fact]
    public async Task ConcurrentDuplicateWriteEmitsAtMostOne()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Http()))).Matched);
        var same = Modbus();
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(same, 2)).AsTask(),
            rule.EvaluateAsync(At(same, 2)).AsTask());
        Assert.Equal(1, results.Count(x => x.Matched));
    }

    [Fact]
    public async Task EventExcludesSecretsAndFreeformPayloadText()
    {
        var rule = new R563_DefaultBasicThenModbusWriteRule();
        var first = Http();
        first.Info = "diagnostic-secret-marker";
        var last = Modbus();
        last.Info = "another-secret-marker";
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        var matched = await rule.EvaluateAsync(At(last, 2));
        var json = JsonSerializer.Serialize(Assert.Single(matched.Events));
        Assert.DoesNotContain(SyntheticBasic, json);
        Assert.DoesNotContain("diagnostic-secret-marker", json);
        Assert.DoesNotContain("another-secret-marker", json);
        Assert.DoesNotContain("plc.lab.internal", json);
        Assert.Contains("http.defaultBasicObserved", json);
    }

    [Fact]
    public void RegistryCandidateShadowAndConfidenceFloorArePreserved()
    {
        var found = RuleRegistry.CreateDefaultRules()
            .Where(rule => rule.Descriptor.RuleId == "R563").ToArray();
        var registered = Assert.IsType<R563_DefaultBasicThenModbusWriteRule>(Assert.Single(found));
        Assert.Equal("Rules.R563.Enabled", registered.Descriptor.ConfigKey);
        Assert.Equal(RulePrecisionMaturity.Candidate, registered.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, registered.PrecisionProfile.DefaultMode);
        Assert.Equal(90, registered.PrecisionProfile.MinimumConfidence);
    }
}
