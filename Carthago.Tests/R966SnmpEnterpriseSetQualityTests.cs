// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;
public sealed class R966SnmpEnterpriseSetQualityTests
{
    private static readonly DateTime Epoch = new(2026, 11, 13, 0, 0, 0, DateTimeKind.Utc);
    private const string Community = "private-community-fixture";
    private const string Value = "private-setting-fixture";
    private static byte[] Tlv(byte tag, params byte[][] values)
    {
        var bytes = values.SelectMany(x => x).ToArray();
        byte[] length = bytes.Length < 128 ? new[] { (byte)bytes.Length } :
            bytes.Length <= 255 ? new[] { (byte)0x81, (byte)bytes.Length } :
            new[] { (byte)0x82, (byte)(bytes.Length >> 8), (byte)bytes.Length };
        return new[] { tag }.Concat(length).Concat(bytes).ToArray();
    }
    private static byte[] I(byte v) => Tlv(2, new[] { v });
    private static byte[] Message(byte version = 1, byte pdu = 0xA3, byte error = 0,
        byte index = 0, byte[]? oid = null, byte[]? value = null, int count = 1)
    {
        var binding = Tlv(0x30, Tlv(6, oid ?? new byte[] { 0x2B, 6, 1, 4, 1, 9, 1 }),
            value ?? Tlv(4, Encoding.ASCII.GetBytes(Value)));
        return Tlv(0x30, I(version), Tlv(4, Encoding.ASCII.GetBytes(Community)),
            Tlv(pdu, I(7), I(error), I(index), Tlv(0x30, Enumerable.Repeat(binding, count).ToArray())));
    }
    private static TrafficRecord Capture(byte[]? payload = null, string src = "8.8.8.8",
        string dst = "10.1.2.45", int port = 161, bool badLength = false)
        => TftpCaptureQualificationTests.Parse(new PacketHandler(), src, dst, 51000, port,
            payload ?? Message(), badLength);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    public async Task CapturePositiveAndPrivacy(byte version)
    {
        var r = Capture(Message(version: version));
        Assert.True(r.SnmpEnterpriseSetRequestObserved);
        var result = await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r, 0));
        Assert.True(result.Matched);
        string json = JsonSerializer.Serialize(new { Record = r, result.Events });
        Assert.DoesNotContain(Community, json);
        Assert.DoesNotContain(Value, json);
    }

    [Theory]
    [InlineData((byte)0xA0)] // GET
    [InlineData((byte)0xA1)] // GETNEXT
    [InlineData((byte)0xA2)] // response
    [InlineData((byte)0xA5)] // GETBULK
    public async Task BenignPollingAndResponseDoNotMatch(byte tag)
    {
        var r = Capture(Message(pdu: tag, value: Tlv(5)));
        Assert.False(r.SnmpEnterpriseSetRequestObserved);
        Assert.False((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r, 0))).Matched);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("error")]
    [InlineData("index")]
    [InlineData("empty")]
    [InlineData("many")]
    [InlineData("nonenterprise")]
    [InlineData("prefix")]
    [InlineData("unterminated")]
    [InlineData("overlongarc")]
    [InlineData("null")]
    [InlineData("badinteger")]
    [InlineData("longvalue")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("indefinite")]
    [InlineData("random")]
    public async Task InvalidOrUnsupportedBerFailsClosed(string variant)
    {
        byte[] payload = variant switch
        {
            "version" => Message(version: 3),
            "error" => Message(error: 1),
            "index" => Message(index: 1),
            "empty" => Message(count: 0),
            "many" => Message(count: 33),
            "nonenterprise" => Message(oid: new byte[] { 0x2B,6,1,2,1,1,1,0 }),
            "prefix" => Message(oid: new byte[] { 0x2B,6,1,4,1,9 }),
            "unterminated" => Message(oid: new byte[] { 0x2B,6,1,4,1,9,0x81 }),
            "overlongarc" => Message(oid: new byte[] { 0x2B,6,1,4,1,9,0x80,1 }),
            "null" => Message(value: Tlv(5)),
            "badinteger" => Message(value: Tlv(2, new byte[] { 0, 1 })),
            "longvalue" => Message(value: Tlv(4, new byte[1025])),
            "truncated" => Message()[..^1],
            "trailing" => Message().Concat(new byte[] { 0 }).ToArray(),
            "indefinite" => new byte[] { 0x30,0x80 }.Concat(Message().Skip(2)).Concat(new byte[] { 0,0 }).ToArray(),
            _ => new byte[] { 0x30,0x06,1,2,3,4,5,6 }
        };
        Assert.False(SnmpEnterpriseSetInspector.TryInspect(payload));
        var r = Capture(payload);
        Assert.False(r.SnmpEnterpriseSetRequestObserved);
        Assert.False((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r, 0))).Matched);
    }

    [Fact]
    public async Task BoundsAndScopeAreEnforced()
    {
        Assert.True(SnmpEnterpriseSetInspector.TryInspect(Message(count: 32)));
        Assert.True(SnmpEnterpriseSetInspector.TryInspect(Message(value: Tlv(4, new byte[1024]))));
        Assert.True(SnmpEnterpriseSetInspector.TryInspect(Message(value: I(1))));
        foreach (var r in new[] { Capture(src: "10.1.1.10"), Capture(dst: "9.9.9.9"),
            Capture(port: 162), Capture(badLength: true) })
            Assert.False((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r, 0))).Matched);
    }

    [Fact]
    public async Task LabelsAndContradictoryTelemetryCannotSubstituteForCapture()
    {
        var rule = new R966_PublicSnmpEnterpriseSetRequestRule();
        var fake = Capture(new byte[] { 1, 2, 3 });
        fake.ApplicationProtocol = "snmp.enterprise.set.request"; fake.Info = "SNMP SET";
        Assert.False((await rule.EvaluateAsync(At(fake, 0))).Matched);
        foreach (string kind in new[] { "tcp", "port", "id", "tls", "dns", "label" })
        {
            var r = Capture();
            switch (kind)
            {
                case "tcp": r.IsTcp = true; break;
                case "port": r.DestinationPort = 162; break;
                case "id": r.Id = Guid.Empty; break;
                case "tls": r.Sni = "other.example"; break;
                case "dns": r.DnsIsResponse = true; break;
                case "label": r.ApplicationProtocol = "UDP"; break;
            }
            Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
        }
    }

    [Fact]
    public async Task CooldownDuplicateReverseAndPeerIsolation()
    {
        var rule = new R966_PublicSnmpEnterpriseSetRequestRule();
        var first = Capture();
        Assert.True((await rule.EvaluateAsync(At(first, 100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first, 101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(), 99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(), 200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst: "10.1.2.46"), 201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(), 1000))).Matched);
        Assert.True((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(Capture(), 100))).Matched);
    }

    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules = RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(r => r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule = Assert.IsType<R966_PublicSnmpEnterpriseSetRequestRule>(Assert.Single(rules.Where(r => r.Descriptor.RuleId == "R966")));
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
    }
}
