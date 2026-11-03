// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Synthetic LDAPv3 TCP frames only.
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class LdapSimpleBindCaptureIntegrationTests
{
    internal static byte[] Bind(byte[]? password = null)
    {
        password ??= Encoding.ASCII.GetBytes("synthetic-secret");
        var name = Encoding.ASCII.GetBytes("cn=synthetic");
        var inner = new byte[] { 0x02, 0x01, 0x03, 0x04, (byte)name.Length }
            .Concat(name).Concat(new byte[] { 0x80, (byte)password.Length })
            .Concat(password).ToArray();
        var op = new byte[] { 0x60, (byte)inner.Length }.Concat(inner).ToArray();
        var message = new byte[] { 0x02, 0x01, 0x07 }.Concat(op).ToArray();
        return new byte[] { 0x30, (byte)message.Length }.Concat(message).ToArray();
    }

    private static byte[] Frame(byte[] payload, int sourcePort, int destinationPort,
        uint sequence, byte flags, bool reverse = false, bool privateSource = false,
        string? sourceOverride = null)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64;
        frame[9] = 6;
        IPAddress.Parse(reverse ? "10.20.0.66" : privateSource ? "10.21.0.44" : sourceOverride ?? "203.0.113.44")
            .GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(reverse ? "203.0.113.44" : "10.20.0.66")
            .GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        frame[24] = (byte)(sequence >> 24);
        frame[25] = (byte)(sequence >> 16);
        frame[26] = (byte)(sequence >> 8);
        frame[27] = (byte)sequence;
        frame[32] = 0x50;
        frame[33] = flags;
        payload.CopyTo(frame, 40);
        return frame;
    }

    internal static TrafficRecord Parse(byte[] payload, int destinationPort = 389,
        bool witnessedSyn = true, uint payloadSequence = 1, bool reverse = false,
        bool privateSource = false, string? sourceOverride = null)
    {
        var handler = new PacketHandler();
        var sourcePort = reverse ? 389 : 48000;
        var destination = reverse ? 48000 : destinationPort;
        var link = (PacketDotNet.LinkLayers)12;
        if (witnessedSyn)
            Assert.NotNull(handler.ParseFrame(Frame(Array.Empty<byte>(), sourcePort, destination,
                0, 0x02, reverse, privateSource, sourceOverride), link));
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(
            Frame(payload, sourcePort, destination, payloadSequence, 0x18, reverse, privateSource, sourceOverride), link));
    }

    [Fact]
    public async Task VerifiedInboundSimpleBindCreatesOnlyShadowCandidate()
    {
        var record = Parse(Bind());
        Assert.True(record.LdapCleartextSimpleBindObserved);
        Assert.Equal("ldap.bind.simple", record.ApplicationProtocol);
        Assert.DoesNotContain("synthetic-secret", string.Join("|", record.Info,
            record.ApplicationProtocol, record.HttpUri, record.HttpRequestHeaders));

        var rule = new R286_LDAPSimpleBindOverCleartextExternalRule();
        // Historical profile metadata stays unchanged; the new candidate
        // observation is independently forced to Shadow at emission.
        Assert.Equal(RuleRuntimeMode.Alert, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(78, rule.PrecisionProfile.MinimumConfidence);
        Assert.True(RulePrecisionCatalog.HasField("capture_only_ldap_simple_bind", record));
        Assert.True(RulePrecisionCatalog.Validate("R286", record).CanEvaluate);
        var result = await rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.True(result.Matched);
        Assert.All(result.Events, evt =>
        {
            Assert.Equal("R286", evt.RuleId);
            Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus);
            Assert.DoesNotContain("synthetic-secret", evt.Evidence ?? string.Empty);
        });
    }

    [Fact]
    public void TruncatedCaptureAndOversizedFirstPayloadCannotAttestLdapMessageBoundary()
    {
        var handler = new PacketHandler();
        var link = (PacketDotNet.LinkLayers)12;
        Assert.NotNull(handler.ParseFrame(Frame(Array.Empty<byte>(), 48000, 389, 0, 0x02), link));
        var truncatedCapture = Frame(Bind(), 48000, 389, 1, 0x18);
        truncatedCapture[3]++; // Advertised IP total exceeds captured snap length.
        var truncatedRecord = Assert.IsType<TrafficRecord>(handler.ParseFrame(truncatedCapture, link));
        Assert.False(truncatedRecord.LdapCleartextSimpleBindObserved);

        // A complete 4096-byte LDAPMessage followed by one additional TCP
        // byte must not be certified after the inspection budget clips it.
        var longBind = new byte[4096];
        new byte[] { 0x30, 0x82, 0x0f, 0xfc, 0x02, 0x01, 0x07,
            0x60, 0x82, 0x0f, 0xf5, 0x02, 0x01, 0x03,
            0x04, 0x82, 0x0f, 0xeb }.CopyTo(longBind, 0);
        Array.Fill(longBind, (byte)'a', 18, 4075);
        longBind[4093] = 0x80;
        longBind[4094] = 0x01;
        longBind[4095] = (byte)'x';
        var oversized = longBind.Concat(new byte[] { 0x30 }).ToArray();
        var anotherHandler = new PacketHandler();
        Assert.NotNull(anotherHandler.ParseFrame(Frame(Array.Empty<byte>(), 48001, 389, 0, 0x02), link));
        var oversizedRecord = Assert.IsType<TrafficRecord>(anotherHandler.ParseFrame(
            Frame(oversized, 48001, 389, 1, 0x18), link));
        Assert.False(oversizedRecord.LdapCleartextSimpleBindObserved);
    }

    [Fact]
    public void FragmentAndResetBearingPayloadsAreNeverAdmitted()
    {
        var link = (PacketDotNet.LinkLayers)12;
        var fragment = Frame(Bind(), 48000, 389, 1, 0x18);
        fragment[6] = 0x20; // More IPv4 fragments; cannot reconstruct TCP PDU.
        Assert.Null(new PacketHandler().ParseFrame(fragment, link));
        var handler = new PacketHandler();
        Assert.NotNull(handler.ParseFrame(Frame(Array.Empty<byte>(), 48000, 389, 0, 0x02), link));
        var resetRecord = Assert.IsType<TrafficRecord>(handler.ParseFrame(Frame(Bind(), 48000, 389, 1, 0x1c), link));
        Assert.False(resetRecord.LdapCleartextSimpleBindObserved);
    }

    [Fact]
    public async Task NoSynGapWrongPortServerDirectionAndTlsDoNotProduceSimpleBind()
    {
        var bind = Bind();
        var negative = new[]
        {
            Parse(bind, witnessedSyn: false),
            Parse(bind, payloadSequence: 2),
            Parse(bind, destinationPort: 636),
            Parse(bind, reverse: true),
            Parse(bind.Take(bind.Length - 1).ToArray()),
            Parse(new byte[] { 0x16, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5 })
        };
        var rule = new R286_LDAPSimpleBindOverCleartextExternalRule();
        foreach (var record in negative)
        {
            Assert.False(record.LdapCleartextSimpleBindObserved);
            Assert.False((await rule.EvaluateAsync(
                new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow))).Matched);
        }
    }

    [Fact]
    public async Task ImportedAndTextClaimedSimpleBindCannotForgeCaptureFlag()
    {
        var claimed = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"Source\":\"203.0.113.44\",\"Destination\":\"10.20.0.66\",\"IsTcp\":true,\"DestinationPort\":389,\"ApplicationProtocol\":\"ldap.bind.simple\",\"LdapCleartextSimpleBindObserved\":true,\"Info\":\"LDAP simple bind password\"}");
        Assert.NotNull(claimed);
        Assert.False(claimed!.LdapCleartextSimpleBindObserved);
        Assert.False(RulePrecisionCatalog.HasField("capture_only_ldap_simple_bind", claimed));
        Assert.False(RulePrecisionCatalog.Validate("R286", claimed).CanEvaluate);
        var result = await new R286_LDAPSimpleBindOverCleartextExternalRule().EvaluateAsync(
            new RuleEvaluationContext(claimed, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task ValidInternalOnlyBindIsNotAnExternalBoundaryIncident()
    {
        var record = Parse(Bind(), privateSource: true);
        Assert.True(record.LdapCleartextSimpleBindObserved);
        var result = await new R286_LDAPSimpleBindOverCleartextExternalRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task RepeatedQualifiedBindPreservesExistingCooldownAndNeverAlerts()
    {
        var rule = new R286_LDAPSimpleBindOverCleartextExternalRule();
        var at = DateTime.UtcNow;
        var first = await rule.EvaluateAsync(new RuleEvaluationContext(
            Parse(Bind(), sourceOverride: "203.0.113.84"), Sensitivity.Balanced, at));
        var second = await rule.EvaluateAsync(new RuleEvaluationContext(
            Parse(Bind(), sourceOverride: "203.0.113.84"), Sensitivity.Balanced, at.AddSeconds(10)));
        Assert.True(first.Matched);
        Assert.True(second.Matched);
        Assert.All(first.Events, evt => Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus));
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);
    }
}
