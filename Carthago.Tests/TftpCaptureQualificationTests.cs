// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;
public sealed class TftpCaptureQualificationTests
{
    private const string Client = "10.1.1.10", Server = "10.1.2.45";
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    internal static byte[] Request(byte opcode = 1)
    {
        byte[] text = Encoding.ASCII.GetBytes("private-router-config.cfg\0octet\0");
        var result = new byte[text.Length + 2]; result[1] = opcode; text.CopyTo(result, 2);
        return result;
    }
    internal static TrafficRecord Parse(PacketHandler handler, string src, string dst, int sport, int dport,
        byte[] payload, bool inconsistentLength = false)
    {
        var raw = new byte[28 + payload.Length];
        raw[0] = 0x45; raw[8] = 64; raw[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2, 2), (ushort)raw.Length);
        IPAddress.Parse(src).GetAddressBytes().CopyTo(raw, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(raw, 16);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(20, 2), (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(22, 2), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(24, 2), (ushort)(8 + payload.Length - (inconsistentLength ? 1 : 0)));
        payload.CopyTo(raw, 28);
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(raw, (LinkLayers)12));
    }
    internal static TrafficRecord[] PrivatePair(byte opcode = 1)
    {
        var h = new PacketHandler();
        var request = Parse(h, Client, Server, 51000, 69, Request(opcode));
        var response = Parse(h, Server, Client, 52000, 51000,
            opcode == 1 ? new byte[] { 0, 3, 0, 1, 42 } : new byte[] { 0, 4, 0, 0 });
        return new[] { request, response };
    }
    internal static TrafficRecord Initial(string src, string dst, byte opcode = 1)
        => Parse(new PacketHandler(), src, dst, 51000, 69, Request(opcode));
    private static RuleEvaluationContext At(TrafficRecord r, int seconds) => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    [Theory]
    [InlineData((byte)1, (byte)3)]
    [InlineData((byte)2, (byte)4)]
    public async Task CaptureToRuleRecognizesMatchingInitialProtocolExchange(byte requestOpcode, byte replyOpcode)
    {
        var pair = PrivatePair(requestOpcode);
        Assert.Equal(requestOpcode, pair[0].TftpInitialRequestOpcode);
        Assert.Equal(replyOpcode, pair[1].TftpInitialReplyOpcode);
        Assert.Equal(pair[0].Id, pair[1].TftpRequestCorrelationId);
        var rule = new R946_PrivateTftpRequestThenEphemeralReplyRule();
        Assert.False((await rule.EvaluateAsync(At(pair[0], 0))).Matched);
        var result = await rule.EvaluateAsync(At(pair[1], 2));
        Assert.True(result.Matched);
        Assert.DoesNotContain("private-router-config", JsonSerializer.Serialize(result.Events));
        Assert.DoesNotContain("private-router-config", JsonSerializer.Serialize(pair));
    }
    [Fact]
    public async Task ArbitraryPort69AndEphemeralUdpCannotTrigger()
    {
        var h = new PacketHandler(); var rule = new R946_PrivateTftpRequestThenEphemeralReplyRule();
        var request = Parse(h, Client, Server, 51000, 69, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        var response = Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 3, 0, 1, 42 });
        Assert.Null(request.TftpInitialRequestOpcode); Assert.Null(response.TftpInitialReplyOpcode);
        Assert.False((await rule.EvaluateAsync(At(request, 0))).Matched);
        Assert.False((await rule.EvaluateAsync(At(response, 2))).Matched);
    }
    [Fact]
    public void WrongBlockOpcodePeerAndClientPortDoNotConsumePendingRequest()
    {
        var h = new PacketHandler(); var request = Parse(h, Client, Server, 51000, 69, Request());
        foreach (var r in new[] {
            Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 4, 0, 0 }),
            Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 3, 0, 2, 42 }),
            Parse(h, "10.1.2.46", Client, 52000, 51000, new byte[] { 0, 3, 0, 1, 42 }),
            Parse(h, Server, Client, 52000, 51001, new byte[] { 0, 3, 0, 1, 42 }),
            Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 5, 0, 1, 0 }),
            Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 6, 1, 0 }) })
            Assert.Null(r.TftpInitialReplyOpcode);
        var good = Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 3, 0, 1, 42 });
        Assert.Equal(request.Id, good.TftpRequestCorrelationId);
        Assert.Null(Parse(h, Server, Client, 52000, 51000, new byte[] { 0, 3, 0, 1, 42 }).TftpInitialReplyOpcode);
    }
    [Fact]
    public void TruncatedOrInconsistentDatagramsAndDifferentCaptureInstancesFailClosed()
    {
        var h = new PacketHandler();
        var request = Parse(h, Client, Server, 51000, 69, Request(), inconsistentLength: true);
        Assert.Null(request.TftpInitialRequestOpcode);
        request = Parse(h, Client, Server, 51000, 69, Request());
        Assert.NotNull(request.TftpInitialRequestOpcode);
        Assert.Null(Parse(new PacketHandler(), Server, Client, 52000, 51000, new byte[] { 0, 3, 0, 1, 42 }).TftpInitialReplyOpcode);
    }
    [Fact]
    public async Task CorrelationMustReferenceTheExactCapturedRequest()
    {
        var pair = PrivatePair(); var other = PrivatePair();
        var rule = new R946_PrivateTftpRequestThenEphemeralReplyRule();
        await rule.EvaluateAsync(At(pair[0], 0));
        Assert.False((await rule.EvaluateAsync(At(other[1], 2))).Matched);
        Assert.True((await rule.EvaluateAsync(At(pair[1], 3))).Matched);
    }
    [Fact]
    public void ProducerExpiresAndRejectsOutOfOrderResponses()
    {
        var tracker = new TftpHandshakeTracker();
        TrafficRecord R(string src, string dst, int sp, int dp) => new()
            { Source=src, Destination=dst, SourcePort=sp, DestinationPort=dp, IsUdp=true, IpVersion=4 };
        var request = R(Client, Server, 51000, 69);
        tracker.Observe(request, Request(), true, Epoch);
        var earlier = R(Server, Client, 52000, 51000);
        tracker.Observe(earlier, new byte[] { 0, 3, 0, 1 }, true, Epoch.AddSeconds(-1));
        Assert.Null(earlier.TftpInitialReplyOpcode);
        var expired = R(Server, Client, 52000, 51000);
        tracker.Observe(expired, new byte[] { 0, 3, 0, 1 }, true, Epoch.AddSeconds(46));
        Assert.Null(expired.TftpInitialReplyOpcode);
    }
    [Fact]
    public async Task SshAndFtpStagesRequireActualTftpRequestNotPortOrText()
    {
        var ssh = new TrafficRecord { Source=Client, Destination=Server, SourcePort=51000, DestinationPort=22,
            IsTcp=true, IpVersion=4, Protocol="TCP", TcpFlags=0x02, Length=40, L4Len=0 };
        var ftp = new TrafficRecord { Source=Client, Destination=Server, SourcePort=51000, DestinationPort=21,
            IsTcp=true, IpVersion=4, Protocol="TCP", TcpFlags=0x18, Length=60, L4Len=20, ApplicationProtocol="ftp.stor" };
        var r947 = new R947_PrivateSshIngressThenPublicTftpRule();
        var r949 = new R949_PrivateFtpStorThenTftpDataRule();
        await r947.EvaluateAsync(At(ssh,0)); await r949.EvaluateAsync(At(ftp,0));
        var badPublic = Parse(new PacketHandler(), Server, "8.8.8.8", 51000, 69, new byte[] { 0, 1, 2, 3 });
        var badPrivate = Parse(new PacketHandler(), Client, Server, 51000, 69, new byte[] { 0, 1, 2, 3 });
        badPublic.Info = "TFTP RRQ"; badPrivate.Info = "TFTP WRQ";
        Assert.False((await r947.EvaluateAsync(At(badPublic,1))).Matched);
        Assert.False((await r949.EvaluateAsync(At(badPrivate,1))).Matched);
        Assert.True((await r947.EvaluateAsync(At(Initial(Server,"8.8.8.8"),2))).Matched);
        Assert.True((await r949.EvaluateAsync(At(Initial(Client,Server,2),2))).Matched);
    }
}
