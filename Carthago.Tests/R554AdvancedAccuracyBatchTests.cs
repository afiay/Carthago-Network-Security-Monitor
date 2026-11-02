// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using SharpPcap;
using Xunit;

namespace Carthago.Tests;

public sealed class R554AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 5, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Smb(string source = "10.90.1.10", string target = "10.91.1.20")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = target,
            Protocol = "TCP", IsTcp = true, IpVersion = 4,
            SourcePort = 40000, DestinationPort = 445,
            ApplicationProtocol = "smb2.write.request", Length = 157, L4Len = 117,
            Info = string.Empty
        };

    private static TrafficRecord Ftp(string source = "10.90.1.10", string target = "8.8.8.8",
        string operation = "ftp.stor")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = target,
            Protocol = "TCP", IsTcp = true, IpVersion = 4,
            SourcePort = 40001, DestinationPort = 21,
            ApplicationProtocol = operation, Length = 57, L4Len = 17,
            Info = string.Empty
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Chain(
        R554_Smb2WriteThenExternalFtpUploadRule rule, int first = 0,
        int second = 1, int ftpAt = 2)
    {
        Assert.False((await rule.EvaluateAsync(At(Smb(), first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), second))).Matched);
        return await rule.EvaluateAsync(At(Ftp(), ftpAt));
    }

    private static byte[] SmbWrite()
    {
        var payload = new byte[117];
        payload[3] = 113; // RFC1002 message length
        payload[4] = 0xfe; payload[5] = 0x53; payload[6] = 0x4d; payload[7] = 0x42;
        payload[8] = 64; payload[16] = 9; payload[68] = 49;
        payload[70] = 112; payload[72] = 1;
        return payload;
    }

    private static TrafficRecord Parsed(string source, string destination,
        byte[] payload, int sourcePort, int destinationPort)
    {
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64; frame[9] = 6;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        frame[32] = 0x50; frame[33] = 0x18;
        payload.CopyTo(frame, 40);
        var record = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
        Assert.NotNull(record);
        return record!;
    }

    [Fact]
    public void ExistingPacketHandlerClassifiesBothRequiredRequestShapes()
    {
        var smb = Parsed("10.90.1.10", "10.91.1.20", SmbWrite(), 40000, 445);
        var ftp = Parsed("10.90.1.10", "8.8.8.8",
            Encoding.ASCII.GetBytes("STOR report.bin\r\n"), 40001, 21);
        Assert.Equal("smb2.write.request", smb.ApplicationProtocol);
        Assert.Equal("ftp.stor", ftp.ApplicationProtocol);
        Assert.Equal(117, smb.L4Len);
        Assert.Equal(17, ftp.L4Len);
        Assert.True(smb.IsTcp && ftp.IsTcp);
    }

    [Fact]
    public void ExistingWireClassifierRejectsNonUploadAndInvalidRequests()
    {
        var create = SmbWrite(); create[16] = 5;
        var response = SmbWrite(); response[20] = 1;
        Assert.False(NetworkBatch246250Wire.Smb2Write(create, 40000, 445));
        Assert.False(NetworkBatch246250Wire.Smb2Write(response, 40000, 445));
        Assert.False(NetworkBatch246250Wire.FtpUpload(
            Encoding.ASCII.GetBytes("RETR report.bin\r\n"), 40001, 21, out _));
        Assert.False(NetworkBatch246250Wire.FtpUpload(
            Encoding.ASCII.GetBytes("STOR report.bin"), 40001, 21, out _));
    }

    [Fact]
    public async Task TwoRemoteSmbSubnetsThenExternalFtpProducesOneHighCandidate()
    {
        var result = await Chain(new R554_Smb2WriteThenExternalFtpUploadRule());
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R554", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(2, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Contains(evt.StructuredEvidence!.Items,
            item => item.Key == "ftp.transfer_status" && item.Value == "request_only_unverified");
    }

    [Fact]
    public async Task RealPacketHandlerRecordsCanCompleteOrderedChain()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        var a = Parsed("10.90.1.10", "10.91.1.20", SmbWrite(), 40000, 445);
        var b = Parsed("10.90.1.10", "10.92.2.20", SmbWrite(), 40000, 445);
        var ftp = Parsed("10.90.1.10", "8.8.8.8",
            Encoding.ASCII.GetBytes("APPE report.bin\r\n"), 40001, 21);
        Assert.Equal("ftp.appe", ftp.ApplicationProtocol);
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(ftp, 2))).Matched);
    }

    [Fact]
    public async Task FtpAloneOrSmbAloneCannotMatch()
    {
        var ftpOnly = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await ftpOnly.EvaluateAsync(At(Ftp()))).Matched);
        var smbOnly = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await smbOnly.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await smbOnly.EvaluateAsync(At(Smb(target: "10.92.2.20"), 1))).Matched);
    }

    [Fact]
    public async Task SameSubnetAndSameSourceSubnetAreNotTwoRemoteTargets()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.91.1.21"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.90.1.22"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 3))).Matched);
    }

    [Fact]
    public async Task FtpBeforeSecondSmbDoesNotRetroactivelyCompleteChain()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), 2))).Matched);
    }

    [Fact]
    public async Task DifferentPrivateSourcesCannotCombineEvidence()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb("10.90.1.11", "10.92.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 2))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.8")]
    [InlineData("198.51.100.8")]
    [InlineData("203.0.113.8")]
    [InlineData("10.45.1.8")]
    [InlineData("169.254.1.8")]
    public async Task NonPublicOrReservedFtpDestinationCannotCompleteChain(string destination)
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(target: destination), 2))).Matched);
    }

    [Theory]
    [InlineData("ftp.list")]
    [InlineData("ftp.retr")]
    [InlineData("FTP")]
    public async Task NonUploadFtpOperationsCannotCompleteChain(string operation)
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(operation: operation), 2))).Matched);
    }

    [Fact]
    public async Task InfoOnlyPortOnlyAndSmbCreateSpoofingFailClosed()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        var guessed = Smb(); guessed.ApplicationProtocol = null; guessed.Info = "smb2.write.request";
        var create = Smb(target: "10.92.2.20"); create.ApplicationProtocol = "smb2.create.request";
        var ftp = Ftp(); ftp.ApplicationProtocol = null; ftp.Info = "STOR password=marker";
        Assert.False((await rule.EvaluateAsync(At(guessed))).Matched);
        Assert.False((await rule.EvaluateAsync(At(create, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ftp, 2))).Matched);
    }

    [Fact]
    public async Task ContradictoryTransportAndEncryptedMetadataFailClosed()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        var udp = Smb(); udp.IsTcp = false; udp.IsUdp = true; udp.Protocol = "UDP";
        var tls = Smb(); tls.TlsVersion = "TLS1.3";
        var http = Smb(); http.HttpUri = "/upload";
        var dns = Ftp(); dns.DnsQname = "example.test";
        var quic = Ftp(); quic.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(udp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(http, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 4))).Matched);
    }

    [Fact]
    public async Task InvalidPacketIdsAndPayloadLengthBoundsFailClosed()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        var empty = Smb(); empty.Id = Guid.Empty;
        var shortSmb = Smb(); shortSmb.L4Len = 116;
        var oversizedSmb = Smb(); oversizedSmb.L4Len = 4097;
        var inconsistent = Smb(); inconsistent.Length = 120;
        var shortFtp = Ftp(); shortFtp.L4Len = 7;
        var ipv6 = Ftp(); ipv6.IpVersion = 6;
        Assert.False((await rule.EvaluateAsync(At(empty))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortSmb, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(oversizedSmb, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(inconsistent, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortFtp, 4))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ipv6, 5))).Matched);
    }

    [Fact]
    public async Task DuplicatePacketIdCannotCreateSecondSmbSubnet()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        var a = Smb();
        var b = Smb(target: "10.92.2.20"); b.Id = a.Id;
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 2))).Matched);
    }

    [Fact]
    public async Task OutOfOrderSmbObservationIsRejected()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 21))).Matched);
    }

    [Fact]
    public async Task ExactlyTwoMinuteSequenceBoundaryIsIncluded()
    {
        Assert.True((await Chain(new R554_Smb2WriteThenExternalFtpUploadRule(),
            first: 0, second: 1, ftpAt: 120)).Matched);
    }

    [Fact]
    public async Task SmbObservationOlderThanTwoMinutesDoesNotCount()
    {
        Assert.False((await Chain(new R554_Smb2WriteThenExternalFtpUploadRule(),
            first: 0, second: 1, ftpAt: 121)).Matched);
    }

    [Fact]
    public async Task ExpiredFiveMinuteObservationCannotCount()
    {
        Assert.False((await Chain(new R554_Smb2WriteThenExternalFtpUploadRule(),
            first: 0, second: 1, ftpAt: 302)).Matched);
    }

    [Fact]
    public async Task SecondFreshChainDuringCooldownIsSuppressed()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.True((await Chain(rule)).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), 11))).Matched);
        var result = await rule.EvaluateAsync(At(Ftp(), 12));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task ConsumedChainCannotBeReusedByRepeatedFtpCommands()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.True((await Chain(rule)).Matched);
        Assert.False((await rule.EvaluateAsync(At(Ftp(), 3))).Matched);
    }

    [Fact]
    public async Task ConcurrentFtpRequestsProduceAtMostOneMatch()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.False((await rule.EvaluateAsync(At(Smb()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Smb(target: "10.92.2.20"), 1))).Matched);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Ftp(), 2)).AsTask(),
            rule.EvaluateAsync(At(Ftp(), 2)).AsTask());
        Assert.Equal(1, results.Count(result => result.Matched));
    }

    [Fact]
    public async Task RawInfoAndSensitiveFileNamesAreNotRetained()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        var a = Smb(); a.Info = "password=secret-marker";
        var b = Smb(target: "10.92.2.20"); b.Info = "share=secret-marker";
        var ftp = Ftp(); ftp.Info = "STOR confidential-secret-marker.csv";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        var result = await rule.EvaluateAsync(At(ftp, 2));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal));
    }

    [Fact]
    public void UniqueRegistryEntryHasShadowCandidatePolicy()
    {
        var rule = new R554_Smb2WriteThenExternalFtpUploadRule();
        Assert.Equal("R554", rule.Descriptor.RuleId);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R554"));
    }
}
