// SPDX-License-Identifier: MIT
using System.Net;
using System.Net.NetworkInformation;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class GatewayIntegritySensorTests
{
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Gateway = IPAddress.Parse("192.168.1.1");
    private static readonly PhysicalAddress Own = PhysicalAddress.Parse("02-00-00-00-00-20");
    private const string A = "02:00:00:00:00:01";
    private const string B = "02:00:00:00:00:02";

    private static byte[] Reply(string claim = A)
    {
        var frame = NpcapArpDiscovery.BuildRequest(Own, Local, Gateway);
        var mac = PhysicalAddress.Parse(claim.Replace(":", "-")).GetAddressBytes();
        Own.GetAddressBytes().CopyTo(frame, 0);
        mac.CopyTo(frame, 6);
        frame[21] = 2;
        mac.CopyTo(frame, 22);
        Gateway.GetAddressBytes().CopyTo(frame, 28);
        Own.GetAddressBytes().CopyTo(frame, 32);
        Local.GetAddressBytes().CopyTo(frame, 38);
        return frame;
    }

    [Fact]
    public void DirectedReplyMatchesGateway()
    {
        Assert.True(GatewayIntegritySensor.TryMatchReply(Reply(), Local, Gateway, Own, out var mac));
        Assert.Equal(A, mac);
    }

    [Fact]
    public void TaggedReplyMatchesGateway()
    {
        var frame = Reply();
        var tagged = new byte[frame.Length + 4];
        frame.AsSpan(0, 12).CopyTo(tagged);
        new byte[] { 0x81, 0, 0, 7, 8, 6 }.CopyTo(tagged, 12);
        frame.AsSpan(14).CopyTo(tagged.AsSpan(18));
        Assert.True(GatewayIntegritySensor.TryMatchReply(tagged, Local, Gateway, Own, out var mac));
        Assert.Equal(A, mac);
    }

    [Theory]
    [InlineData("wrong-ip")]
    [InlineData("wrong-target-ip")]
    [InlineData("wrong-destination")]
    [InlineData("wrong-arp-target-mac")]
    [InlineData("source-mismatch")]
    [InlineData("request")]
    [InlineData("truncated")]
    [InlineData("multicast")]
    [InlineData("own-mac")]
    public void InvalidOrUnrelatedReplyRejected(string change)
    {
        var frame = Reply();
        switch (change)
        {
            case "wrong-ip": frame[31] = 9; break;
            case "wrong-target-ip": frame[41] = 9; break;
            case "wrong-destination": frame[5] = 9; break;
            case "wrong-arp-target-mac": frame[37] = 9; break;
            case "source-mismatch": frame[11] = 9; break;
            case "request": frame[21] = 1; break;
            case "truncated": Array.Resize(ref frame, 41); break;
            case "multicast": frame[6] = frame[22] = 1; break;
            case "own-mac": Own.GetAddressBytes().CopyTo(frame, 6); Own.GetAddressBytes().CopyTo(frame, 22); break;
        }
        Assert.False(GatewayIntegritySensor.TryMatchReply(frame, Local, Gateway, Own, out var mac));
        Assert.Null(mac);
    }

    [Theory]
    [InlineData(null, null, GatewayIntegrityStatus.NoReply, false)]
    [InlineData(null, A, GatewayIntegrityStatus.NoReply, false)]
    [InlineData(A, null, GatewayIntegrityStatus.Observed, false)]
    [InlineData(A, A, GatewayIntegrityStatus.BaselineMatch, false)]
    [InlineData(B, A, GatewayIntegrityStatus.BaselineDifference, true)]
    public void CacheAloneNeverConfirmsAndBaselineIsExplicit(string? direct, string? expected,
        GatewayIntegrityStatus status, bool cacheDiffers)
    {
        var result = GatewayIntegritySensor.Evaluate(Local, Gateway,
            direct is null ? Array.Empty<string>() : new[] { direct }, A, expected);
        Assert.Equal(status, result.Status);
        Assert.Equal(cacheDiffers, result.CacheDiffers);
    }

    [Fact]
    public void ConflictingClaimsTakePrecedenceOverBaselineMatch()
    {
        var result = GatewayIntegritySensor.Evaluate(Local, Gateway, new[] { A, B, A }, A, A);
        Assert.Equal(GatewayIntegrityStatus.ConflictingClaims, result.Status);
        Assert.Equal(new[] { A, B }, result.DirectMacs.ToArray());
        Assert.True(result.CacheDiffers);
    }

    [Fact]
    public void DuplicateClaimsDoNotCreateConflict()
    {
        var result = GatewayIntegritySensor.Evaluate(Local, Gateway, new[] { A, "02-00-00-00-00-01" }, A, A);
        Assert.Equal(GatewayIntegrityStatus.BaselineMatch, result.Status);
        Assert.Single(result.DirectMacs);
    }

    [Theory]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("01:00:00:00:00:01")]
    [InlineData("FF:FF:FF:FF:FF:FF")]
    [InlineData("invalid")]
    public void InvalidMacRejected(string value) => Assert.Null(GatewayIntegritySensor.NormalizeMac(value));

    [Fact]
    public void ClaimOverflowRemainsConflicting()
    {
        var result = GatewayIntegritySensor.Evaluate(Local, Gateway,
            Enumerable.Range(1, 20).Select(i => $"02:00:00:00:00:{i:X2}"), A, A, true);
        Assert.Equal(GatewayIntegrityStatus.ConflictingClaims, result.Status);
        Assert.Equal(GatewayIntegritySensor.MaxClaims, result.DirectMacs.Count);
        Assert.True(result.ClaimLimitReached);
    }
}
