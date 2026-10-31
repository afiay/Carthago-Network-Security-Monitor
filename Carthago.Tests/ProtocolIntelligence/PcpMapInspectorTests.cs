// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 6887 v2 MAP envelopes; not network replay or runtime evidence.
    public sealed class PcpMapInspectorTests
    {
        private static byte[] Map(bool response = false, byte opcode = 1)
        {
            var packet = new byte[60];
            packet[0] = 2;
            packet[1] = (byte)(opcode | (response ? 0x80 : 0));
            packet[4] = 0; packet[5] = 0; packet[6] = 0x0e; packet[7] = 0x10;
            packet[36] = 6; // TCP
            packet[40] = 1; packet[41] = 0xbb; // internal 443
            packet[42] = 1; packet[43] = 0xbb; // external 443
            return packet;
        }

        private static byte[] WithOption(byte[] packet, byte code, int valueLength,
            byte reserved = 0)
        {
            int padded = (valueLength + 3) & ~3;
            var output = new byte[packet.Length + 4 + padded];
            Array.Copy(packet, output, packet.Length);
            int i = packet.Length;
            output[i] = code;
            output[i + 1] = reserved;
            output[i + 2] = (byte)(valueLength >> 8);
            output[i + 3] = (byte)valueLength;
            return output;
        }

        private static bool Inspect(byte[] bytes, out PcpMapObservation result,
            bool complete = true, bool unfragmented = true,
            bool endpoint = true, bool plaintext = true)
            => PcpMapInspector.TryInspect(bytes, complete, unfragmented,
                endpoint, plaintext, out result);

        [Fact] public void ValidMapRequestExposesOnlyWireMetadata()
        {
            Assert.True(Inspect(Map(), out var found));
            Assert.False(found.IsResponseUnverified);
            Assert.Equal((uint)3600, found.LifetimeSecondsUnverified);
            Assert.Equal((byte)6, found.TransportProtocolUnverified);
            Assert.Equal((ushort)443, found.InternalPortUnverified);
            Assert.Equal(0, found.OptionCount);
        }

        [Fact] public void ValidMapResponseIsNotAnAuthenticatedOutcome()
        {
            var packet = Map(response: true);
            Assert.True(Inspect(packet, out var found));
            Assert.True(found.IsResponseUnverified);
            Assert.Equal((byte)0, found.ResultCodeUnverified);
        }

        [Fact] public void ErrorResponseResultIsRetainedAsUntrustedCode()
        {
            var packet = Map(response: true);
            packet[3] = 2;
            Assert.True(Inspect(packet, out var found));
            Assert.Equal((byte)2, found.ResultCodeUnverified);
        }

        [Fact] public void ZeroLifetimeDeletionShapeIsAccepted()
        {
            var packet = Map();
            Array.Clear(packet, 4, 4);
            Assert.True(Inspect(packet, out var found));
            Assert.Equal((uint)0, found.LifetimeSecondsUnverified);
        }

        [Fact] public void ThirdPartyOptionExposesPresenceOnly()
        {
            Assert.True(Inspect(WithOption(Map(), 1, 16), out var found));
            Assert.True(found.HasThirdPartyOptionUnverified);
        }

        [Fact] public void FilterOptionExposesPresenceOnly()
        {
            Assert.True(Inspect(WithOption(Map(), 3, 20), out var found));
            Assert.True(found.HasFilterOptionUnverified);
        }

        [Fact] public void PreferFailureOptionExposesPresenceOnly()
        {
            Assert.True(Inspect(WithOption(Map(), 2, 0), out var found));
            Assert.True(found.HasPreferFailureOptionUnverified);
        }

        [Fact] public void UnknownOptionalOptionIsSkippedWithoutDecoding()
        {
            Assert.True(Inspect(WithOption(Map(), 0x80, 3), out var found));
            Assert.Equal(1, found.OptionCount);
        }

        [Fact] public void MultipleValidOptionsAreCounted()
        {
            var packet = WithOption(WithOption(Map(), 1, 16), 3, 20);
            Assert.True(Inspect(packet, out var found));
            Assert.Equal(2, found.OptionCount);
        }

        [Fact] public void NatPmpAndOrdinaryUdpAreNotPcpMap()
        {
            var natPmp = Map(); natPmp[0] = 0;
            Assert.False(Inspect(natPmp, out _));
            Assert.False(Inspect(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1"), out _));
        }

        [Fact] public void WrongVersionAndUnsupportedOpcodeFailClosed()
        {
            var wrongVersion = Map(); wrongVersion[0] = 3;
            Assert.False(Inspect(wrongVersion, out _));
            Assert.False(Inspect(Map(opcode: 2), out _)); // PEER, not MAP
            Assert.False(Inspect(Map(opcode: 0), out _)); // ANNOUNCE
        }

        [Fact] public void TruncatedFixedHeaderAndMapBodyFailClosed()
        {
            Assert.False(Inspect(Map().Take(23).ToArray(), out _));
            Assert.False(Inspect(Map().Take(59).ToArray(), out _));
        }

        [Fact] public void OversizedDatagramFailsClosed()
        {
            Assert.False(Inspect(new byte[1104], out _));
        }

        [Fact] public void UnalignedTrailingDataFailsClosed()
        {
            Assert.False(Inspect(Map().Concat(new byte[] { 0 }).ToArray(), out _));
        }

        [Fact] public void TruncatedOptionHeaderFailsClosed()
        {
            Assert.False(Inspect(Map().Concat(new byte[] { 1, 0 }).ToArray(), out _));
        }

        [Fact] public void DeclaredOptionOverrunFailsClosed()
        {
            var packet = WithOption(Map(), 0x80, 0);
            packet[62] = 0x04; packet[63] = 0x00;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void NonzeroPaddingFailsClosed()
        {
            var packet = WithOption(Map(), 0x80, 1);
            packet[65] = 0xff;
            Assert.False(Inspect(packet, out _));
        }

        [Fact] public void KnownOptionInvalidLengthFailsClosed()
        {
            Assert.False(Inspect(WithOption(Map(), 1, 12), out _));
            Assert.False(Inspect(WithOption(Map(), 2, 4), out _));
            Assert.False(Inspect(WithOption(Map(), 3, 16), out _));
        }

        [Fact] public void UnknownMandatoryOptionFailsClosed()
        {
            Assert.False(Inspect(WithOption(Map(), 4, 0), out _));
        }

        [Fact] public void DuplicateSingletonOptionFailsClosed()
        {
            Assert.False(Inspect(WithOption(WithOption(Map(), 1, 16), 1, 16), out _));
            Assert.False(Inspect(WithOption(WithOption(Map(), 2, 0), 2, 0), out _));
        }

        [Fact] public void OptionCountIsBounded()
        {
            var packet = Map();
            for (int i = 0; i < 32; i++) packet = WithOption(packet, 0x80, 0);
            Assert.True(Inspect(packet, out var found));
            Assert.Equal(32, found.OptionCount);
            Assert.False(Inspect(WithOption(packet, 0x80, 0), out _));
        }

        [Fact] public void MaximumRfcDatagramSizeIsAcceptedForOpaqueOptionalData()
        {
            Assert.True(Inspect(WithOption(Map(), 0x80, 1036), out var found));
            Assert.Equal(1, found.OptionCount);
        }

        [Fact] public void AllSourceAttestationsAreMandatory()
        {
            var packet = Map();
            Assert.False(Inspect(packet, out _, complete: false));
            Assert.False(Inspect(packet, out _, unfragmented: false));
            Assert.False(Inspect(packet, out _, endpoint: false));
            Assert.False(Inspect(packet, out _, plaintext: false));
        }

        [Fact] public void InvalidInputResetsOutputToDefault()
        {
            Assert.False(Inspect(new byte[60], out var found));
            Assert.Equal(default(PcpMapObservation), found);
        }

        [Fact] public void ReservedBitsAreIgnoredOnReceptionPerRfc()
        {
            var packet = Map(); packet[2] = 0xff; packet[3] = 0xff;
            packet[37] = 0xff; packet[38] = 0xff; packet[39] = 0xff;
            Assert.True(Inspect(packet, out _));
            var response = Map(response: true); response[2] = 0xff;
            Assert.True(Inspect(response, out _));
        }

        [Fact] public void DuplicateAndOutOfOrderPacketsAreStateless()
        {
            var request = Map(); var response = Map(response: true);
            Assert.True(Inspect(response, out var first));
            Assert.True(Inspect(request, out _));
            Assert.True(Inspect(response, out var second));
            Assert.Equal(first, second);
        }

        [Fact] public async Task ConcurrentInspectionsAreDeterministic()
        {
            var packet = WithOption(Map(), 3, 20);
            var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
                Task.Run(() =>
                {
                    Assert.True(Inspect(packet, out var found));
                    return found;
                })));
            Assert.All(results, item => Assert.Equal(results[0], item));
        }

        [Fact] public void SensitiveNonceAndIpAddressBytesAreNeverReturned()
        {
            var a = Map(); var b = Map();
            for (int i = 8; i < 36; i++) { a[i] = 0x13; b[i] = 0x72; }
            for (int i = 44; i < 60; i++) { a[i] = 0x11; b[i] = 0x99; }
            Assert.True(Inspect(a, out var first));
            Assert.True(Inspect(b, out var second));
            Assert.Equal(first, second);
        }
    }
}
