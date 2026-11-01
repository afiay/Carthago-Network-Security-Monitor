// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    internal static class OscoreFixture
    {
        // Synthetic RFC 7252 UDP outer CoAP; OSCORE option number 9.
        internal static byte[] Packet(byte[] option, bool payload = true, byte code = 0x02)
        {
            var bytes = new List<byte> { 0x40, code, 0x12, 0x34 };
            if (option.Length <= 12)
            {
                bytes.Add((byte)(0x90 | option.Length));
            }
            else
            {
                bytes.Add(0x9d);
                bytes.Add((byte)(option.Length - 13));
            }
            bytes.AddRange(option);
            if (payload)
            {
                bytes.Add(0xff);
                bytes.Add(0xca);
            }
            return bytes.ToArray();
        }

        internal static bool Inspect(byte[] bytes, out OscoreOuterObservation observation)
            => OscoreOuterOptionInspector.TryInspect(
                bytes, true, true, true, true, true, out observation);
    }

    public sealed class OscorePositiveCases
    {
        [Fact]
        public void RequestWithPartialIvAndKidHasOnlyLengthMetadata()
        {
            Assert.True(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x09, 0x05, 0x25 }), out var result));
            Assert.Equal(1, result.PartialIvByteCount);
            Assert.True(result.HasKid);
            Assert.False(result.HasKidContext);
            Assert.Equal(1, result.OpaquePayloadByteCount);
        }

        [Fact]
        public void EmptyOptionResponseIsLegal()
        {
            Assert.True(OscoreFixture.Inspect(OscoreFixture.Packet(Array.Empty<byte>(), code: 0x44), out var result));
            Assert.Equal(0, result.PartialIvByteCount);
            Assert.False(result.HasKid);
        }

        [Fact]
        public void KidContextAndKidAreShapeOnly()
        {
            Assert.True(OscoreFixture.Inspect(OscoreFixture.Packet(
                new byte[] { 0x19, 0x05, 0x02, 0x41, 0x42, 0x25 }), out var result));
            Assert.True(result.HasKidContext);
            Assert.True(result.HasKid);
        }

        [Fact]
        public void EmptyKidWithFlagIsLegal()
        {
            Assert.True(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x09, 0x00 }), out _));
        }

        [Theory]
        [InlineData((byte)0x02)]
        [InlineData((byte)0x44)]
        public void OuterCodeIsMetadataNotDecryptedMethod(byte code)
        {
            Assert.True(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x01, 0x05 }, code: code), out var result));
            Assert.Equal(code, result.OuterCode);
        }
    }

    public sealed class OscoreCrossProtocolCases
    {
        [Fact]
        public void OrdinaryCoapWithoutOscoreDoesNotClassify()
        {
            Assert.False(OscoreFixture.Inspect(new byte[] { 0x40, 0x01, 0x12, 0x34, 0xff, 0x41, 0x42 }, out _));
        }

        [Fact]
        public void WrongCoapVersionDoesNotClassify()
        {
            var packet = OscoreFixture.Packet(new byte[] { 0x01, 0x05 });
            packet[0] = 0x80;
            Assert.False(OscoreFixture.Inspect(packet, out _));
        }

        [Fact]
        public void ExcessiveTokenLengthDoesNotClassify()
        {
            var packet = OscoreFixture.Packet(new byte[] { 0x01, 0x05 });
            packet[0] = 0x49;
            Assert.False(OscoreFixture.Inspect(packet, out _));
        }

        [Fact]
        public void EmptyCoapCodeWithOptionsDoesNotClassify()
        {
            var packet = OscoreFixture.Packet(new byte[] { 0x01, 0x05 });
            packet[1] = 0;
            Assert.False(OscoreFixture.Inspect(packet, out _));
        }

        [Fact]
        public void NonOscoreOptionDoesNotClassify()
        {
            Assert.False(OscoreFixture.Inspect(new byte[] { 0x40, 0x02, 0, 1, 0x11, 0x05, 0xff, 0xca }, out _));
        }
    }

    public sealed class OscoreMalformedCases
    {
        [Fact]
        public void TruncatedOptionValueFailsClosed()
        {
            Assert.False(OscoreFixture.Inspect(new byte[] { 0x40, 0x02, 0, 1, 0x93, 0x09, 0x05 }, out _));
        }

        [Fact]
        public void ReservedFlagBitsFailClosed()
        {
            Assert.False(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x20 }), out _));
        }

        [Theory]
        [InlineData((byte)0x06)]
        [InlineData((byte)0x07)]
        public void ReservedPartialIvLengthsFailClosed(byte flags)
        {
            Assert.False(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { flags }), out _));
        }

        [Fact]
        public void MissingPayloadFailsClosed()
        {
            Assert.False(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x01, 0x05 }, payload: false), out _));
        }

        [Fact]
        public void DuplicateOscoreOptionFailsClosed()
        {
            Assert.False(OscoreFixture.Inspect(new byte[] {
                0x40, 0x02, 0, 1, 0x92, 0x01, 0x05, 0x02, 0x01, 0x05, 0xff, 0xca }, out _));
        }

        [Fact]
        public void TruncatedExtendedDeltaFailsClosed()
        {
            Assert.False(OscoreFixture.Inspect(new byte[] { 0x40, 0x02, 0, 1, 0xd0 }, out _));
        }

        [Fact]
        public void UnexpectedTrailingBytesWithoutKidFailClosed()
        {
            Assert.False(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x01, 0x05, 0x99 }), out _));
        }

        [Fact]
        public void EmptyPayloadMarkerFailsClosed()
        {
            Assert.False(OscoreFixture.Inspect(new byte[] { 0x40, 0x02, 0, 1, 0x92, 0x01, 0x05, 0xff }, out _));
        }
    }

    public sealed class OscoreStateBoundsCases
    {
        [Fact]
        public void OversizedDatagramFailsClosed()
        {
            var bytes = new byte[1153];
            Array.Copy(OscoreFixture.Packet(new byte[] { 0x01, 0x05 }), bytes, 9);
            Assert.False(OscoreFixture.Inspect(bytes, out _));
        }

        [Fact]
        public void ExcessiveOptionsFailClosed()
        {
            var bytes = new List<byte> { 0x40, 0x02, 0, 1, 0x92, 0x01, 0x05 };
            for (int i = 0; i < 65; i++) bytes.Add(0x00);
            bytes.Add(0xff);
            bytes.Add(0xca);
            Assert.False(OscoreFixture.Inspect(bytes.ToArray(), out _));
        }

        [Fact]
        public void StatelessConcurrentCallsReturnIdenticalMetadata()
        {
            var packet = OscoreFixture.Packet(new byte[] { 0x09, 0x05, 0x25 });
            Parallel.For(0, 64, _ =>
            {
                Assert.True(OscoreFixture.Inspect(packet, out var result));
                Assert.Equal(1, result.PartialIvByteCount);
                Assert.True(result.HasKid);
            });
        }
    }

    public sealed class OscorePrivacyProvenanceCases
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        public void EveryProducerAttestationIsRequired(int missing)
        {
            var flags = new[] { true, true, true, true, true };
            flags[missing] = false;
            Assert.False(OscoreOuterOptionInspector.TryInspect(
                OscoreFixture.Packet(new byte[] { 0x09, 0x05, 0x25 }),
                flags[0], flags[1], flags[2], flags[3], flags[4], out var result));
            Assert.Equal(default(OscoreOuterObservation), result);
        }

        [Fact]
        public void KidAndPartialIvValuesAreNotReturned()
        {
            Assert.True(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x09, 0xde, 0xad }), out var result));
            Assert.Equal(1, result.PartialIvByteCount);
            Assert.True(result.HasKid);
            Assert.DoesNotContain("dead", result.ToString().ToLowerInvariant());
        }

        [Fact]
        public void EncryptedPayloadIsNotInterpreted()
        {
            var packet = OscoreFixture.Packet(new byte[] { 0x01, 0x05 });
            packet[^1] = 0x00;
            Assert.True(OscoreFixture.Inspect(packet, out var result));
            Assert.Equal(1, result.OpaquePayloadByteCount);
        }

        [Fact]
        public void InvalidContextLengthNeverLeaksAnObservation()
        {
            Assert.False(OscoreFixture.Inspect(OscoreFixture.Packet(new byte[] { 0x10, 0x04, 0x11 }), out var result));
            Assert.Equal(default(OscoreOuterObservation), result);
        }
    }
}
