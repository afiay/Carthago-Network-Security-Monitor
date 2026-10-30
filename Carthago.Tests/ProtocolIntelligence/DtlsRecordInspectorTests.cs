// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class DtlsRecordInspectorTests
    {
        private static byte[] Record(byte type, ushort epoch, byte[] body, ushort version = 0xFEFD, ulong sequence = 1)
        {
            var bytes = new byte[13 + body.Length];
            bytes[0] = type;
            bytes[1] = (byte)(version >> 8);
            bytes[2] = (byte)version;
            bytes[3] = (byte)(epoch >> 8);
            bytes[4] = (byte)epoch;
            for (int i = 0; i < 6; i++)
                bytes[5 + i] = (byte)(sequence >> (40 - 8 * i));
            bytes[11] = (byte)(body.Length >> 8);
            bytes[12] = (byte)body.Length;
            body.CopyTo(bytes, 13);
            return bytes;
        }

        [Fact]
        public void ValidDtls12ClientHelloFragmentExposesOnlyHeaderMetadata()
        {
            var handshake = new byte[12];
            handshake[0] = 1; // ClientHello, empty first fragment for shape testing only.
            Assert.True(DtlsRecordInspector.TryInspect(Record(22, 0, handshake), out var observation));
            Assert.Equal((ushort)0xFEFD, observation.FirstVersion);
            Assert.Equal((byte?)1, observation.FirstHandshakeType);
            Assert.False(observation.ContainsOpaqueContent);
        }

        [Fact]
        public void BenignDnsDatagramIsNotDtls()
        {
            Assert.False(DtlsRecordInspector.TryInspect(new byte[] { 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119 }, out _));
        }

        [Fact]
        public void TruncatedRecordFailsClosed()
        {
            var bytes = Record(23, 1, new byte[] { 0x42, 0x43 });
            Assert.False(DtlsRecordInspector.TryInspect(bytes.AsSpan(0, bytes.Length - 1), out _));
        }

        [Fact]
        public void ForgedRecordLengthFailsClosed()
        {
            var bytes = Record(23, 1, new byte[] { 0x42 });
            bytes[12] = 100;
            Assert.False(DtlsRecordInspector.TryInspect(bytes, out _));
        }

        [Fact]
        public void EncryptedEpochIsMetadataOnlyAndDoesNotExposeHandshakeType()
        {
            Assert.True(DtlsRecordInspector.TryInspect(Record(22, 1, new byte[] { 0x01, 0x02 }), out var observation));
            Assert.Null(observation.FirstHandshakeType);
            Assert.True(observation.ContainsOpaqueContent);
        }

        [Fact]
        public void CoalescedRecordsAreBoundedAndCountedWithoutReplayClaim()
        {
            var bytes = Record(23, 1, new byte[] { 0x01 }, sequence: 7)
                .Concat(Record(23, 1, new byte[] { 0x02 }, sequence: 7)).ToArray();
            Assert.True(DtlsRecordInspector.TryInspect(bytes, out var observation));
            Assert.Equal(2, observation.RecordCount);
            Assert.Equal((ulong)7, observation.FirstSequenceNumber);
        }

        [Fact]
        public void ExcessiveRecordCountFailsClosed()
        {
            var single = Record(23, 1, new byte[] { 0x01 });
            var bytes = new byte[single.Length * 17];
            for (int i = 0; i < 17; i++)
                Array.Copy(single, 0, bytes, i * single.Length, single.Length);
            Assert.False(DtlsRecordInspector.TryInspect(bytes, out _));
        }

        [Fact]
        public void SpoofedHandshakeFragmentOffsetFailsClosed()
        {
            var handshake = new byte[12];
            handshake[0] = 1;
            handshake[8] = 1; // offset=1 but declared message length=0
            Assert.False(DtlsRecordInspector.TryInspect(Record(22, 0, handshake), out _));
        }

        [Theory]
        [InlineData(0x0303)]
        [InlineData(0xFEFC)]
        public void NonSupportedWireVersionIsNotMisclassifiedAsDtls12(ushort version)
        {
            Assert.False(DtlsRecordInspector.TryInspect(Record(23, 1, new byte[] { 0x01 }, version), out _));
        }
    }
}
