// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Hand-authored connection-oriented DCE/RPC v5 PDU fixtures; not a network replay.
    public sealed class DceRpcPduInspectorTests
    {
        private static byte[] Pdu(byte type, byte[] body, bool little = true,
            ushort authLength = 0, byte flags = 3, uint callId = 7)
        {
            var bytes = new byte[16 + body.Length];
            bytes[0] = 5;
            bytes[1] = 0;
            bytes[2] = type;
            bytes[3] = flags;
            bytes[4] = little ? (byte)0x10 : (byte)0x00;
            if (little)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, 2), (ushort)bytes.Length);
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(10, 2), authLength);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), callId);
            }
            else
            {
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8, 2), (ushort)bytes.Length);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10, 2), authLength);
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(12, 4), callId);
            }
            body.CopyTo(bytes, 16);
            return bytes;
        }

        [Fact]
        public void VerifiedRequestHeaderExposesOnlyPduShape()
        {
            var bytes = Pdu(0, new byte[8], callId: 42);
            Assert.True(DceRpcPduInspector.TryInspect(bytes, true, out var found));
            Assert.Equal((byte)0, found.PduType);
            Assert.Equal((uint)42, found.CallId);
            Assert.Equal(bytes.Length, found.BytesConsumed);
            Assert.False(found.HasAuthVerifier);
        }

        [Fact]
        public void BindHeaderWithMinimumFixedFieldsIsRecognized()
        {
            Assert.True(DceRpcPduInspector.TryInspect(Pdu(11, new byte[12]), true, out var found));
            Assert.Equal((byte)11, found.PduType);
        }

        [Fact]
        public void BigEndianResponseIsDecodedWithoutHostEndianAssumptions()
        {
            Assert.True(DceRpcPduInspector.TryInspect(
                Pdu(2, new byte[8], little: false, callId: 0x01020304), true, out var found));
            Assert.False(found.LittleEndian);
            Assert.Equal(0x01020304u, found.CallId);
        }

        [Fact]
        public void OrdinaryHttpTrafficCannotBeClassifiedAsDceRpc()
        {
            Assert.False(DceRpcPduInspector.TryInspect(
                Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\n\r\n"), true, out _));
        }

        [Fact]
        public void TruncatedFragmentFailsClosed()
        {
            var bytes = Pdu(0, new byte[8]);
            Assert.False(DceRpcPduInspector.TryInspect(bytes.AsSpan(0, bytes.Length - 1), true, out _));
        }

        [Fact]
        public void ForgedOversizedFragmentLengthFailsClosed()
        {
            var bytes = Pdu(0, new byte[8]);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, 2), 16_385);
            Assert.False(DceRpcPduInspector.TryInspect(bytes, true, out _));
        }

        [Fact]
        public void UnsupportedDatagramVersionAndRepresentationFailClosed()
        {
            var bytes = Pdu(0, new byte[8]);
            bytes[0] = 4;
            Assert.False(DceRpcPduInspector.TryInspect(bytes, true, out _));
            bytes[0] = 5;
            bytes[4] = 0xFF;
            Assert.False(DceRpcPduInspector.TryInspect(bytes, true, out _));
        }

        [Theory]
        [InlineData(20)]
        [InlineData(255)]
        public void UnsupportedPduTypesCannotClaimConnectionOrientedRpc(byte type)
        {
            Assert.False(DceRpcPduInspector.TryInspect(Pdu(type, new byte[12]), true, out _));
        }

        [Fact]
        public void AuthVerifierIsPresenceOnlyAndNeverDecoded()
        {
            var body = new byte[8 + 8 + 4]; // request body + sec_trailer + opaque verifier
            var bytes = Pdu(0, body, authLength: 4);
            Assert.True(DceRpcPduInspector.TryInspect(bytes, true, out var found));
            Assert.True(found.HasAuthVerifier);
            Assert.Equal((ushort)4, found.AuthVerifierLength);
        }

        [Fact]
        public void ForgedAuthLengthAndPaddingCannotUnderflowBody()
        {
            var bytes = Pdu(0, new byte[8], authLength: 32);
            Assert.False(DceRpcPduInspector.TryInspect(bytes, true, out _));
            var padded = Pdu(0, new byte[8 + 8 + 4], authLength: 4);
            padded[16 + 8 + 2] = 1; // no spare bytes beyond fixed request header
            Assert.False(DceRpcPduInspector.TryInspect(padded, true, out _));
        }

        [Fact]
        public void FragmentFlagsAndCoalescedNextPduDoNotImplyCompletedCall()
        {
            var first = Pdu(0, new byte[8], flags: 1);
            var bytes = first.Concat(Pdu(2, new byte[8], flags: 2)).ToArray();
            Assert.True(DceRpcPduInspector.TryInspect(bytes, true, out var found));
            Assert.Equal((byte)1, found.FragmentFlags);
            Assert.Equal(first.Length, found.BytesConsumed);
        }

        [Fact]
        public void NoTrustedPduBoundaryMeansNoClassification()
        {
            Assert.False(DceRpcPduInspector.TryInspect(Pdu(0, new byte[8]), false, out _));
        }
    }
}
