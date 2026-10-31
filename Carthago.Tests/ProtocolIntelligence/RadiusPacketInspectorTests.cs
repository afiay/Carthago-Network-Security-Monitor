// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 2865/2866 UDP envelopes. Authenticator bytes are fake.
    public sealed class RadiusPacketInspectorTests
    {
        private static byte[] Packet(byte code = 1, params byte[][] attributes)
        {
            int size = 20;
            foreach (var attribute in attributes)
                size += attribute.Length;
            var bytes = new byte[size];
            bytes[0] = code; bytes[1] = 19;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)size);
            bytes[4] = 0xfa; bytes[19] = 0xfb; // never exposed
            int offset = 20;
            foreach (var attribute in attributes)
            {
                attribute.CopyTo(bytes, offset);
                offset += attribute.Length;
            }
            return bytes;
        }

        private static byte[] Attribute(byte type, int valueLength)
        {
            var result = new byte[2 + valueLength];
            result[0] = type; result[1] = (byte)result.Length;
            return result;
        }

        [Theory]
        [InlineData((byte)1, (ushort)1812)]
        [InlineData((byte)2, (ushort)1812)]
        [InlineData((byte)3, (ushort)1812)]
        [InlineData((byte)11, (ushort)1812)]
        [InlineData((byte)4, (ushort)1813)]
        [InlineData((byte)5, (ushort)1813)]
        public void SupportedCodesHaveCorrectServicePort(byte code, ushort port)
        {
            Assert.True(RadiusPacketInspector.TryInspect(Packet(code), 54000, port, true, out var found));
            Assert.Equal(code, found.Code);
        }

        [Fact] public void ReplyDirectionIsAccepted()
            => Assert.True(RadiusPacketInspector.TryInspect(Packet(2), 1812, 54000, true, out _));

        [Fact] public void AttributesAreCountedWithoutValues()
        {
            var data = Packet(1, Attribute(1, 4), Attribute(6, 4));
            Assert.True(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out var found));
            Assert.Equal(2, found.AttributeCount);
        }

        [Fact] public void MessageAuthenticatorPresenceIsNotAuthentication()
        {
            var data = Packet(1, Attribute(80, 16));
            Assert.True(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out var found));
            Assert.True(found.HasMessageAuthenticatorAttribute);
        }

        [Fact] public void WrongServicePortFails()
            => Assert.False(RadiusPacketInspector.TryInspect(Packet(), 54000, 1813, true, out _));

        [Fact] public void UnknownCodeFails()
            => Assert.False(RadiusPacketInspector.TryInspect(Packet(255), 54000, 1812, true, out _));

        [Fact] public void UnattestedBoundaryFails()
            => Assert.False(RadiusPacketInspector.TryInspect(Packet(), 54000, 1812, false, out _));

        [Fact] public void TruncatedHeaderFails()
            => Assert.False(RadiusPacketInspector.TryInspect(new byte[19], 54000, 1812, true, out _));

        [Fact] public void OversizedDatagramFails()
            => Assert.False(RadiusPacketInspector.TryInspect(new byte[4097], 54000, 1812, true, out _));

        [Fact] public void DeclaredLengthLargerThanCapturedFails()
        {
            var data = Packet(); data[3] = 21;
            Assert.False(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out _));
        }

        [Fact] public void UdpPaddingIsNotAcceptedInStrictProfile()
        {
            var data = Packet(); Array.Resize(ref data, 24);
            Assert.False(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out _));
        }

        [Fact] public void ZeroLengthAttributeFails()
        {
            var data = Packet(1, Attribute(1, 0)); data[21] = 0;
            Assert.False(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out _));
        }

        [Fact] public void AttributeOverrunFails()
        {
            var data = Packet(1, Attribute(1, 2)); data[21] = 10;
            Assert.False(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out _));
        }

        [Fact] public void ReservedAttributeTypeFails()
            => Assert.False(RadiusPacketInspector.TryInspect(
                Packet(1, Attribute(0, 1)), 54000, 1812, true, out _));

        [Fact] public void InvalidMessageAuthenticatorLengthFails()
            => Assert.False(RadiusPacketInspector.TryInspect(
                Packet(1, Attribute(80, 4)), 54000, 1812, true, out _));

        [Fact] public void DuplicateMessageAuthenticatorFails()
            => Assert.False(RadiusPacketInspector.TryInspect(
                Packet(1, Attribute(80, 16), Attribute(80, 16)), 54000, 1812, true, out _));

        [Fact] public void TooManyAttributesFailClosed()
        {
            var attrs = new byte[129][];
            for (int i = 0; i < attrs.Length; i++)
                attrs[i] = Attribute(1, 0);
            Assert.False(RadiusPacketInspector.TryInspect(Packet(1, attrs), 54000, 1812, true, out _));
        }

        [Fact] public void ReorderedRequestsDoNotAssertLoginOutcome()
        {
            Assert.True(RadiusPacketInspector.TryInspect(Packet(3), 1812, 54000, true, out var reject));
            Assert.True(RadiusPacketInspector.TryInspect(Packet(2), 1812, 54000, true, out var accept));
            Assert.Equal((byte)3, reject.Code);
            Assert.Equal((byte)2, accept.Code);
        }

        [Fact] public void ConcurrentCallsRemainDeterministic()
        {
            var data = Packet(1);
            Parallel.For(0, 32, index =>
                Assert.True(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out _)));
        }

        [Fact] public void AuthenticatorAndUserNameNeverLeaveInspector()
        {
            var data = Packet(1, Attribute(1, 4));
            data[22] = 203; data[23] = 0; data[24] = 113; data[25] = 99;
            Assert.True(RadiusPacketInspector.TryInspect(data, 54000, 1812, true, out var found));
            Assert.DoesNotContain("203", found.ToString());
            Assert.DoesNotContain("250", found.ToString());
        }
    }
}
