// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    // Synthetic RFC 8489 Binding envelopes; not captured or exploit traffic.
    public sealed class StunBindingMessageInspectorTests
    {
        private static byte[] Binding(ushort messageType = 0x0001, params byte[][] attributes)
        {
            int size = 20;
            foreach (var attribute in attributes)
                size += attribute.Length;
            var data = new byte[size];
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(0, 2), messageType);
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2, 2), (ushort)(size - 20));
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), 0x2112a442);
            data[8] = 0xa5; data[19] = 0x5a; // synthetic transaction ID, never returned
            int offset = 20;
            foreach (var attribute in attributes)
            {
                attribute.CopyTo(data, offset);
                offset += attribute.Length;
            }
            return data;
        }

        private static byte[] Attribute(ushort type, int length)
        {
            int padded = (length + 3) & ~3;
            var bytes = new byte[4 + padded];
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), type);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)length);
            return bytes;
        }

        [Theory]
        [InlineData((ushort)0x0001, (byte)0)]
        [InlineData((ushort)0x0011, (byte)1)]
        [InlineData((ushort)0x0101, (byte)2)]
        [InlineData((ushort)0x0111, (byte)3)]
        public void BindingClassesAreRecognized(ushort type, byte messageClass)
        {
            Assert.True(StunBindingMessageInspector.TryInspect(Binding(type), true, out var found));
            Assert.Equal(messageClass, found.MessageClass);
            Assert.Equal(0, found.AttributeCount);
        }

        [Fact] public void AttributesAreCountedWithoutValues()
        {
            var data = Binding(0x0101, Attribute(0x0020, 8), Attribute(0x8022, 4));
            Assert.True(StunBindingMessageInspector.TryInspect(data, true, out var found));
            Assert.Equal(2, found.AttributeCount);
        }

        [Fact] public void IntegrityAndFinalFingerprintPresenceIsNotVerification()
        {
            var data = Binding(0x0001, Attribute(0x0008, 20), Attribute(0x8028, 4));
            Assert.True(StunBindingMessageInspector.TryInspect(data, true, out var found));
            Assert.True(found.HasIntegrityAttribute);
            Assert.True(found.HasFingerprintAttribute);
        }

        [Fact] public void UnknownMethodFails()
            => Assert.False(StunBindingMessageInspector.TryInspect(Binding(0x0003), true, out _));

        [Fact] public void UnattestedUdpBoundaryFails()
            => Assert.False(StunBindingMessageInspector.TryInspect(Binding(), false, out _));

        [Fact] public void DtlsLookalikeFails()
        {
            var data = Binding(); data[0] = 0x16;
            Assert.False(StunBindingMessageInspector.TryInspect(data, true, out _));
        }

        [Fact] public void WrongMagicCookieFails()
        {
            var data = Binding(); data[4] = 0;
            Assert.False(StunBindingMessageInspector.TryInspect(data, true, out _));
        }

        [Fact] public void DeclaredLengthMismatchFails()
        {
            var data = Binding(); data[3] = 4;
            Assert.False(StunBindingMessageInspector.TryInspect(data, true, out _));
        }

        [Fact] public void UnalignedLengthFails()
        {
            var data = Binding(); data[3] = 1;
            Assert.False(StunBindingMessageInspector.TryInspect(data, true, out _));
        }

        [Fact] public void TruncatedHeaderFails()
            => Assert.False(StunBindingMessageInspector.TryInspect(new byte[19], true, out _));

        [Fact] public void OversizedDatagramFails()
            => Assert.False(StunBindingMessageInspector.TryInspect(new byte[2049], true, out _));

        [Fact] public void AttributeOverrunFails()
        {
            var data = Binding(0x0001, Attribute(0x0020, 4));
            data[23] = 100;
            Assert.False(StunBindingMessageInspector.TryInspect(data, true, out _));
        }

        [Fact] public void MalformedIntegrityLengthFails()
            => Assert.False(StunBindingMessageInspector.TryInspect(
                Binding(0x0001, Attribute(0x0008, 4)), true, out _));

        [Fact] public void DuplicateIntegrityAttributeFails()
            => Assert.False(StunBindingMessageInspector.TryInspect(
                Binding(0x0001, Attribute(0x0008, 20), Attribute(0x0008, 20)), true, out _));

        [Fact] public void FingerprintMustBeLast()
            => Assert.False(StunBindingMessageInspector.TryInspect(
                Binding(0x0001, Attribute(0x8028, 4), Attribute(0x0020, 8)), true, out _));

        [Fact] public void TooManyAttributesFailClosed()
        {
            var attrs = new byte[65][];
            for (int i = 0; i < attrs.Length; i++)
                attrs[i] = Attribute(0x8022, 0);
            Assert.False(StunBindingMessageInspector.TryInspect(Binding(0x0001, attrs), true, out _));
        }

        [Fact] public void ReorderedIndependentMessagesHaveNoSessionState()
        {
            var success = Binding(0x0101); var request = Binding();
            Assert.True(StunBindingMessageInspector.TryInspect(success, true, out var a));
            Assert.True(StunBindingMessageInspector.TryInspect(request, true, out var b));
            Assert.Equal((byte)2, a.MessageClass);
            Assert.Equal((byte)0, b.MessageClass);
        }

        [Fact] public void ConcurrentCallsRemainDeterministic()
        {
            var data = Binding();
            Parallel.For(0, 32, index =>
                Assert.True(StunBindingMessageInspector.TryInspect(data, true, out _)));
        }

        [Fact] public void TransactionAndSensitiveAttributeValuesNeverLeaveInspector()
        {
            var data = Binding(0x0001, Attribute(0x0006, 8));
            data[24] = 203; data[25] = 0; data[26] = 113; data[27] = 99;
            Assert.True(StunBindingMessageInspector.TryInspect(data, true, out var found));
            Assert.DoesNotContain("203", found.ToString());
            Assert.DoesNotContain("165", found.ToString());
        }
    }
}
