// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class NtlmV1AuthenticateInspectorTests
    {
        private static byte[] Candidate()
        {
            var bytes = new byte[112];
            "NTLMSSP\0"u8.CopyTo(bytes.AsSpan());
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 3);
            Buffer(bytes, 12, 64, 24);
            Buffer(bytes, 20, 88, 24);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 2);
            bytes.AsSpan(64, 48).Fill(0x39);
            return bytes;
        }
        private static void Buffer(byte[] bytes, int field, int offset, ushort length,
            ushort? capacity = null)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(field), length);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(field + 2), capacity ?? length);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(field + 4), (uint)offset);
        }

        [Fact] public void CompleteLegacyShapeIsOnlyAProtocolObservation()
        {
            Assert.True(NtlmV1AuthenticateInspector.TryInspect(Candidate(), true, out var result));
            Assert.True(result.IsLegacyV1Compatible);
            Assert.False(result.IsAuthenticated);
        }
        [Fact] public void TruncatedOrIncompleteMessageFailsClosed()
        {
            var bytes = Candidate();
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, false, out _));
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes.AsSpan(0, 100), true, out _));
        }
        [Fact] public void ExtendedSessionSecurityIsNotMisclassified()
        {
            var bytes = Candidate();
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 0x00080002);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }
        [Fact] public void SessionNonceAndZeroLmTailIsExcluded()
        {
            var bytes = Candidate();
            bytes.AsSpan(72, 16).Clear();
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }
        [Fact] public void OverlappingOrOutOfRangeBuffersFailClosed()
        {
            var bytes = Candidate();
            Buffer(bytes, 20, 70, 24);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
            bytes = Candidate();
            Buffer(bytes, 20, 100, 24);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }
        [Fact] public void AncillarySecurityBufferCannotOverlapResponseBytes()
        {
            var bytes = Candidate();
            Buffer(bytes, 28, 70, 4);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void SecurityBufferMaximumLengthMustFitInsideMessage()
        {
            var bytes = Candidate();
            Buffer(bytes, 12, 64, 24, 49);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void VersionFieldCannotBeReusedAsResponseBytes()
        {
            var bytes = Candidate();
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 0x02000002);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }

        [Fact] public void VersionedHeaderWithDisjointResponsesIsAccepted()
        {
            var bytes = new byte[120];
            "NTLMSSP\0"u8.CopyTo(bytes.AsSpan());
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 3);
            Buffer(bytes, 12, 72, 24);
            Buffer(bytes, 20, 96, 24);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 0x02000002);
            bytes.AsSpan(72, 48).Fill(0x39);

            Assert.True(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out var result));
            Assert.True(result.IsLegacyV1Compatible);
            Assert.False(result.IsAuthenticated);
        }

        [Fact] public void ZeroPasswordResponsesAndWrongMessageTypeFailClosed()
        {
            var bytes = Candidate();
            bytes.AsSpan(88, 24).Clear();
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
            bytes = Candidate();
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 1);
            Assert.False(NtlmV1AuthenticateInspector.TryInspect(bytes, true, out _));
        }
    }
}
