// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict, complete NTLMSSP type-3 response-shape inspector for an isolated
    /// capture producer. Does not establish successful authentication, user identity,
    /// server acceptance or a version-verified NTLMv1 outcome. Not wired to R288.
    /// Never returns or retains password-response bytes.
    /// </summary>
    public static class NtlmV1AuthenticateInspector
    {
        private const uint ExtendedSessionSecurity = 0x00080000;
        private const uint Unicode = 0x00000001;
        private const uint Oem = 0x00000002;
        private const int MaximumMessageBytes = 65536;

        public static bool TryInspect(ReadOnlySpan<byte> message, bool completeMessage,
            out NtlmV1ResponseShape observation)
        {
            observation = default;
            if (!completeMessage || message.Length < 64 || message.Length > MaximumMessageBytes ||
                !message.Slice(0, 8).SequenceEqual("NTLMSSP\0"u8) ||
                BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(8, 4)) != 3)
                return false;

            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(60, 4));
            if ((flags & ExtendedSessionSecurity) != 0 ||
                (flags & (Unicode | Oem)) == 0)
                return false;

            if (!TryBuffer(message, 12, out int lmOffset, out int lmLength) ||
                !TryBuffer(message, 20, out int ntOffset, out int ntLength) ||
                !TryBuffer(message, 28, out _, out _) ||
                !TryBuffer(message, 36, out _, out _) ||
                !TryBuffer(message, 44, out _, out _) ||
                !TryBuffer(message, 52, out _, out _) ||
                lmLength != 24 || ntLength != 24 ||
                Overlaps(lmOffset, lmLength, ntOffset, ntLength))
                return false;

            // A 24-byte NT response alone cannot distinguish NTLMv1 from
            // NTLM2-session or other legacy variants. Require nonzero LM and NT
            // material and exclude the NTLM2-session LM nonce + 16 zero bytes.
            ReadOnlySpan<byte> lm = message.Slice(lmOffset, lmLength);
            ReadOnlySpan<byte> nt = message.Slice(ntOffset, ntLength);
            if (AllZero(lm) || AllZero(nt) || AllZero(lm.Slice(8, 16)))
                return false;

            observation = new NtlmV1ResponseShape(
                IsLegacyV1Compatible: true, IsAuthenticated: false);
            return true;
        }

        private static bool TryBuffer(ReadOnlySpan<byte> message, int offset,
            out int dataOffset, out int length)
        {
            dataOffset = 0;
            length = 0;
            ushort size = BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(offset, 2));
            ushort capacity = BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(offset + 2, 2));
            uint start = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(offset + 4, 4));
            if (size > capacity || start > (uint)message.Length ||
                size > message.Length - (long)start ||
                (size != 0 && start < 64))
                return false;
            dataOffset = (int)start;
            length = size;
            return true;
        }

        private static bool Overlaps(int a, int al, int b, int bl)
            => a < (long)b + bl && b < (long)a + al;

        private static bool AllZero(ReadOnlySpan<byte> bytes)
        {
            foreach (byte b in bytes)
                if (b != 0) return false;
            return true;
        }
    }

    public readonly record struct NtlmV1ResponseShape(
        bool IsLegacyV1Compatible, bool IsAuthenticated);
}
