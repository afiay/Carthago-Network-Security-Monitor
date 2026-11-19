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
        private const uint NegotiateVersion = 0x02000000;
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

            // Type-3 has six security buffers. Validate every descriptor, not
            // only LM/NT responses: ancillary fields must not alias response bytes.
            // NEGOTIATE_VERSION inserts an eight-byte version field at offset 64.
            int minimumDataOffset = (flags & NegotiateVersion) != 0 ? 72 : 64;
            Span<int> offsets = stackalloc int[6];
            Span<int> lengths = stackalloc int[6];
            for (int i = 0; i < 6; i++)
            {
                if (!TryBuffer(message, 12 + (i * 8), minimumDataOffset,
                    out int dataOffset, out int length))
                    return false;
                offsets[i] = dataOffset;
                lengths[i] = length;
            }

            for (int i = 0; i < lengths.Length; i++)
            {
                if (lengths[i] == 0) continue;
                for (int j = i + 1; j < lengths.Length; j++)
                {
                    if (lengths[j] != 0 &&
                        Overlaps(offsets[i], lengths[i], offsets[j], lengths[j]))
                        return false;
                }
            }

            int lmOffset = offsets[0], lmLength = lengths[0];
            int ntOffset = offsets[1], ntLength = lengths[1];
            if (lmLength != 24 || ntLength != 24)
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
            int minimumDataOffset, out int dataOffset, out int length)
        {
            dataOffset = 0;
            length = 0;
            ushort size = BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(offset, 2));
            ushort capacity = BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(offset + 2, 2));
            uint start = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(offset + 4, 4));
            long available = start <= (uint)message.Length
                ? message.Length - (long)start : -1;
            if (size > capacity || available < 0 ||
                capacity > available || size > available ||
                (size != 0 && start < (uint)minimumDataOffset))
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
