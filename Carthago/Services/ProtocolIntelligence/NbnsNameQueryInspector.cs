// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// A bounded first-level NetBIOS Name Service query decoder for complete
    /// capture-origin UDP payloads only. No raw name, suffix, question or
    /// authentication secret is exported. Does not imply unauthorized discovery.
    /// </summary>
    internal static class NbnsNameQueryInspector
    {
        // RFC 1002: 12-byte header, 1 length + 32 encoded name bytes +
        // zero terminator, 2-byte QTYPE and 2-byte QCLASS.
        private const int QueryLength = 50;

        internal static bool TryInspect(ReadOnlySpan<byte> payload, out string questionDigest)
        {
            questionDigest = string.Empty;
            if (payload.Length != QueryLength)
                return false;

            var flags = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
            // Reject QR response, non-query opcode, authoritative or truncated
            // packets, and nonzero RCODE. RD and the NBNS broadcast bit are legal.
            if ((flags & 0xFE0F) != 0
                || BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2)) != 1
                || BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(6, 2)) != 0
                || BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2)) != 0
                || BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(10, 2)) != 0
                || payload[12] != 32 || payload[45] != 0
                || BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(46, 2)) != 0x0020
                || BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(48, 2)) != 1)
                return false;

            Span<byte> decoded = stackalloc byte[16];
            var nonBlank = false;
            for (int index = 0; index < 16; index++)
            {
                int hi = payload[13 + index * 2] - 'A';
                int lo = payload[14 + index * 2] - 'A';
                if (hi is < 0 or > 15 || lo is < 0 or > 15)
                {
                    CryptographicOperations.ZeroMemory(decoded);
                    return false;
                }
                decoded[index] = (byte)((hi << 4) | lo);
                if (index >= 15) continue;
                if (decoded[index] is < 0x20 or > 0x7E)
                {
                    CryptographicOperations.ZeroMemory(decoded);
                    return false;
                }
                if (decoded[index] != 0x20) nonBlank = true;
            }

            if (!nonBlank)
            {
                CryptographicOperations.ZeroMemory(decoded);
                return false;
            }

            questionDigest = Convert.ToHexString(SHA256.HashData(decoded));
            CryptographicOperations.ZeroMemory(decoded);
            return true;
        }
    }
}
