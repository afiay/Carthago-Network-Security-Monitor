// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded connection-oriented DCE/RPC v5 PDU header inspection at a
    /// caller-attested complete PDU boundary. No NDR, auth token, SMB pipe,
    /// interface UUID, opnum, or successful-operation decoding.
    /// ISOLATED: no live capture or shared telemetry integration.
    /// </summary>
    public static class DceRpcPduInspector
    {
        private const int CommonHeaderLength = 16;
        private const int MaxInspectedFragment = 16_384;

        public static bool TryInspect(
            ReadOnlySpan<byte> bytes,
            bool verifiedRpcPduBoundary,
            out DceRpcPduObservation observation)
        {
            observation = default;
            if (!verifiedRpcPduBoundary || bytes.Length < CommonHeaderLength
                || bytes[0] != 5 || bytes[1] != 0)
                return false;

            byte pduType = bytes[2];
            if (pduType is not (0 or 2 or 3 or 11 or 12 or 13 or 14 or 15 or 16 or 17 or 18 or 19))
                return false;

            byte representation = bytes[4];
            if ((representation != 0x10 && representation != 0x00)
                || bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0)
                return false;

            bool littleEndian = representation == 0x10;
            ushort fragmentLength = littleEndian
                ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(8, 2))
                : BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(8, 2));
            ushort authLength = littleEndian
                ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(10, 2))
                : BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(10, 2));

            if (fragmentLength < CommonHeaderLength
                || fragmentLength > MaxInspectedFragment
                || fragmentLength > bytes.Length)
                return false;

            int authTrailerLength = authLength == 0 ? 0 : 8 + authLength;
            if (authTrailerLength > fragmentLength - CommonHeaderLength)
                return false;

            int bodyLength = fragmentLength - CommonHeaderLength - authTrailerLength;
            int minimumBody = pduType switch
            {
                0 or 2 or 3 => 8,      // request, response, fault fixed fields
                11 or 14 => 12,       // bind / alter_context fixed fields
                _ => 0
            };
            if (bodyLength < minimumBody)
                return false;

            if (authLength > 0)
            {
                int trailerOffset = fragmentLength - authLength - 8;
                int paddingLength = bytes[trailerOffset + 2];
                if (paddingLength > bodyLength - minimumBody)
                    return false;
            }

            uint callId = littleEndian
                ? BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(12, 4))
                : BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(12, 4));

            observation = new DceRpcPduObservation(
                pduType, bytes[3], callId, fragmentLength, authLength,
                littleEndian, authLength != 0);
            return true;
        }
    }

    /// <summary>Untrusted PDU-shape metadata, never a verified RPC operation outcome.</summary>
    public readonly record struct DceRpcPduObservation(
        byte PduType,
        byte FragmentFlags,
        uint CallId,
        int BytesConsumed,
        ushort AuthVerifierLength,
        bool LittleEndian,
        bool HasAuthVerifier);
}
