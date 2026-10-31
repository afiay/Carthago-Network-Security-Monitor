// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Firebird XDR wire-protocol envelope observer. The caller must independently
    /// attest a complete, plaintext, reassembled PDU, direction and a verified
    /// Firebird endpoint. TCP segments, port 3050 and encrypted bytes are not
    /// sufficient. No payload, identity, database path or credential is returned.
    /// Stateless and unregistered: never an authentication or exploit verdict.
    /// Reference: Firebird Wire Protocol, revision 0.18 (18 May 2025).
    /// </summary>
    public static class FirebirdWirePduInspector
    {
        private const int MaximumPduLength = 4096;
        private const int MaximumNameLength = 1024;
        private const int MaximumPrivateBufferLength = 2048;
        private const int MaximumProtocolOffers = 11;

        public static bool TryInspect(ReadOnlySpan<byte> pdu,
            bool verifiedCompletePlaintextPdu, bool verifiedFirebirdEndpoint,
            bool fromServer, out FirebirdWireObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextPdu || !verifiedFirebirdEndpoint ||
                pdu.Length is < 4 or > MaximumPduLength)
                return false;

            int offset = 0;
            if (!TryReadUInt32(pdu, ref offset, out uint opcode))
                return false;

            int offeredVersions = 0;
            switch (opcode)
            {
                case 1: // op_connect: client protocol negotiation
                    if (fromServer || !TryConnect(pdu, ref offset, out offeredVersions))
                        return false;
                    break;
                case 3: // op_accept: legacy simple accept (not extended accept)
                    if (!fromServer || pdu.Length != 16 ||
                        !TryReadUInt32(pdu, ref offset, out uint version) ||
                        !TryReadUInt32(pdu, ref offset, out uint architecture) ||
                        !TryReadUInt32(pdu, ref offset, out uint connectionType) ||
                        !ValidVersion(version) || architecture == 0 ||
                        !ValidConnectionType(connectionType, allowFlags: true))
                        return false;
                    break;
                case 4: // op_reject: a response shape, not a proven login failure
                    if (!fromServer || pdu.Length != 4)
                        return false;
                    break;
                case 19: // op_attach
                case 20: // op_create
                case 82: // op_service_attach
                    if (fromServer ||
                        !TryReadUInt32(pdu, ref offset, out uint unused) || unused != 0 ||
                        !TrySkipOpaque(pdu, ref offset, MaximumNameLength) ||
                        !TrySkipOpaque(pdu, ref offset, MaximumPrivateBufferLength))
                        return false;
                    break;
                case 97: // op_crypt_key_callback: may legitimately occur during auth
                    if (!TrySkipOpaque(pdu, ref offset, MaximumPrivateBufferLength))
                        return false;
                    if (offset != pdu.Length)
                    {
                        if (pdu.Length - offset != 4 ||
                            !TryReadUInt32(pdu, ref offset, out uint replySize) ||
                            (!fromServer && replySize != 0))
                            return false;
                    }
                    break;
                default:
                    return false; // No claim for op_slice, SQL, extended auth or unknown PDUs.
            }

            if (offset != pdu.Length)
                return false;
            observation = new FirebirdWireObservation(
                opcode, pdu.Length, offeredVersions, fromServer, opcode == 97);
            return true;
        }

        private static bool TryConnect(ReadOnlySpan<byte> pdu, ref int offset,
            out int offeredVersions)
        {
            offeredVersions = 0;
            if (!TryReadUInt32(pdu, ref offset, out uint unused) || unused != 0 ||
                !TryReadUInt32(pdu, ref offset, out uint connectVersion) ||
                connectVersion is not (2 or 3) ||
                !TryReadUInt32(pdu, ref offset, out uint clientArchitecture) ||
                clientArchitecture == 0 ||
                !TrySkipOpaque(pdu, ref offset, MaximumNameLength) ||
                !TryReadUInt32(pdu, ref offset, out uint count) ||
                count is < 1 or > MaximumProtocolOffers ||
                !TrySkipOpaque(pdu, ref offset, MaximumPrivateBufferLength))
                return false;

            for (int i = 0; i < (int)count; i++)
            {
                if (!TryReadUInt32(pdu, ref offset, out uint version) ||
                    !TryReadUInt32(pdu, ref offset, out uint architecture) ||
                    !TryReadUInt32(pdu, ref offset, out uint minimumType) ||
                    !TryReadUInt32(pdu, ref offset, out uint maximumType) ||
                    !TryReadUInt32(pdu, ref offset, out _) ||
                    !ValidVersion(version) || architecture == 0 ||
                    !ValidConnectionType(minimumType, allowFlags: false) ||
                    !ValidConnectionType(maximumType, allowFlags: true) ||
                    (minimumType & 0xffu) > (maximumType & 0xffu))
                    return false;
            }
            offeredVersions = (int)count;
            return true;
        }

        private static bool ValidVersion(uint value)
        {
            uint normalized = value & ~0x8000u;
            return normalized is >= 10 and <= 19;
        }

        private static bool ValidConnectionType(uint value, bool allowFlags)
        {
            uint kind = value & 0xffu;
            uint flags = value & ~0xffu;
            return kind is >= 1 and <= 5 &&
                (allowFlags ? (flags & ~0x300u) == 0 : flags == 0);
        }

        private static bool TrySkipOpaque(ReadOnlySpan<byte> pdu, ref int offset,
            int maximumLength)
        {
            if (!TryReadUInt32(pdu, ref offset, out uint length) ||
                length > (uint)maximumLength)
                return false;
            int padded = ((int)length + 3) & ~3;
            if (padded > pdu.Length - offset)
                return false;
            for (int i = (int)length; i < padded; i++)
                if (pdu[offset + i] != 0)
                    return false;
            offset += padded;
            return true;
        }

        private static bool TryReadUInt32(ReadOnlySpan<byte> pdu, ref int offset,
            out uint value)
        {
            value = 0;
            if (offset > pdu.Length - 4)
                return false;
            value = BinaryPrimitives.ReadUInt32BigEndian(pdu.Slice(offset, 4));
            offset += 4;
            return true;
        }
    }

    /// <summary>
    /// Structural metadata only. CallbackShapeOnly is not evidence of an
    /// authentication bypass, vulnerable server or successful operation.
    /// </summary>
    public readonly record struct FirebirdWireObservation(
        uint OperationCode, int PduLength, int OfferedVersions,
        bool ServerToClient, bool CallbackShapeOnly);
}
