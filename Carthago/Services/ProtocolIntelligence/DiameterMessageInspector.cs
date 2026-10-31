// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 6733 Diameter v1 structural envelope inspection only.
    /// The caller must independently attest a complete, plaintext Diameter message
    /// from TCP reassembly or SCTP message delivery. This does not implement
    /// transport reassembly, TLS/DTLS decryption, AVP semantics or AAA outcomes.
    /// No identifiers, AVP values, credentials or payload bytes are retained.
    /// </summary>
    public static class DiameterMessageInspector
    {
        private const int HeaderLength = 20;
        private const int MaximumMessageLength = 16 * 1024;
        private const int MaximumAvps = 256;

        public static bool TryInspect(ReadOnlySpan<byte> message,
            DiameterTransport transport, bool verifiedCompletePlaintextMessage,
            out DiameterObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextMessage
                || transport is not (DiameterTransport.Tcp or DiameterTransport.Sctp)
                || message.Length is < HeaderLength or > MaximumMessageLength
                || message[0] != 1)
                return false;

            int declaredLength = ReadUInt24(message.Slice(1, 3));
            if (declaredLength != message.Length || (declaredLength & 3) != 0)
                return false;

            byte flags = message[4];
            bool isRequest = (flags & 0x80) != 0;
            bool isError = (flags & 0x20) != 0;
            bool retransmitted = (flags & 0x10) != 0;
            if ((flags & 0x0f) != 0 || (isRequest && isError)
                || (!isRequest && retransmitted))
                return false;

            int commandCode = ReadUInt24(message.Slice(5, 3));
            if (commandCode == 0)
                return false;

            uint applicationId = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(8, 4));
            int cursor = HeaderLength;
            int avpCount = 0;
            bool vendorSpecific = false;

            while (cursor < message.Length)
            {
                if (++avpCount > MaximumAvps || message.Length - cursor < 8)
                    return false;

                byte avpFlags = message[cursor + 4];
                bool hasVendorId = (avpFlags & 0x80) != 0;
                int avpHeaderLength = hasVendorId ? 12 : 8;
                int avpLength = ReadUInt24(message.Slice(cursor + 5, 3));
                // Strict subset: reserved and obsolete P flag are rejected.
                if ((avpFlags & 0x3f) != 0
                    || avpLength < avpHeaderLength
                    || avpLength > message.Length - cursor)
                    return false;

                int alignedLength = (avpLength + 3) & ~3;
                if (alignedLength > message.Length - cursor)
                    return false;

                if (hasVendorId)
                {
                    if (BinaryPrimitives.ReadUInt32BigEndian(
                        message.Slice(cursor + 8, 4)) == 0)
                        return false;
                    vendorSpecific = true;
                }

                // RFC 6733 AVP padding must be zero; never inspect or retain data.
                for (int i = avpLength; i < alignedLength; i++)
                    if (message[cursor + i] != 0)
                        return false;

                cursor += alignedLength;
            }

            observation = new DiameterObservation(
                commandCode, applicationId, isRequest, isError,
                retransmitted, avpCount, vendorSpecific, declaredLength);
            return true;
        }

        private static int ReadUInt24(ReadOnlySpan<byte> bytes)
            => (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
    }

    public enum DiameterTransport : byte
    {
        Unknown = 0,
        Tcp = 1,
        Sctp = 2
    }

    public readonly record struct DiameterObservation(
        int CommandCode,
        uint ApplicationId,
        bool IsRequest,
        bool IsError,
        bool PotentialRetransmission,
        int AvpCount,
        bool HasVendorSpecificAvp,
        int MessageLength);
}
