// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded DTLS 1.0/1.2 record-shape inspection for one UDP datagram.
    /// Does not decrypt payloads, authenticate peers, infer replay or detect CVEs.
    /// DTLS 1.3 compact encrypted headers require a separate version-aware adapter.
    /// Not wired into the capture pipeline.
    /// </summary>
    public static class DtlsRecordInspector
    {
        private const int RecordHeaderLength = 13;
        private const int MaxRecordsPerDatagram = 16;
        private const int MaxRecordPayload = 18_432;

        public static bool TryInspect(ReadOnlySpan<byte> datagram, out DtlsRecordObservation observation)
        {
            observation = default;
            if (datagram.Length < RecordHeaderLength + 1 || datagram.Length > 65_535)
                return false;

            int cursor = 0;
            int recordCount = 0;
            byte firstType = 0;
            ushort firstVersion = 0;
            ushort firstEpoch = 0;
            ulong firstSequence = 0;
            byte? firstHandshakeType = null;
            bool opaqueContent = false;

            while (cursor < datagram.Length)
            {
                if (++recordCount > MaxRecordsPerDatagram
                    || datagram.Length - cursor < RecordHeaderLength)
                    return false;

                byte type = datagram[cursor];
                ushort version = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(cursor + 1, 2));
                ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(cursor + 3, 2));
                ulong sequence = ((ulong)datagram[cursor + 5] << 40)
                    | ((ulong)datagram[cursor + 6] << 32)
                    | ((ulong)datagram[cursor + 7] << 24)
                    | ((ulong)datagram[cursor + 8] << 16)
                    | ((ulong)datagram[cursor + 9] << 8)
                    | datagram[cursor + 10];
                int length = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(cursor + 11, 2));

                if (type is < 20 or > 23 || (version != 0xFEFF && version != 0xFEFD)
                    || length < 1 || length > MaxRecordPayload
                    || length > datagram.Length - cursor - RecordHeaderLength)
                    return false;

                ReadOnlySpan<byte> body = datagram.Slice(cursor + RecordHeaderLength, length);
                byte? handshakeType = null;
                if (type == 22 && epoch == 0)
                {
                    // Only an unencrypted first handshake fragment can be inspected.
                    // The 12-byte handshake header contains message and fragment lengths.
                    if (body.Length < 12)
                        return false;
                    int messageLength = (body[1] << 16) | (body[2] << 8) | body[3];
                    int fragmentOffset = (body[6] << 16) | (body[7] << 8) | body[8];
                    int fragmentLength = (body[9] << 16) | (body[10] << 8) | body[11];
                    if (fragmentOffset > messageLength
                        || fragmentLength > messageLength - fragmentOffset
                        || fragmentLength > body.Length - 12)
                        return false;
                    handshakeType = body[0];
                }

                if (recordCount == 1)
                {
                    firstType = type;
                    firstVersion = version;
                    firstEpoch = epoch;
                    firstSequence = sequence;
                    firstHandshakeType = handshakeType;
                }
                opaqueContent |= epoch != 0 || type == 23;
                cursor += RecordHeaderLength + length;
            }

            observation = new DtlsRecordObservation(
                firstType, firstVersion, firstEpoch, firstSequence, recordCount,
                firstHandshakeType, opaqueContent);
            return true;
        }
    }

    /// <summary>Datagram framing metadata, not an authenticated endpoint or exploit result.</summary>
    public readonly record struct DtlsRecordObservation(
        byte FirstContentType,
        ushort FirstVersion,
        ushort FirstEpoch,
        ulong FirstSequenceNumber,
        int RecordCount,
        byte? FirstHandshakeType,
        bool ContainsOpaqueContent);
}
