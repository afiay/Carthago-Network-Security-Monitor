// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only BACnet/IPv4 BVLC (Annex J) control-plane envelope inspector.
    /// Requires a trusted, complete plaintext UDP datagram. This does not parse
    /// BACnet NPDU/APDU, authenticate a peer, infer a BBMD state change, or emit
    /// telemetry/alerts. It never retains addresses, table contents or payload.
    /// NOT REGISTERED IN LIVE CAPTURE.
    /// </summary>
    public static class BacnetBvlcControlInspector
    {
        private const int HeaderLength = 4;
        private const int MaximumTableEntries = 32;
        private const int TableEntryLength = 10;
        private const int MaximumLength = HeaderLength + MaximumTableEntries * TableEntryLength;

        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            bool verifiedCompletePlaintextUdpDatagram,
            out BvlcControlObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextUdpDatagram
                || datagram.Length is < HeaderLength or > MaximumLength
                || datagram[0] != 0x81
                || BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2)) != datagram.Length)
                return false;

            byte function = datagram[1];
            int entryCount = 0;
            ushort ttlSeconds = 0;
            ushort resultCode = 0;

            switch (function)
            {
                case 0x00: // BVLC-Result: a wire response, not an authenticated outcome.
                    if (datagram.Length != 6)
                        return false;
                    resultCode = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(4, 2));
                    if (resultCode is not (0x0000 or 0x0010 or 0x0020 or 0x0030
                        or 0x0040 or 0x0050 or 0x0060))
                        return false;
                    break;

                case 0x01: // Write-Broadcast-Distribution-Table: 10-byte entries.
                    if (datagram.Length < HeaderLength + TableEntryLength
                        || (datagram.Length - HeaderLength) % TableEntryLength != 0)
                        return false;
                    entryCount = (datagram.Length - HeaderLength) / TableEntryLength;
                    if (entryCount > MaximumTableEntries)
                        return false;
                    break;

                case 0x02: // Read-Broadcast-Distribution-Table.
                case 0x06: // Read-Foreign-Device-Table.
                    if (datagram.Length != HeaderLength)
                        return false;
                    break;

                case 0x05: // Register-Foreign-Device; zero TTL is not success evidence.
                    if (datagram.Length != 6)
                        return false;
                    ttlSeconds = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(4, 2));
                    break;

                case 0x08: // Delete-Foreign-Device-Table-Entry: 6-byte B/IP address.
                    if (datagram.Length != 10)
                        return false;
                    break;

                default:
                    // Do not overlap existing BACnet NPDU recognition, parse
                    // BVLC table replies, or guess BACnet/IPv6 (0x82) semantics.
                    return false;
            }

            observation = new BvlcControlObservation(
                (BvlcControlFunction)function, datagram.Length,
                entryCount, ttlSeconds, resultCode);
            return true;
        }
    }

    public enum BvlcControlFunction : byte
    {
        Result = 0x00,
        WriteBroadcastDistributionTable = 0x01,
        ReadBroadcastDistributionTable = 0x02,
        RegisterForeignDevice = 0x05,
        ReadForeignDeviceTable = 0x06,
        DeleteForeignDeviceTableEntry = 0x08
    }

    /// <summary>
    /// Unauthenticated wire-shape metadata only. No peer address, identifier,
    /// table entries, sensitive BACnet values, or server-accepted outcome.
    /// </summary>
    public readonly record struct BvlcControlObservation(
        BvlcControlFunction Function,
        int MessageLength,
        int TableEntryCount,
        ushort RequestedTtlSeconds,
        ushort UnauthenticatedResultCode);
}
