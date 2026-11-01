// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded, stateless SOME/IP Service Discovery envelope inspection.
    /// Caller must attest one complete unfragmented, readable UDP datagram,
    /// a known SOME/IP-SD endpoint, and trustworthy capture provenance.
    /// This is NOT a generic SOME/IP/TCP decoder, an authenticated ECU
    /// identity, an authorization decision, or an exploitation detector.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class SomeIpSdEnvelopeInspector
    {
        private const int MaximumDatagramBytes = 4096;
        private const int MaximumEntries = 64;
        private const int MaximumOptions = 64;
        private const int EntrySize = 16;
        private const int MinimumMessageBytes = 44; // 16 header + 12 SD header + one entry

        public static bool TryInspect(
            ReadOnlySpan<byte> datagram,
            bool verifiedCompleteUdpDatagram,
            bool verifiedUnfragmentedIpPacket,
            bool verifiedReadablePlaintext,
            bool verifiedSomeIpSdEndpoint,
            bool verifiedCaptureProvenance,
            out SomeIpSdEnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpDatagram || !verifiedUnfragmentedIpPacket ||
                !verifiedReadablePlaintext || !verifiedSomeIpSdEndpoint ||
                !verifiedCaptureProvenance ||
                datagram.Length < MinimumMessageBytes ||
                datagram.Length > MaximumDatagramBytes)
                return false;

            // SOME/IP length counts Request ID through the end of the payload,
            // excluding the first eight bytes. Never allocate from this value.
            if (BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(0, 2)) != 0xffff ||
                BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2)) != 0x8100 ||
                BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(4, 4)) !=
                    (uint)(datagram.Length - 8) ||
                datagram[12] != 1 || datagram[13] != 1 ||
                datagram[14] != 0x02 || datagram[15] != 0)
                return false;

            byte flags = datagram[16];
            if ((flags & 0x1f) != 0 ||
                datagram[17] != 0 || datagram[18] != 0 || datagram[19] != 0)
                return false;

            uint declaredEntryBytes = BinaryPrimitives.ReadUInt32BigEndian(
                datagram.Slice(20, 4));
            if (declaredEntryBytes < EntrySize ||
                declaredEntryBytes > MaximumEntries * EntrySize ||
                declaredEntryBytes % EntrySize != 0 ||
                declaredEntryBytes > datagram.Length - 28)
                return false;

            int entryBytes = (int)declaredEntryBytes;
            int entryCount = entryBytes / EntrySize;
            int optionsLengthOffset = 24 + entryBytes;
            uint declaredOptionBytes = BinaryPrimitives.ReadUInt32BigEndian(
                datagram.Slice(optionsLengthOffset, 4));
            int optionsOffset = optionsLengthOffset + 4;
            if (declaredOptionBytes != (uint)(datagram.Length - optionsOffset))
                return false;

            ReadOnlySpan<byte> options = datagram.Slice(optionsOffset);
            int optionCount = 0;
            bool hasEndpointOption = false;
            int optionOffset = 0;
            while (optionOffset < options.Length)
            {
                if (++optionCount > MaximumOptions || options.Length - optionOffset < 4)
                    return false;

                int contentLength = BinaryPrimitives.ReadUInt16BigEndian(
                    options.Slice(optionOffset, 2));
                if (contentLength < 1 ||
                    contentLength > options.Length - optionOffset - 3)
                    return false;

                byte optionType = options[optionOffset + 2];
                if (optionType == 0x04 || optionType == 0x14 || optionType == 0x24 ||
                    optionType == 0x06 || optionType == 0x16 || optionType == 0x26)
                {
                    bool ipv6 = optionType == 0x06 || optionType == 0x16 ||
                                optionType == 0x26;
                    if (contentLength != (ipv6 ? 21 : 9))
                        return false;

                    int secondReserved = optionOffset + (ipv6 ? 20 : 8);
                    int transportOffset = secondReserved + 1;
                    if (options[optionOffset + 3] != 0 ||
                        options[secondReserved] != 0 ||
                        (options[transportOffset] != 6 &&
                         options[transportOffset] != 17))
                        return false;

                    hasEndpointOption = true;
                }
                else if (optionType == 0x02 && contentLength != 5)
                {
                    return false; // Load Balancing option
                }

                // Unknown/Configuration option contents are opaque, never logged.
                optionOffset += 3 + contentLength;
            }

            int findCount = 0;
            int offerCount = 0;
            int subscribeCount = 0;
            int subscribeAckCount = 0;
            int stopOfferCount = 0;
            for (int i = 0; i < entryCount; i++)
            {
                ReadOnlySpan<byte> entry = datagram.Slice(24 + i * EntrySize, EntrySize);
                int firstCount = entry[3] >> 4;
                int secondCount = entry[3] & 0x0f;
                if ((firstCount != 0 && entry[1] + firstCount > optionCount) ||
                    (secondCount != 0 && entry[2] + secondCount > optionCount))
                    return false;

                switch (entry[0])
                {
                    case 0x00: // FindService
                        findCount++;
                        break;
                    case 0x01: // OfferService (TTL zero = StopOffer)
                        offerCount++;
                        if (entry[9] == 0 && entry[10] == 0 && entry[11] == 0)
                            stopOfferCount++;
                        break;
                    case 0x06: // SubscribeEventgroup
                    case 0x07: // SubscribeEventgroupAck
                        if (entry[12] != 0 || (entry[13] & 0x70) != 0)
                            return false;
                        if (entry[0] == 0x06)
                            subscribeCount++;
                        else
                            subscribeAckCount++;
                        break;
                    default:
                        return false;
                }
            }

            observation = new SomeIpSdEnvelopeObservation(
                findCount, offerCount, subscribeCount, subscribeAckCount,
                stopOfferCount, optionCount, hasEndpointOption,
                (flags & 0x80) != 0, (flags & 0x40) != 0);
            return true;
        }
    }

    /// <summary>
    /// Unverified message-shape counts only. Does not retain ECU/service IDs,
    /// endpoint addresses/ports, session identifiers, or option contents.
    /// No proof of authorized service discovery, spoofing, or state change.
    /// </summary>
    public readonly record struct SomeIpSdEnvelopeObservation(
        int FindServiceCountUnverified,
        int OfferServiceCountUnverified,
        int SubscribeEventgroupCountUnverified,
        int SubscribeAckCountUnverified,
        int StopOfferCountUnverified,
        int OptionCount,
        bool HasEndpointOption,
        bool RebootFlag,
        bool UnicastFlag);
}
