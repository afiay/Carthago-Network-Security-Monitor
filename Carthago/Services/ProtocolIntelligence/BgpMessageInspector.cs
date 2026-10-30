// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated BGP-4 message-envelope inspection (RFC 4271, route refresh RFC 2918).
    /// Requires a complete caller-attested TCP BGP message boundary.
    /// Does not parse routes, validate AS paths or infer hijacking or session success.
    /// </summary>
    public static class BgpMessageInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> message,
            bool verifiedCompleteTcpMessageBoundary,
            out BgpMessageObservation observation)
        {
            observation = default;
            if (!verifiedCompleteTcpMessageBoundary || message.Length is < 19 or > 4096)
                return false;
            for (int i = 0; i < 16; i++)
                if (message[i] != 0xff)
                    return false;
            int declared = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(16, 2));
            if (declared != message.Length)
                return false;

            BgpMessageKind kind;
            switch (message[18])
            {
                case 1: // OPEN: version, AS, hold, router ID, optional parameter length.
                    if (message.Length < 29 || message[19] != 4
                        || message.Length != 29 + message[28])
                        return false;
                    ushort holdTime = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(22, 2));
                    if (holdTime is 1 or 2)
                        return false;
                    kind = BgpMessageKind.Open;
                    break;
                case 2: // UPDATE: withdrawn length + withdrawn bytes + attribute length + attributes.
                    if (message.Length < 23)
                        return false;
                    int withdrawn = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(19, 2));
                    int attrLengthOffset = 21 + withdrawn;
                    if (attrLengthOffset > message.Length - 2)
                        return false;
                    int attrs = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(attrLengthOffset, 2));
                    if (attrs > message.Length - (attrLengthOffset + 2))
                        return false;
                    kind = BgpMessageKind.Update;
                    break;
                case 3:
                    if (message.Length < 21)
                        return false;
                    kind = BgpMessageKind.Notification;
                    break;
                case 4:
                    if (message.Length != 19)
                        return false;
                    kind = BgpMessageKind.Keepalive;
                    break;
                case 5: // ROUTE-REFRESH (AFI, reserved, SAFI).
                    if (message.Length != 23 || message[21] != 0)
                        return false;
                    kind = BgpMessageKind.RouteRefresh;
                    break;
                default:
                    return false;
            }
            // Never retain ASNs, prefixes, BGP IDs, notification data or attributes.
            observation = new BgpMessageObservation(kind, message.Length);
            return true;
        }
    }

    public enum BgpMessageKind : byte
    {
        Open = 1, Update = 2, Notification = 3, Keepalive = 4, RouteRefresh = 5
    }

    public readonly record struct BgpMessageObservation(BgpMessageKind Kind, int MessageLength);
}