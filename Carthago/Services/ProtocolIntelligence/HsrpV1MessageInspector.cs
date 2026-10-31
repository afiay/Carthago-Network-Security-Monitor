// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 2281 HSRP version-0 UDP message-shape inspector.
    /// The caller must attest a complete IPv4 UDP/1985 payload received with
    /// TTL=1 and destination 224.0.0.2. This is NOT authentication or proof
    /// of router election/forwarding. Cleartext password and virtual IP
    /// fields are never retained, exposed or compared.
    /// </summary>
    public static class HsrpV1MessageInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> datagram, ushort destinationPort,
            bool verifiedCompleteUdpPayload, bool verifiedIpv4LocalMulticastEnvelope,
            out HsrpV1MessageObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || !verifiedIpv4LocalMulticastEnvelope
                || destinationPort != 1985 || datagram.Length != 20
                || datagram[0] != 0 || datagram[1] > 2 || datagram[7] != 0)
                return false; // Version 0 only; HSRPv2 is a separate framing contract.

            byte state = datagram[2];
            if (state is not (0 or 1 or 2 or 4 or 8 or 16))
                return false;
            if (datagram[1] == 0 && (datagram[3] == 0
                || datagram[4] <= datagram[3]))
                return false; // Hello holdtime MUST exceed hellotime (RFC 2281).

            observation = new HsrpV1MessageObservation(
                datagram[1], state, datagram[5], datagram[6],
                datagram[3], datagram[4]);
            return true;
        }
    }

    public readonly record struct HsrpV1MessageObservation(
        byte OpCode, byte State, byte Priority, byte Group,
        byte HelloSeconds, byte HoldSeconds);
}
