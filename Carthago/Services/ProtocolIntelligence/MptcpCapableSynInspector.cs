// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 8684 MPTCP v1 MP_CAPABLE initial-SYN option shape only.
    /// The caller must attest a complete TCP header/options slice, an
    /// unfragmented IP packet, an initial SYN without ACK, and source provenance.
    /// No TCP handshake completion, authentication, subflow, key or exploit
    /// conclusion follows. ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class MptcpCapableSynInspector
    {
        private const byte EndOfOptions = 0;
        private const byte NoOperation = 1;
        private const byte MptcpOptionKind = 30;
        private const int MptcpSynOptionLength = 4;
        private const int MaximumTcpOptionsLength = 40;

        public static bool TryInspect(
            ReadOnlySpan<byte> tcpOptions,
            bool verifiedCompleteTcpHeader,
            bool verifiedInitialSynWithoutAck,
            bool verifiedUnfragmentedIpPacket,
            bool verifiedSourceAttribution,
            out MptcpCapableSynObservation observation)
        {
            observation = default;
            if (!verifiedCompleteTcpHeader || !verifiedInitialSynWithoutAck ||
                !verifiedUnfragmentedIpPacket || !verifiedSourceAttribution ||
                tcpOptions.Length is < MptcpSynOptionLength or > MaximumTcpOptionsLength ||
                (tcpOptions.Length & 3) != 0)
                return false;

            bool found = false;
            byte flags = 0;
            for (int offset = 0; offset < tcpOptions.Length;)
            {
                byte kind = tcpOptions[offset];
                if (kind == EndOfOptions)
                {
                    // Strictly require zero padding after EOL; never parse
                    // apparent MPTCP bytes concealed after an EOL marker.
                    for (int index = offset; index < tcpOptions.Length; index++)
                    {
                        if (tcpOptions[index] != 0)
                            return false;
                    }

                    break;
                }

                if (kind == NoOperation)
                {
                    offset++;
                    continue;
                }

                if (tcpOptions.Length - offset < 2)
                    return false;

                int length = tcpOptions[offset + 1];
                if (length < 2 || length > tcpOptions.Length - offset)
                    return false;

                if (kind == MptcpOptionKind)
                {
                    // RFC 8684 §3.1: initial v1 SYN uses four bytes;
                    // subtype 0, version 1, HMAC-SHA256 flag H required.
                    // Reject B and unassigned crypto flags for this v1 shape.
                    if (found || length != MptcpSynOptionLength ||
                        tcpOptions[offset + 2] != 0x01)
                        return false;

                    flags = tcpOptions[offset + 3];
                    if ((flags & 0x5E) != 0 || (flags & 0x01) == 0)
                        return false;

                    found = true;
                }

                offset += length;
            }

            if (!found)
                return false;

            observation = new MptcpCapableSynObservation(
                1,
                (flags & 0x80) != 0,
                (flags & 0x20) != 0);
            return true;
        }
    }

    /// <summary>
    /// Unauthenticated TCP SYN option flags, not a negotiated connection.
    /// Never exposes tokens, cryptographic keys, addresses or payload bytes.
    /// </summary>
    public readonly record struct MptcpCapableSynObservation(
        byte OfferedVersion,
        bool ChecksumRequestedUnverified,
        bool AdditionalSubflowsToSourceDisallowedUnverified);
}
