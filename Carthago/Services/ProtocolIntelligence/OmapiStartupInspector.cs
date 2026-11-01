// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// ISC DHCP OMAPI version-1 startup prefix only, per ISC doc/api+protocol.
    /// The caller must attest that bytes start at the TCP stream origin, are
    /// contiguous plaintext, and belong to a trusted OMAPI service endpoint.
    /// This is NOT an OMAPI operation decoder, authentication validator,
    /// memory-exhaustion detector, or proof of successful server manipulation.
    /// No connection state, secrets, object names, or raw bytes are retained.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class OmapiStartupInspector
    {
        private const int StartupPrefixBytes = 8;
        private const uint Version100 = 100;
        private const uint MinimumFixedHeaderBytes = 56;
        private const uint MaximumSupportedFixedHeaderBytes = 4096;
        private const int MaximumInspectedPrefixBytes = 4096;

        public static bool TryInspect(
            ReadOnlySpan<byte> tcpStreamPrefix,
            bool verifiedStartOfTcpStream,
            bool verifiedOmapiServiceEndpoint,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            out OmapiStartupObservation observation)
        {
            observation = default;
            if (!verifiedStartOfTcpStream ||
                !verifiedOmapiServiceEndpoint ||
                !verifiedPlaintext ||
                !verifiedCaptureProvenance ||
                tcpStreamPrefix.Length < StartupPrefixBytes ||
                tcpStreamPrefix.Length > MaximumInspectedPrefixBytes)
                return false;

            uint version = BinaryPrimitives.ReadUInt32BigEndian(
                tcpStreamPrefix.Slice(0, 4));
            uint fixedHeaderBytes = BinaryPrimitives.ReadUInt32BigEndian(
                tcpStreamPrefix.Slice(4, 4));

            // ISC v1.00 sends version=100, normally hlength=56. Extensions
            // may increase hlength; larger values are unsupported, not
            // declared malicious. Later bytes are intentionally opaque.
            if (version != Version100 ||
                fixedHeaderBytes < MinimumFixedHeaderBytes ||
                fixedHeaderBytes > MaximumSupportedFixedHeaderBytes)
                return false;

            observation = new OmapiStartupObservation(
                (int)version, (int)fixedHeaderBytes);
            return true;
        }
    }

    /// <summary>
    /// Unauthenticated startup metadata only. Does not carry the OMAPI
    /// authid, transaction IDs, object attributes, signature, or outcome.
    /// </summary>
    public readonly record struct OmapiStartupObservation(
        int VersionHundredths, int AdvertisedFixedHeaderBytes);
}
