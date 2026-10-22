// SPDX-License-Identifier: MIT
// File: Fingerprinting/Ja4Builders.cs
//
// Facade aggregating your JA4* pieces so other components have a single import.
// Hooks existing X509Ja4X + LatencyTracker and leaves clear stubs for Tcp JA4T/TS if you add them.

using System;
using System.Security.Cryptography.X509Certificates;
using Carthago.Services.Flow;

namespace Carthago.Services.Fingerprints
{
    public static class Ja4Builders
    {
        // JA4X: from certificate DER or X509Certificate2
        public static string? FromCertificateDer(byte[] der)
        {
            try { return X509Ja4X.FromCertificateDer(der); }
            catch { return null; }
        }

        public static string? FromCertificate(X509Certificate2 cert)
        {
            try { return X509Ja4X.FromCertificateDer(cert.RawData); }
            catch { return null; }
        }

        // JA4L / JA4LS (latency) – surfaced via LatencyTracker (already used in PacketHandler)
        public static (string? ja4l, string? ja4ls) GetLatencyFingerprints(FlowKey clientFlowKey)
            => Carthago.Services.Flow.LatencyTracker.GetLatencyFingerprints(clientFlowKey);

        // Placeholders for JA4T/JA4TS if you decide to implement exact TCP option pattern hashing.
        public static string? FromTcpSyn(/*TcpPacket syn*/) => null;
        public static string? FromTcpSynAck(/*TcpPacket synAck*/) => null;
    }
}
