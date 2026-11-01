// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated, conservative ERSPAN Type II GRE-envelope inspector.
    /// Requires caller-attested complete IP protocol 47 payload, trusted
    /// mirror endpoint, plaintext envelope and capture provenance.
    /// Never decapsulates or retains mirrored frames, MACs or credentials.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class ErspanTypeIIEnvelopeInspector
    {
        private const int GreHeaderBytes = 8;
        private const int ErspanHeaderBytes = 8;
        private const int MinimumMirroredEthernetBytes = 14;
        private const int MaximumGrePayloadBytes = 16384;
        private const ushort GreSequenceOnly = 0x1000;
        private const ushort ErspanTypeIOrII = 0x88be;

        public static bool TryInspect(
            ReadOnlySpan<byte> grePayload,
            byte ipProtocol,
            bool verifiedCompleteIpPayload,
            bool verifiedMirrorEndpoint,
            bool verifiedPlaintextEnvelope,
            bool verifiedCaptureProvenance,
            out ErspanTypeIIObservation observation)
        {
            observation = default;

            if (ipProtocol != 47 ||
                !verifiedCompleteIpPayload ||
                !verifiedMirrorEndpoint ||
                !verifiedPlaintextEnvelope ||
                !verifiedCaptureProvenance ||
                grePayload.Length < GreHeaderBytes + ErspanHeaderBytes +
                    MinimumMirroredEthernetBytes ||
                grePayload.Length > MaximumGrePayloadBytes)
                return false;

            // GRE sequence bit is mandatory for Type II. Reject Type I,
            // Type III, keys, checksums, routing and other GRE variants.
            if (BinaryPrimitives.ReadUInt16BigEndian(grePayload) != GreSequenceOnly ||
                BinaryPrimitives.ReadUInt16BigEndian(grePayload.Slice(2, 2)) !=
                    ErspanTypeIOrII ||
                (grePayload[8] >> 4) != 1)
                return false;

            // Type II's reserved 12 bits must be zero. The remaining
            // 20 bits represent a platform-dependent port index.
            if (grePayload[12] != 0 || (grePayload[13] & 0xf0) != 0)
                return false;

            int mirroredOffset = GreHeaderBytes + ErspanHeaderBytes;
            // Conservative Ethernet-II discriminator; 802.3 length-format
            // frames are deliberately unsupported rather than misclassified.
            ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(
                grePayload.Slice(mirroredOffset + 12, 2));
            if (etherType < 0x0600)
                return false;

            ushort vlan = (ushort)(((grePayload[8] & 0x0f) << 8) | grePayload[9]);
            byte classOfService = (byte)(grePayload[10] >> 5);
            byte encapsulationKind = (byte)((grePayload[10] >> 3) & 3);
            bool truncated = (grePayload[10] & 4) != 0;
            ushort sessionId = (ushort)(((grePayload[10] & 3) << 8) | grePayload[11]);
            uint portIndex = (uint)(((grePayload[13] & 15) << 16) |
                (grePayload[14] << 8) | grePayload[15]);

            observation = new ErspanTypeIIObservation(
                vlan, classOfService, encapsulationKind, truncated,
                sessionId, BinaryPrimitives.ReadUInt32BigEndian(
                    grePayload.Slice(4, 4)), portIndex,
                grePayload.Length - mirroredOffset, etherType);
            return true;
        }
    }

    /// <summary>
    /// Unauthenticated, untrusted header metadata only. Sequence, VLAN,
    /// session and port index are not proof of identity, replay, integrity,
    /// packet delivery, or malicious behavior. Mirrored payload is opaque.
    /// </summary>
    public readonly record struct ErspanTypeIIObservation(
        ushort VlanId,
        byte ClassOfService,
        byte EncapsulationKind,
        bool Truncated,
        ushort SessionId,
        uint SequenceNumber,
        uint PortIndex,
        int MirroredFrameBytes,
        ushort MirroredEtherType);
}
