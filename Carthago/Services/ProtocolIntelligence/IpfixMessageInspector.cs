// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 7011 IPFIX v10 message/Set envelope inspection only. A trusted caller
    /// must supply exactly one complete, plaintext, provenance-attested message.
    /// Does not decode Data Records, cache templates, validate exporter identity,
    /// infer flow outcomes, or emit detection events.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class IpfixMessageInspector
    {
        private const int HeaderLength = 16;
        private const int MaximumMessageLength = 65535;
        private const int MaximumSets = 4096;

        public static bool TryInspect(
            ReadOnlySpan<byte> message,
            bool verifiedCompleteMessageBoundary,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            out IpfixEnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompleteMessageBoundary || !verifiedPlaintext ||
                !verifiedCaptureProvenance || message.Length < HeaderLength ||
                message.Length > MaximumMessageLength ||
                BinaryPrimitives.ReadUInt16BigEndian(message) != 10 ||
                BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2)) != message.Length)
                return false;

            int offset = HeaderLength;
            int setCount = 0;
            int templateSetCount = 0;
            int optionsTemplateSetCount = 0;
            int dataSetCount = 0;

            while (offset < message.Length)
            {
                if (setCount == MaximumSets || message.Length - offset < 4)
                    return false;

                ushort setId = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
                int setLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
                if (setLength < 4 || setLength > message.Length - offset ||
                    setId < 2 || (setId > 3 && setId < 256) ||
                    (setId is 2 or 3 && setLength < 8))
                    return false;

                if (setId == 2)
                    templateSetCount++;
                else if (setId == 3)
                    optionsTemplateSetCount++;
                else
                    dataSetCount++;

                setCount++;
                offset += setLength;
            }

            // All values originate in untrusted wire bytes, even with a trusted
            // sensor. Never interpret them as successful exports or security events.
            observation = new IpfixEnvelopeObservation(
                BinaryPrimitives.ReadUInt32BigEndian(message.Slice(4, 4)),
                BinaryPrimitives.ReadUInt32BigEndian(message.Slice(8, 4)),
                BinaryPrimitives.ReadUInt32BigEndian(message.Slice(12, 4)),
                setCount,
                templateSetCount,
                optionsTemplateSetCount,
                dataSetCount);
            return true;
        }
    }

    /// <summary>
    /// Bounded unverified wire-envelope metadata. No raw data, exporter
    /// identity, IP addresses, field contents, or decoded flow records.
    /// </summary>
    public readonly record struct IpfixEnvelopeObservation(
        uint ExportTimeUnverified,
        uint SequenceNumberUnverified,
        uint ObservationDomainIdUnverified,
        int SetCount,
        int TemplateSetCount,
        int OptionsTemplateSetCount,
        int DataSetCount);
}
