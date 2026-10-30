// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Recognizes only exact 8-octet AMQP connection prefaces at a trusted
    /// plaintext connection-start boundary: 0-9-1, 1.0, and 1.0 SASL.
    /// A header does not establish broker acceptance, authentication,
    /// message publication, consumption, or application payload visibility.
    /// ISOLATED: no stream/capture producer or runtime registration.
    /// </summary>
    public static class AmqpConnectionHeaderInspector
    {
        private const int HeaderLength = 8;
        private const int MaxInputBytes = 4_096;

        public static bool TryInspect(
            ReadOnlySpan<byte> bytes,
            bool verifiedPlaintextConnectionStart,
            out AmqpConnectionHeaderObservation observation)
        {
            observation = default;
            if (!verifiedPlaintextConnectionStart || bytes.Length < HeaderLength
                || bytes.Length > MaxInputBytes
                || !bytes.Slice(0, 4).SequenceEqual("AMQP"u8))
                return false;

            AmqpHeaderKind kind;
            if (bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 9 && bytes[7] == 1)
                kind = AmqpHeaderKind.Amqp091;
            else if (bytes[4] == 0 && bytes[5] == 1 && bytes[6] == 0 && bytes[7] == 0)
                kind = AmqpHeaderKind.Amqp10;
            else if (bytes[4] == 3 && bytes[5] == 1 && bytes[6] == 0 && bytes[7] == 0)
                kind = AmqpHeaderKind.Amqp10Sasl;
            else
                return false;

            observation = new(kind, HeaderLength);
            return true;
        }
    }

    public enum AmqpHeaderKind
    {
        Amqp091 = 1,
        Amqp10 = 2,
        Amqp10Sasl = 3
    }

    /// <summary>Untrusted connection-preface shape, not a negotiated session.</summary>
    public readonly record struct AmqpConnectionHeaderObservation(
        AmqpHeaderKind Kind,
        int BytesConsumed);
}
