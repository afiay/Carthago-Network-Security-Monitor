// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated MQTT 3.1.1 CONNECT/CONNACK shape verifier for R451.
    /// Requires independently established complete, plaintext, same-flow bidirectional frames.
    /// Anonymous CONNECT plus accepted CONNACK is a protocol observation, not proof
    /// of unauthorized access, verified broker identity, or malicious intent.
    /// </summary>
    public static class MqttAnonymousConnectInspector
    {
        public static bool TryInspect(
            ReadOnlySpan<byte> connect,
            ReadOnlySpan<byte> connack,
            bool completePlaintextSameFlow,
            out MqttAnonymousConnectObservation observation)
        {
            observation = default;
            if (!completePlaintextSameFlow || connect.Length < 14 || connect.Length > 4096
                || connack.Length != 4 || connect[0] != 0x10 || connack[0] != 0x20
                || connack[1] != 2 || connack[2] != 0 || connack[3] > 5)
                return false;

            int position = 1, multiplier = 1, remaining = 0;
            bool terminated = false;
            for (int i = 0; i < 4; i++)
            {
                if (position >= connect.Length) return false;
                byte encoded = connect[position++];
                remaining += (encoded & 0x7f) * multiplier;
                if ((encoded & 0x80) == 0) { terminated = true; break; }
                multiplier *= 128;
            }
            if (!terminated || remaining != connect.Length - position || remaining < 12)
                return false;

            if (connect[position++] != 0 || connect[position++] != 4
                || !connect.Slice(position, 4).SequenceEqual("MQTT"u8))
                return false;
            position += 4;
            if (connect[position++] != 4) return false; // MQTT 3.1.1 only
            byte flags = connect[position++];
            if ((flags & 1) != 0 || (flags & 0xc0) != 0) return false;
            bool cleanSession = (flags & 0x02) != 0;
            if ((flags & 0x04) == 0 && (flags & 0x38) != 0) return false;
            if ((flags & 0x04) != 0 && (flags & 0x18) == 0x18) return false;
            position += 2; // keepalive
            if (position + 2 > connect.Length) return false;
            int clientLength = (connect[position++] << 8) | connect[position++];
            if (clientLength == 0 || position + clientLength > connect.Length) return false;
            // MQTT 3.1.1 ClientId is UTF-8. Reject invalid encodings and forbidden NUL.
            var clientId = connect.Slice(position, clientLength);
            if (clientId.IndexOf((byte)0) >= 0) return false;
            try
            {
                _ = new System.Text.UTF8Encoding(false, true).GetString(clientId);
            }
            catch (System.Text.DecoderFallbackException)
            {
                return false;
            }
            position += clientLength;

            // A strict no-Will anonymous CONNECT must contain exactly the client ID.
            if ((flags & 0x04) != 0 || position != connect.Length) return false;
            // CONNACK bit 0 is Session Present; reserved bits must be zero.
            // Rejected connections and clean sessions cannot resume a prior session.
            byte ackFlags = connack[2];
            if ((ackFlags & 0xfe) != 0 || ((ackFlags & 1) != 0 && (cleanSession || connack[3] != 0)))
                return false;
            observation = new MqttAnonymousConnectObservation(connack[3] == 0, connack[3]);
            return true;
        }
    }

    public readonly record struct MqttAnonymousConnectObservation(bool BrokerAccepted, byte ReturnCode);
}
