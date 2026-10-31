// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only MQTT-SN v1.2 UDP message envelope inspector (selected message types).
    /// The caller must independently attest an entire plaintext UDP payload.
    /// Native Zigbee/non-IP capture, authentication, gateway state and live registration
    /// are NOT provided. No ClientId, topic, payload, address or raw bytes are retained.
    /// </summary>
    public static class MqttSnDatagramInspector
    {
        private const int MaximumMessageLength = 4096;

        public static bool TryInspect(ReadOnlySpan<byte> payload,
            bool verifiedCompletePlaintextDatagram, out MqttSnObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextDatagram || payload.Length is < 2 or > MaximumMessageLength)
                return false;

            int headerLength;
            int declaredLength;
            if (payload[0] == 0x01)
            {
                if (payload.Length < 4) return false;
                declaredLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(1, 2));
                headerLength = 4;
                // Enforce canonical long form and a finite local inspection limit.
                if (declaredLength <= 255) return false;
            }
            else
            {
                declaredLength = payload[0];
                headerLength = 2;
            }
            if (declaredLength != payload.Length || declaredLength < headerLength)
                return false;

            byte type = payload[headerLength - 1];
            var body = payload.Slice(headerLength);
            MqttSnMessageKind kind;
            bool? clean = null, will = null, retain = null;
            byte? qos = null;
            switch (type)
            {
                case 0x00: // ADVERTISE: GwId(1) + Duration(2)
                    if (body.Length != 3) return false;
                    kind = MqttSnMessageKind.Advertise;
                    break;
                case 0x01: // SEARCHGW: Radius(1)
                    if (body.Length != 1) return false;
                    kind = MqttSnMessageKind.SearchGateway;
                    break;
                case 0x02: // GWINFO: GwId + optional gateway address
                    if (body.Length < 1) return false;
                    kind = MqttSnMessageKind.GatewayInfo;
                    break;
                case 0x04: // CONNECT: Flags, ProtocolId, Duration, ClientId
                    if (body.Length < 4 || body[1] != 0x01 || (body[0] & 0xf3) != 0)
                        return false;
                    kind = MqttSnMessageKind.Connect;
                    clean = (body[0] & 0x04) != 0;
                    will = (body[0] & 0x08) != 0;
                    break;
                case 0x05: // CONNACK: ReturnCode(1)
                    if (body.Length != 1 || body[0] > 3) return false;
                    kind = MqttSnMessageKind.ConnectAcknowledgement;
                    break;
                case 0x0c: // PUBLISH: Flags, TopicId(2), MsgId(2), Data
                    if (body.Length < 5 || (body[0] & 0x0c) != 0
                        || (body[0] & 0x03) == 0x03)
                        return false;
                    kind = MqttSnMessageKind.Publish;
                    retain = (body[0] & 0x10) != 0;
                    qos = (byte)((body[0] >> 5) & 0x03);
                    break;
                case 0x16: // PINGREQ: optional ClientId
                    kind = MqttSnMessageKind.PingRequest;
                    break;
                case 0x17: // PINGRESP: no body
                    if (body.Length != 0) return false;
                    kind = MqttSnMessageKind.PingResponse;
                    break;
                case 0x18: // DISCONNECT: optional Duration(2)
                    if (body.Length is not (0 or 2)) return false;
                    kind = MqttSnMessageKind.Disconnect;
                    break;
                default:
                    // Unsupported message types are NOT identified by a type byte alone.
                    return false;
            }
            observation = new(kind, payload.Length, clean, will, retain, qos);
            return true;
        }
    }

    public enum MqttSnMessageKind : byte
    {
        None, Advertise, SearchGateway, GatewayInfo, Connect,
        ConnectAcknowledgement, Publish, PingRequest, PingResponse, Disconnect
    }

    public readonly record struct MqttSnObservation(
        MqttSnMessageKind Kind, int MessageLength, bool? CleanSession,
        bool? WillRequested, bool? Retain, byte? Qos);
}
