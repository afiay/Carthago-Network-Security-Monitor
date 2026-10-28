// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Text;

namespace Carthago.Services
{
    // Bounded first-packet parsing, not stream reassembly or proof of action success.
    internal static class NetworkBatch226230Wire
    {
        internal static bool CipListIdentity(ReadOnlySpan<byte> data, int? src, int? dst)
        {
            if (src != 44818 && dst != 44818 || data.Length < 24) return false;
            ushort command = BinaryPrimitives.ReadUInt16LittleEndian(data);
            ushort length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
            uint options = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(20, 4));
            return command == 0x0063 && length == 0 && options == 0 && data.Length == 24;
        }

        private static bool Length(ReadOnlySpan<byte> data, ref int offset, out int length)
        {
            length = 0;
            for (int i = 0; i < 4; i++)
            {
                if (offset >= data.Length) return false;
                byte b = data[offset++];
                length |= (b & 0x7f) << (i * 7);
                if ((b & 0x80) == 0) return length >= 0 && length <= 4096;
            }
            return false;
        }

        private static bool String(ReadOnlySpan<byte> data, ref int offset, out string text)
        {
            text = "";
            if (offset + 2 > data.Length) return false;
            int size = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
            offset += 2;
            if (size == 0 || size > 512 || offset + size > data.Length) return false;
            text = Encoding.UTF8.GetString(data.Slice(offset, size));
            offset += size;
            return text.IndexOf('\0') < 0;
        }

        internal static bool Mqtt(ReadOnlySpan<byte> data, int? src, int? dst,
            out string operation, out string topic, out bool retain)
        {
            operation = ""; topic = ""; retain = false;
            if (src != 1883 && dst != 1883 || data.Length < 5) return false;
            int pos = 1;
            if (!Length(data, ref pos, out int remaining) || remaining != data.Length - pos) return false;
            int type = data[0] >> 4;
            if (type == 3)
            {
                // PUBLISH: QoS 0/1/2 allowed; QoS 3 reserved.
                if (((data[0] >> 1) & 3) == 3 || !String(data, ref pos, out topic)) return false;
                operation = "mqtt.publish";
                retain = (data[0] & 1) != 0;
                return true;
            }
            if (type != 1 || data[0] != 0x10) return false;
            if (!String(data, ref pos, out var protocol) || protocol != "MQTT"
                || pos + 4 > data.Length || data[pos++] != 4) return false;
            byte flags = data[pos++];
            if ((flags & 1) != 0 || (flags & 0x04) == 0 || ((flags >> 3) & 3) == 3)
                return false;
            pos += 2; // keepalive
            if (!String(data, ref pos, out _)) return false; // client identifier
            if (!String(data, ref pos, out topic)) return false; // will topic
            operation = "mqtt.connect";
            return true;
        }
    }
}
