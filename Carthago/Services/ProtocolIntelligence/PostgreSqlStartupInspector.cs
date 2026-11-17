// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>Strict PostgreSQL startup-frame evidence only; not proof of authentication.</summary>
    public static class PostgreSqlStartupInspector
    {
        public const int MaxStartupBytes = 8192;
        public static bool IsCompleteStartup(ReadOnlySpan<byte> bytes, bool completeCapture, bool verifiedPlaintext)
        {
            if (!completeCapture || !verifiedPlaintext || bytes.Length < 9 || bytes.Length > MaxStartupBytes)
                return false;
            int length = BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(0, 4));
            if (length != bytes.Length || BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(4, 4)) != 196608)
                return false; // PostgreSQL protocol 3.0; reject SSLRequest/GSSENCRequest and CancelRequest.
            int index = 8;
            bool user = false, database = false;
            while (index < bytes.Length)
            {
                if (bytes[index] == 0)
                    return index == bytes.Length - 1 && user;
                int keyStart = index;
                while (index < bytes.Length && bytes[index] != 0) index++;
                if (index == bytes.Length || index == keyStart) return false;
                var key = bytes.Slice(keyStart, index - keyStart);
                index++;
                int valueStart = index;
                while (index < bytes.Length && bytes[index] != 0) index++;
                if (index == bytes.Length || index == valueStart) return false;
                var value = bytes.Slice(valueStart, index - valueStart);
                for (int i = 0; i < value.Length; i++)
                    if (value[i] < 0x20 || value[i] > 0x7e) return false;
                if (key.SequenceEqual("user"u8)) { if (user) return false; user = true; }
                if (key.SequenceEqual("database"u8)) { if (database) return false; database = true; }
                index++;
            }
            return false;
        }
    }
}
