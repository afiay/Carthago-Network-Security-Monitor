// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // One bounded, early IEC 60870-5-104 session sequence; no payload,
    // station address or information-object address retained.
    internal sealed class Iec104StartupOffSequence
    {
        private byte _stage;
        private DateTime _started;
        internal void Reset() { _stage = 0; _started = default; }

        internal bool Observe(ReadOnlySpan<byte> data, bool client, bool first,
            bool complete, DateTime utc)
        {
            if (!complete || utc.Kind != DateTimeKind.Utc)
            { Reset(); return false; }
            if (_stage != 0 && (utc < _started || utc - _started > TimeSpan.FromSeconds(30)))
            { Reset(); return false; }
            if (_stage == 0 && client && first && IsStart(data, 0x07))
            { _stage = 1; _started = utc; return false; }
            if (_stage == 1 && !client && first && IsStart(data, 0x0B))
            { _stage = 2; return false; }
            bool match = _stage == 2 && client && !first && IsOffExecute(data);
            Reset();
            return match;
        }

        private static bool IsStart(ReadOnlySpan<byte> p, byte control)
            => p.Length == 6 && p[0] == 0x68 && p[1] == 4 &&
                p[2] == control && p[3] == 0 && p[4] == 0 && p[5] == 0;

        // Exact first I-format APDU: N(S)=N(R)=0, C_DC_NA_1 (46),
        // one non-sequence object, activation (6), no test/negative bits,
        // originator zero, nonbroadcast common address and nonzero IOA,
        // DCO=1 (OFF, execute, no qualifier).
        internal static bool IsOffExecute(ReadOnlySpan<byte> p)
        {
            if (p.Length != 16 || p[0] != 0x68 || p[1] != 14 ||
                p[2] != 0 || p[3] != 0 || p[4] != 0 || p[5] != 0 ||
                p[6] != 46 || p[7] != 1 || p[8] != 6 || p[9] != 0 ||
                p[15] != 1) return false;
            ushort station = BinaryPrimitives.ReadUInt16LittleEndian(p.Slice(10, 2));
            return station is > 0 and < 65535 && (p[12] != 0 || p[13] != 0 || p[14] != 0);
        }
    }
}
