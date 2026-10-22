// SPDX-License-Identifier: MIT
// File: Services/Fingerprints/Hassh.cs
//
// Purpose: HASSH / HASSHServer fingerprints for SSH from SSH_MSG_KEXINIT payloads.
// Reference: https://github.com/salesforce/hassh
//
// This file parses a KEXINIT payload and constructs the semicolon-delimited
// algorithms string which is then MD5 hashed (lowercase hex) per the HASSH spec.

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.Fingerprints
{
    public static class Hassh
    {
        public static bool TryComputeClient(ReadOnlySpan<byte> kexInitPayload, out string hassh, out string algString)
            => TryCompute(kexInitPayload, client: true, out hassh, out algString);

        public static bool TryComputeServer(ReadOnlySpan<byte> kexInitPayload, out string hasshServer, out string algString)
            => TryCompute(kexInitPayload, client: false, out hasshServer, out algString);

        private static bool TryCompute(ReadOnlySpan<byte> payload, bool client, out string hash, out string algs)
        {
            hash = string.Empty; algs = string.Empty;
            // SSH_MSG_KEXINIT = 0x14 as first byte in the payload (after packet framing).
            if (payload.Length < 1 || payload[0] != 0x14) return false;

            int p = 1; // after msg code
            if (p + 16 > payload.Length) return false; // cookie
            p += 16;

            // name-list helper
            static string ReadNameList(ReadOnlySpan<byte> buf, ref int idx)
            {
                if (idx + 4 > buf.Length) return string.Empty;
                uint n = BinaryPrimitives.ReadUInt32BigEndian(buf.Slice(idx, 4)); idx += 4;
                if (idx + n > buf.Length) return string.Empty;
                var s = Encoding.ASCII.GetString(buf.Slice(idx, (int)n));
                idx += (int)n;
                return s;
            }

            var kex = ReadNameList(payload, ref p);
            var hostKey = ReadNameList(payload, ref p);
            var enc_C2S = ReadNameList(payload, ref p);
            var enc_S2C = ReadNameList(payload, ref p);
            var mac_C2S = ReadNameList(payload, ref p);
            var mac_S2C = ReadNameList(payload, ref p);
            var comp_C2S = ReadNameList(payload, ref p);
            var comp_S2C = ReadNameList(payload, ref p);
            _ = ReadNameList(payload, ref p); // languages c2s
            _ = ReadNameList(payload, ref p); // languages s2c

            if (p + 1 > payload.Length) return false; // first_kex_packet_follows
            p += 1;
            if (p + 4 > payload.Length) return false; // reserved
            p += 4;

            if (client)
                algs = $"{kex};{hostKey};{enc_C2S};{mac_C2S};{comp_C2S}";
            else
                algs = $"{kex};{hostKey};{enc_S2C};{mac_S2C};{comp_S2C}";

            hash = Md5Hex(algs);
            return true;
        }

        private static string Md5Hex(string s)
        {
            using var md5 = MD5.Create();
            var bytes = Encoding.ASCII.GetBytes(s);
            var h = md5.ComputeHash(bytes);
            var sb = new StringBuilder(h.Length * 2);
            foreach (var b in h) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
