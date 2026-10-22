// SPDX-License-Identifier: MIT
// File: Services/Fingerprints/TlsJa4.cs
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.Fingerprints
{
    /// <summary>
    /// Lightweight JA4-like TLS client/server fingerprint.
    /// Reads a full TLS handshake record and builds a normalized core string
    /// from version, cipher list, extension list, groups, sigalgs, and ALPN.
    /// Output: "t:<core>|<sha8>". Server side replaces 't:' with 'ts:'.
    /// </summary>
    public static class TlsJa4
    {
        public static string FromClientHello(ReadOnlySpan<byte> tlsRecord)
        {
            if (tlsRecord.Length < 5 || tlsRecord[0] != 0x16) return string.Empty;
            // Skip record header
            var body = tlsRecord.Slice(5);
            if (body.Length < 4 || body[0] != 0x01) return string.Empty;

            var (legacyVer, ciphers, exts, groups, sigalgs, alpn) = ParseClientHello(body);
            string core = $"v:{legacyVer};cs:{JoinU16(ciphers)};ex:{JoinU16(exts)};grp:{JoinU16(groups)};sig:{JoinU16(sigalgs)};alpn:{alpn}";
            string tag = Sha8(core);
            return $"t:{core}|{tag}";
        }

        public static string FromServerHello(ReadOnlySpan<byte> tlsRecord)
        {
            if (tlsRecord.Length < 5 || tlsRecord[0] != 0x16) return string.Empty;
            var body = tlsRecord.Slice(5);
            if (body.Length < 4 || body[0] != 0x02) return string.Empty;

            // For server, we have negotiated version/cipher and extensions (shorter)
            int hsLen = (body[1] << 16) | (body[2] << 8) | body[3];
            if (hsLen + 4 > body.Length) return string.Empty;
            var span = body.Slice(4);
            if (span.Length < 2 + 32 + 1 + 2) return string.Empty;

            ushort legacyVer = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(0, 2));
            int idx = 2 + 32; // version + random
            if (idx >= span.Length) return string.Empty;

            // session id
            byte sidLen = span[idx++];
            idx += sidLen;
            if (idx + 2 > span.Length) return string.Empty;
            ushort cipher = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2));
            idx += 2;

            // compression methods
            if (idx >= span.Length) return string.Empty;
            byte compLen = span[idx++];
            idx += compLen;

            List<ushort> exts = new();
            if (idx + 2 <= span.Length)
            {
                ushort extTotal = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
                if (idx + extTotal <= span.Length)
                {
                    int exEnd = idx + extTotal;
                    while (idx + 4 <= exEnd)
                    {
                        ushort et = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2));
                        ushort elen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx + 2, 2));
                        idx += 4 + elen;
                        exts.Add(et);
                    }
                }
            }

            string core = $"v:{legacyVer};cs:{cipher};ex:{string.Join("-", exts)}";
            string tag = Sha8(core);
            return $"ts:{core}|{tag}";
        }

        private static (ushort legacyVer, List<ushort> ciphers, List<ushort> exts, List<ushort> groups, List<ushort> sigalgs, string alpn)
            ParseClientHello(ReadOnlySpan<byte> body)
        {
            int hsLen = (body[1] << 16) | (body[2] << 8) | body[3];
            var span = body.Slice(4);
            ushort legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(0, 2));

            int idx = 2 + 32;
            byte sidLen = span[idx++]; idx += sidLen;

            ushort csLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
            var cipherSpan = span.Slice(idx, csLen); idx += csLen;

            byte compLen = span[idx++]; idx += compLen;

            List<ushort> exts = new();
            List<ushort> groups = new();
            List<ushort> sigalgs = new();
            string alpn = "-";

            if (idx + 2 <= span.Length)
            {
                ushort extTotal = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
                int end = idx + extTotal;
                while (idx + 4 <= end)
                {
                    ushort etype = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2));
                    ushort elen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx + 2, 2));
                    idx += 4;
                    if (idx + elen > end) break;
                    var ext = span.Slice(idx, elen);
                    idx += elen;

                    exts.Add(etype);
                    if (etype == 0x0010) // ALPN
                    {
                        if (ext.Length >= 3)
                        {
                            int p = 2; byte l = ext[p++];
                            if (p + l <= ext.Length) alpn = Encoding.ASCII.GetString(ext.Slice(p, l));
                        }
                    }
                    else if (etype == 0x000A) // supported_groups
                    {
                        if (ext.Length >= 2)
                        {
                            int p = 2;
                            while (p + 2 <= ext.Length)
                            {
                                groups.Add(BinaryPrimitives.ReadUInt16BigEndian(ext.Slice(p, 2)));
                                p += 2;
                            }
                        }
                    }
                    else if (etype == 0x000D) // signature_algorithms
                    {
                        if (ext.Length >= 2)
                        {
                            int p = 2;
                            while (p + 2 <= ext.Length)
                            {
                                sigalgs.Add(BinaryPrimitives.ReadUInt16BigEndian(ext.Slice(p, 2)));
                                p += 2;
                            }
                        }
                    }
                }
            }

            return (legacyVersion, SplitU16(cipherSpan), exts, groups, sigalgs, alpn);
        }

        private static List<ushort> SplitU16(ReadOnlySpan<byte> s)
        {
            var list = new List<ushort>(Math.Max(1, s.Length / 2));
            for (int i = 0; i + 1 < s.Length; i += 2)
                list.Add(BinaryPrimitives.ReadUInt16BigEndian(s.Slice(i, 2)));
            return list;
        }

        private static string JoinU16(List<ushort> v) => v.Count == 0 ? "-" : string.Join("-", v);
        private static string Sha8(string s)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(Encoding.ASCII.GetBytes(s))).ToLowerInvariant()[..8];
        }
    }
}
