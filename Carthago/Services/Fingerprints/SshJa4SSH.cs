// SPDX-License-Identifier: MIT
// File: Services/Fingerprints/SshJa4SSH.cs
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.Fingerprints
{
    public static class SshJa4SSH
    {
        /// <summary>
        /// Compute from SSH banner + KEXINIT lists when available.
        /// We accept partial input: if only banner, we fingerprint banner family.
        /// Output "ssh:<core>|<sha8>"
        /// </summary>
        public static string From(string? banner, string? kexAlgs, string? encCS, string? macCS)
        {
            banner ??= "-";
            kexAlgs ??= "-";
            encCS ??= "-";
            macCS ??= "-";
            var core = $"b:{banner};k:{kexAlgs};e:{encCS};m:{macCS}";
            return $"ssh:{core}|{Sha8(core)}";
        }

        public static string Hassh(string? kexAlgs, string? encCS, string? macCS, string? compCS)
        {
            // Classic HASSH is MD5 of "kexAlgs;encCS;macCS;compCS"
            string baseStr = $"{kexAlgs ?? ""};{encCS ?? ""};{macCS ?? ""};{compCS ?? ""}";
            using var md5 = MD5.Create();
            return Convert.ToHexString(md5.ComputeHash(Encoding.ASCII.GetBytes(baseStr))).ToLowerInvariant();
        }

        private static string Sha8(string s)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(Encoding.ASCII.GetBytes(s))).ToLowerInvariant()[..8];
        }
    }
}
