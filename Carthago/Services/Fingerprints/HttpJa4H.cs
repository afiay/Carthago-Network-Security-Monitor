// SPDX-License-Identifier: MIT
// File: Services/Fingerprints/HttpJa4H.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.Fingerprints
{
    /// <summary>
    /// Very compact HTTP stack fingerprint: method + HTTP version + ordered header names (lowercased) + UA family bucket.
    /// Produces a stable SHA256-8 (first 8 hex) tag for readability, plus the readable core string.
    /// </summary>
    public static class HttpJa4H
    {
        public static (string readable, string tag) Compute(string? method, string? httpVersion, IReadOnlyList<string> headerNames, string? userAgent)
        {
            method ??= "?";
            httpVersion ??= "?";
            var headers = (headerNames?.Count ?? 0) == 0 ? "-" : string.Join(",", (headerNames ?? Enumerable.Empty<string>()).Select(h => h.ToLowerInvariant()));
            string uaBucket = BucketUA(userAgent);

            var core = $"{method}|{httpVersion}|{headers}|{uaBucket}";
            using var sha = SHA256.Create();
            var tag = Convert.ToHexString(sha.ComputeHash(Encoding.ASCII.GetBytes(core))).ToLowerInvariant()[..8];
            return ($"h:{core}", tag);
        }

        private static string BucketUA(string? ua)
        {
            if (string.IsNullOrWhiteSpace(ua)) return "ua:none";
            var s = ua.ToLowerInvariant();
            if (s.Contains("chrome/")) return "ua:chrome";
            if (s.Contains("edg/")) return "ua:edge";
            if (s.Contains("firefox/")) return "ua:firefox";
            if (s.Contains("safari/") && !s.Contains("chrome/")) return "ua:safari";
            if (s.Contains("curl/")) return "ua:curl";
            if (s.Contains("wget/")) return "ua:wget";
            return "ua:other";
        }
    }
}
