// SPDX-License-Identifier: MIT
// File: Engine/PayloadNormalization/PayloadNormalizer.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.PayloadNormalization
{
    public static class PayloadNormalizer
    {
        public static NormalizedPayload FromTrafficRecord(TrafficRecord record, int maxUrlDecodeDepth = 3)
        {
            var fragments = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Add(fragments, "http.method", record.HttpMethod);
            Add(fragments, "http.host", record.HttpHost);
            Add(fragments, "http.uri", record.HttpUri);
            Add(fragments, "http.user_agent", record.HttpUserAgent);
            Add(fragments, "http.headers", record.HttpRequestHeaders);
            Add(fragments, "info", record.Info);
            Add(fragments, "dns.qname", record.DnsQname);
            Add(fragments, "tls.sni", record.Sni);
            var original = string.Join("\n", fragments.Select(kv => $"[{kv.Key}] {kv.Value}"));
            var normalized = original;
            for (var i = 0; i < Math.Max(1, maxUrlDecodeDepth); i++)
            {
                var decoded = SafeUrlDecode(normalized);
                if (string.Equals(decoded, normalized, StringComparison.Ordinal)) break;
                normalized = decoded;
            }
            normalized = WebUtility.HtmlDecode(normalized) ?? normalized;
            normalized = normalized.Replace('\\', '/');
            normalized = Regex.Replace(normalized, @"\s+", " ");
            normalized = Regex.Replace(normalized, @"(?i)\$\{\s*lower\s*:\s*([a-z0-9])\s*\}", "$1");
            normalized = Regex.Replace(normalized, @"(?i)\$\{\s*upper\s*:\s*([a-z0-9])\s*\}", "$1");
            normalized = Regex.Replace(normalized, @"(?i)[`'""\s]+", " ");
            return new NormalizedPayload(original, normalized.Trim(), normalized.ToLowerInvariant(), fragments);
        }

        private static string SafeUrlDecode(string input)
        {
            try { return WebUtility.UrlDecode(input) ?? input; }
            catch { return input; }
        }

        private static void Add(IDictionary<string, string> map, string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value)) map[key] = value.Trim();
        }
    }
}
