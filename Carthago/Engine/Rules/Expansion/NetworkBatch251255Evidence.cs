// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Request-shape only: no decrypted HTTPS, multipart body, TCP delivered-byte
    // counter, verified local timezone or external domain-registration age.
    internal static class NetworkBatch251255Evidence
    {
        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168)
                || b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }
        internal static bool HttpUpload(TrafficRecord r)
            => r.Id != Guid.Empty && Private(r.Source)
                && NetworkBatch226230Evidence.Public(r.Destination)
                && NetworkBatch131135Evidence.CleartextHttpRequest(r)
                && NetworkBatch156165Evidence.Authority(r)
                && NetworkBatch156165Evidence.UriOf(r, out _)
                && r.HttpMethod is "POST" or "PUT" or "PATCH";

        internal static bool Declared(TrafficRecord r, out long bytes)
        {
            bytes = 0;
            return NetworkBatch166170Evidence.Header(r, "Content-Length", out var value)
                && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out bytes)
                && bytes > 0 && bytes <= 10_737_418_240L;
        }
        private static bool HostRoot(string? host, string root)
            => host != null && (host.Equals(root, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + root, StringComparison.OrdinalIgnoreCase));
        internal static bool UnknownHost(TrafficRecord r)
        {
            var host = r.HttpHost;
            if (string.IsNullOrWhiteSpace(host) || host!.Length > 253
                || IPAddress.TryParse(host, out _) || !host.Contains('.')
                || host.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-'))
                || host.StartsWith('.') || host.EndsWith('.') || host.Contains(".."))
                return false;
            return !new[] { "github.com", "gitlab.com", "google.com", "googleapis.com",
                "microsoft.com", "sharepoint.com", "onedrive.com", "dropbox.com",
                "box.com", "slack.com", "amazonaws.com", "icloud.com" }
                .Any(root => HostRoot(host, root));
        }
        internal static bool AutomationProcess(TrafficRecord r)
        {
            var process = r.ProcessName?.Trim();
            return process != null && new[] { "curl.exe", "wget.exe", "python.exe",
                "powershell.exe", "pwsh.exe", "rclone.exe" }
                .Any(p => process.Equals(p, StringComparison.OrdinalIgnoreCase));
        }

        // First observed by this detector instance and source, NOT a durable
        // approved baseline or domain-registration novelty assertion.
        internal sealed class FirstObservedWindow
        {
            private readonly object _gate = new();
            private readonly System.Collections.Generic.Dictionary<string, DateTime> _seen =
                new(StringComparer.OrdinalIgnoreCase);
            internal bool Observe(TrafficRecord r, DateTime at)
            {
                if (r.Id == Guid.Empty || string.IsNullOrWhiteSpace(r.Source)
                    || string.IsNullOrWhiteSpace(r.HttpHost)) return false;
                var key = r.Source + "|" + r.HttpHost;
                lock (_gate)
                {
                    if (_seen.ContainsKey(key)) return false;
                    if (_seen.Count >= 2048)
                    {
                        foreach (var old in _seen.Where(e => at - e.Value > TimeSpan.FromHours(24))
                            .Select(e => e.Key).ToArray()) _seen.Remove(old);
                        if (_seen.Count >= 2048) return false;
                    }
                    _seen.Add(key, at);
                    return true;
                }
            }
        }

        internal static bool Multipart(TrafficRecord r)
        {
            if (!HttpUpload(r) || !UnknownHost(r)
                || !NetworkBatch166170Evidence.Header(r, "Content-Type", out var value)
                || !value.StartsWith("multipart/form-data;", StringComparison.OrdinalIgnoreCase))
                return false;
            var parts = value.Split(';');
            if (parts.Length != 2) return false;
            var parameter = parts[1].Trim();
            if (!parameter.StartsWith("boundary=", StringComparison.OrdinalIgnoreCase)) return false;
            var boundary = parameter[9..].Trim('"');
            return boundary.Length is >= 8 and <= 70
                && boundary.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
        }
        internal static bool HighEntropy(TrafficRecord r, out double entropy)
        {
            entropy = 0;
            if (!HttpUpload(r) || !NetworkBatch156165Evidence.Path(r, out var path)) return false;
            foreach (var token in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                if (token.Length is < 32 or > 256 || !token.All(char.IsAsciiLetterOrDigit)) continue;
                var groups = token.GroupBy(c => c);
                var h = 0.0;
                foreach (var group in groups)
                {
                    var p = (double)group.Count() / token.Length;
                    h -= p * Math.Log(p, 2);
                }
                if (h > entropy) entropy = h;
            }
            return entropy >= 4.2;
        }
        internal static bool EncodedQuery(TrafficRecord r)
        {
            if (!HttpUpload(r) || !NetworkBatch156165Evidence.UriOf(r, out var uri)
                || uri.Query.Length is < 90 or > 1536) return false;
            foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var at = part.IndexOf('=');
                if (at < 1) continue;
                var name = part[..at];
                if (name is not ("data" or "payload" or "blob")) continue;
                string value;
                try { value = Uri.UnescapeDataString(part[(at + 1)..]); }
                catch (UriFormatException) { continue; }
                if (value.Length is < 88 or > 1024
                    || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=' or '-' or '_')))
                    continue;
                try
                {
                    var raw = value.Replace('-', '+').Replace('_', '/');
                    raw = raw.PadRight((raw.Length + 3) / 4 * 4, '=');
                    var bytes = Convert.FromBase64String(raw);
                    if (bytes.Length >= 64 && bytes.Distinct().Take(12).Count() == 12) return true;
                }
                catch (FormatException) { }
            }
            return false;
        }
        internal static bool Chunk(TrafficRecord r, out long declared, out string pathKey)
        {
            declared = 0; pathKey = "";
            if (!HttpUpload(r) || !Declared(r, out declared) || declared > 128L * 1024
                || !NetworkBatch156165Evidence.Path(r, out var path)
                || path.Length is < 2 or > 256) return false;
            pathKey = NetworkBatch131135Evidence.Fingerprint(path);
            return true;
        }
        internal static bool OffHoursDeclared(TrafficRecord r, DateTime at, out long declared)
        {
            declared = 0;
            // Explicitly UTC, not inferred local business hours.
            if (at.Hour is >= 6 and < 20 && at.DayOfWeek is not (DayOfWeek.Saturday or DayOfWeek.Sunday))
                return false;
            return HttpUpload(r) && Declared(r, out declared)
                && declared >= 250L * 1024 * 1024;
        }
    }
}
