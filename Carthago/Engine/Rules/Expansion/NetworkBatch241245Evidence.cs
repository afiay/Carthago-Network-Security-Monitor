// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // Parsed operations and HTTP request metadata, never packet Info or proven transfer completion.
    internal static class NetworkBatch241245Evidence
    {
        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168)
                || b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }
        private static bool Udp(TrafficRecord r)
            => r.Id != Guid.Empty && r.IsUdp && !r.IsTcp && !r.IsQuic
                && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                && r.TlsVersion == null && r.HttpMethod == null && r.DnsQname == null
                && IPAddress.TryParse(r.Source, out var src) && IPAddress.TryParse(r.Destination, out var dst)
                && src.AddressFamily == dst.AddressFamily && !src.Equals(dst);
        internal static bool Bacnet(TrafficRecord r, out string operation)
        {
            operation = "";
            if (!Udp(r) || r.SourcePort != 47808 && r.DestinationPort != 47808) return false;
            if (string.Equals(r.ApplicationProtocol, "bacnet.whois", StringComparison.OrdinalIgnoreCase)) operation = "whois";
            else if (string.Equals(r.ApplicationProtocol, "bacnet.iam", StringComparison.OrdinalIgnoreCase)) operation = "iam";
            return operation.Length > 0;
        }
        internal static bool NtpMonlist(TrafficRecord r)
            => Udp(r) && r.DestinationPort == 123 && r.SourcePort != 123
                && string.Equals(r.ApplicationProtocol, "ntp.mode7.monlist", StringComparison.OrdinalIgnoreCase);
        private static bool Approved(string? p)
            => p != null && new[] { "onedrive.exe", "veeamagent.exe", "rclone-approved", "rsync-approved" }
                .Any(x => p.Equals(x, StringComparison.OrdinalIgnoreCase));
        internal static bool Upload(TrafficRecord r, out string file, out long declared)
        {
            file = ""; declared = 0;
            if (!NetworkBatch131135Evidence.CleartextHttpRequest(r)
                || !NetworkBatch156165Evidence.UriOf(r, out var uri)
                || r.HttpMethod is not ("POST" or "PUT" or "PATCH")
                || !Private(r.Source) || !NetworkBatch226230Evidence.Public(r.Destination)
                || Approved(r.ProcessName) || r.Sni != null
                || !NetworkBatch166170Evidence.Header(r, "Content-Length", out var value)
                || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out declared)
                || declared is <= 0 or > 10_737_418_240L) return false;
            var path = uri.AbsolutePath;
            if (path.Length is < 5 or > 512 || path.Contains('%') || path.Contains("//")) return false;
            var last = path.Split('/').Last();
            if (last.Length is < 5 or > 128 || !last.Contains('.')
                || last.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'))) return false;
            file = last.ToLowerInvariant();
            return true;
        }
        internal static bool Archive(TrafficRecord r)
            => Upload(r, out var file, out var declared) && declared >= 100L * 1024 * 1024
                && new[] { ".zip", ".7z", ".rar", ".tar", ".tgz", ".tar.gz" }
                    .Any(x => file.EndsWith(x, StringComparison.Ordinal));
        internal static bool DatabaseDump(TrafficRecord r)
        {
            if (!Upload(r, out var file, out _)) return false;
            var name = file.Split('.')[0];
            return (name.Contains("dump", StringComparison.Ordinal) || name.Contains("backup", StringComparison.Ordinal)
                    || name.Contains("export", StringComparison.Ordinal))
                && new[] { ".sql", ".sql.gz", ".dump", ".bak", ".sqlite3", ".bson" }
                    .Any(x => file.EndsWith(x, StringComparison.Ordinal));
        }
        internal static bool Sensitive(TrafficRecord r)
        {
            if (!Upload(r, out var file, out _)) return false;
            return new[] { "id_rsa", "credentials", "secrets", "private-key", "passwords", "api_key", "apikey" }
                .Any(x => file.StartsWith(x + ".", StringComparison.Ordinal))
                || new[] { ".pem", ".key", ".pfx", ".p12", ".kdbx", ".env", ".ppk", ".vault" }
                    .Any(x => file.EndsWith(x, StringComparison.Ordinal));
        }
    }
}
