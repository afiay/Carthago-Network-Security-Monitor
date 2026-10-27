// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text.RegularExpressions;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // R166-R170: typed HTTP with authority consistency. Never promote packet
    // Info into a request-body observation or emit sensitive URI values.
    internal static class NetworkBatch166170Evidence
    {
        internal static bool Http(TrafficRecord r)
            => NetworkBatch156165Evidence.Http(r) && Path(r, out _);
        internal static bool Inbound(TrafficRecord r)
            => NetworkBatch126130Evidence.CrossBoundary(r, out _, out var inbound) && inbound;
        internal static bool Path(TrafficRecord r, out string path)
        {
            path = "";
            if (!NetworkBatch156165Evidence.Path(r, out var encoded)) return false;
            try { path = Uri.UnescapeDataString(encoded); }
            catch (UriFormatException) { return false; }
            return path.Length is > 0 and <= 512 && !path.Contains('%')
                && !path.Contains('\\') && !path.Contains("/../", StringComparison.Ordinal)
                && !path.Contains("/./", StringComparison.Ordinal);
        }
        internal static bool Secret(TrafficRecord r)
        {
            if (!Path(r, out var p)) return false;
            return p.ToLowerInvariant() is "/.env" or "/.env.local" or "/.env.production"
                or "/.env.prod" or "/.env.development" or "/.env.staging"
                or "/.aws/credentials" or "/appsettings.json"
                or "/appsettings.production.json" or "/config/secrets.yml"
                or "/database.yml";
        }
        internal static bool Git(TrafficRecord r)
        {
            if (!Path(r, out var p)) return false;
            var s = p.ToLowerInvariant();
            return s is "/.git/config" or "/.git/head" or "/.git/index"
                or "/.git/packed-refs" or "/.git/description"
                || s.StartsWith("/.git/refs/", StringComparison.Ordinal)
                || s.StartsWith("/.git/objects/", StringComparison.Ordinal)
                || s.StartsWith("/.git/logs/", StringComparison.Ordinal);
        }
        private static readonly Regex BackupName = new(
            @"(?:^|[._-])(?:backup|dump|database|db)(?:[._-]|$)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        internal static bool Backup(TrafficRecord r)
        {
            if (!Path(r, out var p)) return false;
            var n = p.Split('/').LastOrDefault() ?? "";
            var ext = new[] { ".bak", ".backup", ".sql", ".sql.gz", ".tar.gz", ".tgz", ".zip", ".7z" };
            return n.Length is >= 7 and <= 160 && BackupName.IsMatch(n)
                && ext.Any(x => n.EndsWith(x, StringComparison.OrdinalIgnoreCase));
        }
        internal static bool AdminFailure(TrafficRecord r)
        {
            if (!Http(r) || !string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                || !Path(r, out var p)) return false;
            var login = p.ToLowerInvariant() is "/admin/login" or "/wp-login.php"
                or "/administrator/login" or "/user/login" or "/manager/html"
                or "/admin/signin" or "/api/admin/login";
            return login && NetworkBatch131135Evidence.AuthenticationFailure(r, p);
        }
        internal static bool XxeQuery(TrafficRecord r)
        {
            if (!Http(r) || !NetworkBatch156165Evidence.UriOf(r, out var uri)
                || uri.Query.Length is < 12 or > 2048 || !Header(r, "Content-Type", out var type)
                || !(type.StartsWith("text/xml", StringComparison.OrdinalIgnoreCase)
                    || type.StartsWith("application/xml", StringComparison.OrdinalIgnoreCase)
                    || type.StartsWith("application/soap+xml", StringComparison.OrdinalIgnoreCase)))
                return false;
            string q;
            try { q = Uri.UnescapeDataString(uri.Query); }
            catch (UriFormatException) { return false; }
            // TrafficRecord has no request-body field. Query-encoded XML is
            // observable; Info-only XML descriptions are not payload evidence.
            return q.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
                && q.Contains("<!ENTITY", StringComparison.OrdinalIgnoreCase)
                && q.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase)
                && (q.Contains("file://", StringComparison.OrdinalIgnoreCase)
                    || q.Contains("http://", StringComparison.OrdinalIgnoreCase)
                    || q.Contains("https://", StringComparison.OrdinalIgnoreCase));
        }
        internal static bool Header(TrafficRecord r, string name, out string value)
        {
            value = "";
            if (string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                || r.HttpRequestHeaders!.Length > 8192) return false;
            bool found = false;
            foreach (var line in r.HttpRequestHeaders.Split('\n'))
            {
                int colon = line.IndexOf(':');
                if (colon < 1 || !line[..colon].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (found) return false;
                value = line[(colon + 1)..].Trim();
                found = true;
            }
            return found && value.Length is > 0 and <= 1024;
        }
        internal static string Key(string value)
            => NetworkBatch131135Evidence.Fingerprint(value);
    }
}
