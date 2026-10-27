// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // R126-R130 only. Do not infer protocol identity from packet Info or port alone.
    internal static class NetworkBatch126130Evidence
    {
        private static bool Same(string? value, string expected)
            => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

        private static bool Segment(string path, string segment)
            => path.Equals(segment, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(segment + "/", StringComparison.OrdinalIgnoreCase);

        private static bool Endpoints(TrafficRecord r)
        {
            if (r.Id == Guid.Empty || !r.IsTcp || r.IsUdp || r.IsQuic
                || r.IcmpTypeCode.HasValue || r.DnsQname != null || r.DnsAnswers != null
                || r.DnsIsResponse || r.TcpFlags.HasValue
                    && ((r.TcpFlags.Value & 0x07) != 0 || (r.TcpFlags.Value & 0x18) == 0)
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily)
                return false;
            return r.IpVersion == null
                || r.IpVersion == 4 && src.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        private static bool Internal(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
                return true;
            var b = ip.GetAddressBytes();
            if (b.Length == 4)
                return b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31
                    || b[0] == 192 && b[1] == 168 || b[0] == 169 && b[1] == 254;
            return b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }

        internal static bool CrossBoundary(TrafficRecord r, out bool outbound, out bool inbound)
        {
            outbound = false; inbound = false;
            if (!Endpoints(r) || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)) return false;
            outbound = Internal(src) && !Internal(dst) && !dst.IsIPv6Multicast;
            inbound = !Internal(src) && !src.IsIPv6Multicast && Internal(dst);
            return outbound || inbound;
        }

        internal static bool SshFailure(TrafficRecord r)
        {
            if (!Endpoints(r) || r.HttpMethod != null || r.HttpUri != null
                || r.HttpRequestHeaders != null || r.HttpHost != null
                || !(Same(r.Protocol, "TCP") || Same(r.Protocol, "SSH"))
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "TCP") && !Same(r.ApplicationProtocol, "SSH")
                || r.ApplicationService != null && !Same(r.ApplicationService, "SSH")
                || !(r.DestinationPort == 22 || Same(r.ApplicationProtocol, "SSH") || Same(r.ApplicationService, "SSH")))
                return false;
            var info = r.Info ?? string.Empty;
            return info.Length is > 0 and <= 1024
                && (info.Contains("failed password", StringComparison.OrdinalIgnoreCase)
                    || info.Contains("authentication failed", StringComparison.OrdinalIgnoreCase)
                    || info.Contains("invalid user", StringComparison.OrdinalIgnoreCase))
                && !info.Contains("accepted password", StringComparison.OrdinalIgnoreCase)
                && !info.Contains("login successful", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool HttpRequest(TrafficRecord r)
        {
            if (!Endpoints(r) || string.IsNullOrWhiteSpace(r.HttpHost)
                || string.IsNullOrWhiteSpace(r.HttpUri) || string.IsNullOrWhiteSpace(r.HttpMethod)
                || r.HttpUri!.Length > 2048 || r.HttpHost!.Length > 255
                || !(Same(r.HttpMethod, "GET") || Same(r.HttpMethod, "POST")
                    || Same(r.HttpMethod, "PUT") || Same(r.HttpMethod, "PATCH"))
                || !(Same(r.Protocol, "TCP") || Same(r.Protocol, "HTTP") || Same(r.Protocol, "HTTPS") || Same(r.Protocol, "TLS"))
                || !(Same(r.ApplicationProtocol, "HTTP") || Same(r.ApplicationProtocol, "HTTPS")
                    || Same(r.ApplicationService, "HTTP") || Same(r.ApplicationService, "HTTPS"))
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "TCP")
                    && !Same(r.ApplicationProtocol, "HTTP") && !Same(r.ApplicationProtocol, "HTTPS")
                || r.ApplicationService != null && !Same(r.ApplicationService, "HTTP") && !Same(r.ApplicationService, "HTTPS")
                || r.Sni != null && !Same(r.Sni, r.HttpHost))
                return false;
            if (Uri.TryCreate(r.HttpUri, UriKind.Absolute, out var absolute)
                && !Same(absolute.Host, r.HttpHost!)) return false;
            return true;
        }

        internal static bool AdminPortal(string path)
            => Segment(path, "/admin") || Segment(path, "/administrator")
                || Segment(path, "/wp-admin") || Segment(path, "/manager/html")
                || Segment(path, "/console") || Segment(path, "/manage")
                || Segment(path, "/supervisor") || Segment(path, "/config")
                || Segment(path, "/settings") || Segment(path, "/control");

        private static bool Docs(string path)
            => Segment(path, "/docs") || Segment(path, "/documentation")
                || Segment(path, "/help") || Segment(path, "/support")
                || Segment(path, "/download") || Segment(path, "/manual");

        private static bool VendorHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            var label = host!.Split('.')[0];
            return new[] { "fortigate", "fortinet", "pfsense", "opnsense", "firewall",
                "sonicwall", "mikrotik", "unifi", "meraki", "checkpoint", "netscaler" }
                .Any(x => label.Equals(x, StringComparison.OrdinalIgnoreCase)
                    || label.StartsWith(x + "-", StringComparison.OrdinalIgnoreCase));
        }

        internal static bool VpnApplianceHost(string? host)
            => !string.IsNullOrWhiteSpace(host)
                && new[] { "fortigate", "fortinet", "sonicwall", "netscaler" }
                    .Any(x => host!.Split('.')[0].StartsWith(x, StringComparison.OrdinalIgnoreCase));

        internal static bool AppliancePortal(TrafficRecord r, string path)
            => VendorHost(r.HttpHost) && !Docs(path)
                && (AdminPortal(path) || Segment(path, "/ui")
                    || Segment(path, "/cgi-bin") || Segment(path, "/webvpn")
                    || Segment(path, "/sslvpn") || Segment(path, "/remote/login")
                    || Segment(path, "/login"));

        private static bool CallbackPath(string path)
            => Segment(path, "/signin-oidc") || Segment(path, "/oauth2/callback")
                || Segment(path, "/saml/acs") || Segment(path, "/acs")
                || Segment(path, "/oidc/callback") || Segment(path, "/callback");

        internal static bool SuspiciousCallback(TrafficRecord r, out bool insecureRedirect)
        {
            insecureRedirect = false;
            if (!HttpRequest(r) || !Same(r.HttpMethod, "GET")) return false;
            var value = r.HttpUri!;
            if (!Uri.TryCreate("https://placeholder" + (value.StartsWith("/") ? "" : "/") + value,
                    UriKind.Absolute, out var uri)
                || !CallbackPath(uri.AbsolutePath) || string.IsNullOrWhiteSpace(uri.Query))
                return false;
            bool tokenLeak = false;
            foreach (var item in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var pair = item.Split('=', 2);
                if (pair.Length != 2) continue;
                var name = Uri.UnescapeDataString(pair[0]);
                var param = Uri.UnescapeDataString(pair[1]);
                if (string.IsNullOrWhiteSpace(param)) continue;
                if (Same(name, "SAMLResponse") || Same(name, "id_token") || Same(name, "access_token"))
                    tokenLeak = true;
                if ((Same(name, "redirect_uri") || Same(name, "post_logout_redirect_uri") || Same(name, "RelayState"))
                    && Uri.TryCreate(param, UriKind.Absolute, out var target)
                    && Same(target.Scheme, "http")) insecureRedirect = true;
            }
            return tokenLeak || insecureRedirect;
        }

        internal static bool WebLoginSubmission(TrafficRecord r, string path)
            => HttpRequest(r) && Same(r.HttpMethod, "POST") && !Docs(path)
                && (Segment(path, "/login") || Segment(path, "/signin")
                    || Segment(path, "/auth/login") || Segment(path, "/session")
                    || Segment(path, "/oauth/token"));

        internal static bool ExplicitWebFailure(TrafficRecord r)
        {
            var info = r.Info ?? string.Empty;
            return info.Length <= 1024 && (info.Contains("401 unauthorized", StringComparison.OrdinalIgnoreCase)
                || info.Contains("login failed", StringComparison.OrdinalIgnoreCase)
                || info.Contains("authentication failed", StringComparison.OrdinalIgnoreCase)
                || info.Contains("invalid password", StringComparison.OrdinalIgnoreCase));
        }
    }

    // Per-rule instance state: bounded by key count, event count and time.
    internal sealed class NetworkBatch126130Window
    {
        private sealed class Observation
        {
            internal Guid Id;
            internal DateTime At;
            internal string Identity = string.Empty;
            internal bool Failed;
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, List<Observation>> _windows = new(StringComparer.OrdinalIgnoreCase);

        internal (int Count, int Failures, int Distinct) Add(
            string key, Guid id, string identity, bool failed, DateTime now, TimeSpan window)
        {
            lock (_gate)
            {
                if (!_windows.TryGetValue(key, out var list))
                {
                    if (_windows.Count >= 256)
                    {
                        var oldest = _windows.OrderBy(pair => pair.Value.Count == 0
                            ? DateTime.MinValue : pair.Value[^1].At).First().Key;
                        _windows.Remove(oldest);
                    }
                    list = new List<Observation>();
                    _windows[key] = list;
                }
                // Late telemetry must not rewind state; packet replay is not independent evidence.
                if (list.Count == 0 || now >= list[^1].At)
                {
                    list.RemoveAll(item => now - item.At > window);
                    if (id != Guid.Empty && !list.Any(item => item.Id == id))
                    {
                        if (list.Count >= 512) list.RemoveAt(0);
                        list.Add(new Observation { Id = id, At = now,
                            Identity = identity ?? string.Empty, Failed = failed });
                    }
                }
                return (list.Count, list.Count(item => item.Failed),
                    list.Where(item => !string.IsNullOrWhiteSpace(item.Identity))
                        .Select(item => item.Identity).Distinct(StringComparer.OrdinalIgnoreCase).Count());
            }
        }
    }
}
