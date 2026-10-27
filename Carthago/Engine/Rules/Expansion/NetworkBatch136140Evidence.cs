// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // R136-R140: typed transport, bounded HTTP headers and certificate evidence.
    // Do not infer credentials, certificate identities or negotiated TLS versions from Info.
    internal static class NetworkBatch136140Evidence
    {
        private static bool Same(string? a, string b)
            => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        internal static string Fingerprint(string? value)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty));
            return Convert.ToHexString(hash)[..16];
        }

        internal static bool SessionCookie(TrafficRecord record, out string cookieName)
        {
            cookieName = string.Empty;
            if (!NetworkBatch131135Evidence.CleartextHttpRequest(record))
                return false;
            var headers = record.HttpRequestHeaders;
            if (string.IsNullOrWhiteSpace(headers) || headers.Length > 8192)
                return false;
            foreach (var line in headers.Split('\n'))
            {
                var colon = line.IndexOf(':');
                if (colon < 0 || !Same(line[..colon].Trim(), "Cookie"))
                    continue;
                foreach (var item in line[(colon + 1)..].Split(';', StringSplitOptions.RemoveEmptyEntries))
                {
                    var separator = item.IndexOf('=');
                    if (separator < 1) continue;
                    var name = item[..separator].Trim();
                    var value = item[(separator + 1)..].Trim();
                    if (!new[] { "sessionid", "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid" }
                            .Any(allowed => Same(name, allowed)) || !OpaqueSession(value))
                        continue;
                    cookieName = name.ToLowerInvariant();
                    return true;
                }
            }
            return false;
        }

        private static bool OpaqueSession(string value)
        {
            if (value.Length is < 12 or > 256
                || !value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '=')
                || !value.Any(char.IsAsciiLetter) || !value.Any(char.IsDigit)
                || value.Distinct().Count() < 6)
                return false;
            var lower = value.ToLowerInvariant();
            return !new[] { "placeholder", "changeme", "example", "notasecret", "dummyvalue" }
                .Any(lower.Contains);
        }

        internal static bool RecoverySubmission(TrafficRecord record, out bool enrollment)
        {
            enrollment = false;
            if (!NetworkBatch131135Evidence.HttpRequest(record)
                || !(Same(record.HttpMethod, "POST") || Same(record.HttpMethod, "PUT")
                    || Same(record.HttpMethod, "PATCH")))
                return false;
            var path = record.HttpUri ?? string.Empty;
            if (!Uri.TryCreate(path, UriKind.Absolute, out var uri)
                && !Uri.TryCreate("https://placeholder" + (path.StartsWith("/", StringComparison.Ordinal) ? "" : "/") + path,
                    UriKind.Absolute, out uri))
                return false;
            path = uri.AbsolutePath.TrimEnd('/').ToLowerInvariant();
            if (path.StartsWith("/docs/", StringComparison.Ordinal)
                || path.StartsWith("/documentation/", StringComparison.Ordinal)
                || path.StartsWith("/download/", StringComparison.Ordinal)
                || path.StartsWith("/assets/", StringComparison.Ordinal))
                return false;
            enrollment = path is "/mfa/enroll" or "/mfa/enrollment" or "/totp/enroll"
                or "/webauthn/register" or "/account/enrollment";
            return enrollment || path is "/password-reset" or "/password/reset"
                or "/forgot-password" or "/account/recovery" or "/recover-account"
                or "/auth/reset" or "/reset-password" or "/account/reset-password";
        }

        internal static bool TlsSession(TrafficRecord record)
        {
            if (record.Id == Guid.Empty || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.IcmpTypeCode.HasValue || record.DnsQname != null
                || record.DnsAnswers != null || record.DnsIsResponse
                || record.HttpMethod != null || record.HttpUri != null
                || record.HttpRequestHeaders != null
                || record.TcpFlags.HasValue
                    && ((record.TcpFlags.Value & 0x07) != 0 || (record.TcpFlags.Value & 0x18) == 0))
                return false;
            if (!TransportLabel(record.Protocol, true)
                || !TransportLabel(record.ApplicationProtocol, false)
                || !TransportLabel(record.ApplicationService, false))
                return false;
            return !string.IsNullOrWhiteSpace(record.TlsVersion)
                || !string.IsNullOrWhiteSpace(record.CertIssuer)
                || !string.IsNullOrWhiteSpace(record.CertSubject)
                || !string.IsNullOrWhiteSpace(record.Sni);
        }

        private static bool TransportLabel(string? value, bool allowTcp)
            => value == null || Same(value, "TLS") || Same(value, "HTTPS")
                || Same(value, "SSL") || (allowTcp && Same(value, "TCP"));

        internal static bool ExternalDestination(TrafficRecord record)
        {
            if (!IPAddress.TryParse(record.Destination, out var ip)
                || IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal
                || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal)
                return false;
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
                return bytes[0] != 0 && bytes[0] != 10 && bytes[0] != 127
                    && bytes[0] < 224 && !(bytes[0] == 169 && bytes[1] == 254)
                    && !(bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    && !(bytes[0] == 192 && bytes[1] == 168);
            return bytes.Length == 16 && (bytes[0] & 0xfe) != 0xfc;
        }

        internal static bool SelfIssuedCertificate(TrafficRecord record)
        {
            var issuer = record.CertIssuer?.Trim();
            var subject = record.CertSubject?.Trim();
            return !string.IsNullOrWhiteSpace(issuer) && !string.IsNullOrWhiteSpace(subject)
                && issuer.Length <= 512 && subject.Length <= 512
                && issuer.Contains('=') && subject.Contains('=')
                && string.Equals(issuer, subject, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool WeakVersion(string? raw, out string normalized)
        {
            normalized = string.Empty;
            switch (raw?.Trim().ToUpperInvariant())
            {
                case "TLS 1.0":
                case "TLS1.0":
                case "TLSV1":
                case "TLSV1.0":
                    normalized = "TLS 1.0"; return true;
                case "TLS 1.1":
                case "TLS1.1":
                case "TLSV1.1":
                    normalized = "TLS 1.1"; return true;
                case "SSLV3":
                case "SSLV3.0":
                case "SSL 3.0":
                case "SSL3":
                    normalized = "SSL 3.0"; return true;
                default:
                    return false;
            }
        }

        internal static bool SuspiciousIssuer(TrafficRecord record)
        {
            var issuer = record.CertIssuer;
            if (string.IsNullOrWhiteSpace(issuer) || issuer.Length > 512)
                return false;
            var cn = issuer.Split(',')
                .Select(part => part.Trim())
                .FirstOrDefault(part => part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
            if (cn == null)
                return false;
            var name = cn[3..].Trim().Trim('"').ToLowerInvariant();
            return name is "mitmproxy" or "mitmproxy ca" or "test ca"
                or "localhost" or "default" or "snakeoil" or "unknown";
        }
    }
}
