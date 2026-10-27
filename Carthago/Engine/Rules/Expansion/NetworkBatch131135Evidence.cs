// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // R131-R135: parser-attributed HTTP evidence, not Info/port/URI alone.
    // Never copy credential material or user-controlled paths into detection evidence.
    internal static class NetworkBatch131135Evidence
    {
        private static bool Same(string? value, string expected)
            => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

        internal static bool HttpRequest(TrafficRecord record)
            => NetworkBatch126130Evidence.HttpRequest(record);

        internal static bool CleartextHttpRequest(TrafficRecord record)
        {
            if (!HttpRequest(record) || !string.IsNullOrWhiteSpace(record.Sni)
                || !string.IsNullOrWhiteSpace(record.TlsVersion)
                || !string.IsNullOrWhiteSpace(record.Alpn)
                || !string.IsNullOrWhiteSpace(record.CertIssuer)
                || !string.IsNullOrWhiteSpace(record.CertSubject)
                || record.DestinationPort is 443 or 8443 or 9443 or 10443 or 5986
                || record.SourcePort is 443 or 8443 or 9443 or 10443 or 5986
                || Same(record.Protocol, "HTTPS") || Same(record.Protocol, "TLS")
                || Same(record.ApplicationProtocol, "HTTPS")
                || Same(record.ApplicationService, "HTTPS"))
                return false;
            return Same(record.Protocol, "HTTP")
                || Same(record.ApplicationProtocol, "HTTP")
                || Same(record.ApplicationService, "HTTP");
        }

        private static bool HeaderName(string? headers, string name)
        {
            if (string.IsNullOrWhiteSpace(headers) || headers.Length > 8192)
                return false;
            foreach (var line in headers.Split('\n'))
            {
                var separator = line.IndexOf(':');
                if (separator > 0 && Same(line[..separator].Trim(), name))
                    return true;
            }
            return false;
        }

        internal static bool AuthenticationFailure(TrafficRecord record, string path)
        {
            if (!HttpRequest(record) || string.IsNullOrWhiteSpace(record.Info)
                || record.Info!.Length > 1024)
                return false;
            var info = record.Info;
            var failed = Has(info, "401 unauthorized", "http 401", "status 401",
                "authentication failed", "login failed", "invalid password",
                "bad credentials", "invalid grant", "user not found");
            if (!failed || Has(info, "login successful", "authentication succeeded", "200 ok"))
                return false;
            var authRoute = Has(path, "/auth/", "/login", "/signin", "/session", "/token", "/oauth");
            return authRoute || HeaderName(record.HttpRequestHeaders, "Authorization")
                || HeaderName(record.HttpRequestHeaders, "Proxy-Authorization")
                || HeaderName(record.HttpRequestHeaders, "WWW-Authenticate");
        }

        internal static bool AuthHeaderContext(TrafficRecord record)
            => HeaderName(record.HttpRequestHeaders, "Authorization")
                || HeaderName(record.HttpRequestHeaders, "Proxy-Authorization")
                || HeaderName(record.HttpRequestHeaders, "WWW-Authenticate");

        internal static string CountryIso2(TrafficRecord record)
        {
            var country = record.SrcCountryIso2?.Trim().ToUpperInvariant() ?? string.Empty;
            return country.Length == 2 && country.All(static c => c >= 'A' && c <= 'Z')
                && country is not ("ZZ" or "XX" or "EU" or "UN") ? country : string.Empty;
        }

        internal static string Fingerprint(string value)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant()));
            return Convert.ToHexString(bytes)[..16];
        }

        internal static bool AuthorizationHeader(TrafficRecord record, string scheme)
        {
            var headers = record.HttpRequestHeaders;
            if (string.IsNullOrWhiteSpace(headers) || headers!.Length > 8192)
                return false;
            foreach (var line in headers.Split('\n'))
            {
                var separator = line.IndexOf(':');
                if (separator <= 0)
                    continue;
                var name = line[..separator].Trim();
                if (!Same(name, "Authorization") && !Same(name, "Proxy-Authorization"))
                    continue;
                var value = line[(separator + 1)..].Trim();
                if (!value.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase))
                    continue;
                var token = value[(scheme.Length + 1)..].Trim();
                if (Same(scheme, "Basic") && ValidBasic(token))
                    return true;
                if (Same(scheme, "Bearer") && OpaqueToken(token))
                    return true;
            }
            return false;
        }

        private static bool ValidBasic(string token)
        {
            if (token.Length is < 8 or > 2048 || token.Any(static c =>
                !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=')))
                return false;
            byte[]? decoded = null;
            try
            {
                decoded = Convert.FromBase64String(token);
                var colon = Array.IndexOf(decoded, (byte)':');
                return colon > 0 && colon < decoded.Length - 1;
            }
            catch (FormatException)
            {
                return false;
            }
            finally
            {
                if (decoded != null)
                    CryptographicOperations.ZeroMemory(decoded);
            }
        }

        private static bool OpaqueToken(string token)
        {
            if (token.Length is < 12 or > 2048
                || !token.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '=' or '.' or '~')
                || !token.Any(char.IsAsciiLetter) || !token.Any(char.IsDigit)
                || token.Distinct().Count() < 6)
                return false;
            var lower = token.ToLowerInvariant();
            return !Has(lower, "placeholder", "changeme", "exampletoken", "dummyvalue", "notasecret");
        }

        internal static bool SensitiveQuery(TrafficRecord record)
        {
            if (!HttpRequest(record) || string.IsNullOrWhiteSpace(record.HttpUri))
                return false;
            var raw = record.HttpUri!;
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)
                && !Uri.TryCreate("https://placeholder" + (raw.StartsWith("/", StringComparison.Ordinal) ? "" : "/") + raw,
                    UriKind.Absolute, out uri))
                return false;
            if (string.IsNullOrWhiteSpace(uri.Query))
                return false;
            foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var pieces = part.Split('=', 2);
                if (pieces.Length != 2)
                    continue;
                var name = Uri.UnescapeDataString(pieces[0]).Trim().ToLowerInvariant();
                if (!SensitiveParameterName(name))
                    continue;
                var value = Uri.UnescapeDataString(pieces[1]).Trim();
                if (OpaqueToken(value))
                    return true;
            }
            return false;
        }

        private static bool SensitiveParameterName(string name)
        {
            if (name.Length is < 3 or > 64
                || Has(name, "csrf", "xsrf", "state", "nonce", "code_verifier",
                    "page_token", "next_token", "reset_token", "verification_token"))
                return false;
            return name is "api_key" or "apikey" or "access_token" or "auth_token"
                or "bearer_token" or "client_secret" or "secret_key"
                || name.EndsWith("_api_key", StringComparison.Ordinal)
                || name.EndsWith("_token", StringComparison.Ordinal)
                || name.EndsWith("_secret", StringComparison.Ordinal);
        }

        private static bool Has(string? value, params string[] needles)
            => value != null && needles.Any(x => value.Contains(x, StringComparison.OrdinalIgnoreCase));
    }
}
