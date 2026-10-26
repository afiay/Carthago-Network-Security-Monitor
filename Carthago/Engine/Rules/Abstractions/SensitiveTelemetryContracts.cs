// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    /// <summary>
    /// Evidence that can be attributed to a parsed protocol field, rather than an arbitrary
    /// description, browser page, or a host name mentioned in free-form text.
    /// These checks are shared by the detector and the runtime telemetry validator.
    /// </summary>
    internal static class SensitiveTelemetryContracts
    {
        private static readonly HashSet<string> DefaultCredentials = new(StringComparer.OrdinalIgnoreCase)
        {
            "admin:admin", "admin:password", "root:root", "root:admin",
            "user:user", "guest:guest", "ubnt:ubnt", "support:support"
        };

        // Canonical Base64 wire tokens are precomputed once. Comparing captured
        // bytes avoids materializing any observed password in a managed string.
        private static readonly byte[][] EncodedDefaultCredentialTokens = DefaultCredentials
            .Select(pair => Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(pair))))
            .ToArray();

        private static bool IsAsciiIgnoreCase(ReadOnlySpan<byte> candidate, ReadOnlySpan<byte> expected)
        {
            if (candidate.Length != expected.Length) return false;
            for (var i = 0; i < candidate.Length; i++)
            {
                var a = candidate[i];
                var b = expected[i];
                if ((a >= 'A' && a <= 'Z' ? a + 32 : a) !=
                    (b >= 'A' && b <= 'Z' ? b + 32 : b))
                    return false;
            }
            return true;
        }

        // Receives only the Authorization value as a span over the capture buffer.
        // No untrusted credential bytes or their Base64 encoding are persisted.
        internal static bool IsKnownDefaultBasicAuthorizationValue(ReadOnlySpan<byte> value)
        {
            while (!value.IsEmpty && (value[0] == (byte)' ' || value[0] == (byte)'\t'))
                value = value[1..];
            if (value.Length < 7 || !IsAsciiIgnoreCase(value[..5], "Basic"u8)
                || (value[5] != (byte)' ' && value[5] != (byte)'\t'))
                return false;

            value = value[6..];
            while (!value.IsEmpty && (value[0] == (byte)' ' || value[0] == (byte)'\t'))
                value = value[1..];
            while (!value.IsEmpty && (value[^1] == (byte)' ' || value[^1] == (byte)'\t'))
                value = value[..^1];

            foreach (var token in EncodedDefaultCredentialTokens)
                if (value.SequenceEqual(token))
                    return true;
            return false;
        }

        private static readonly Regex TelnetLoginWithDefaultPair = new(
            @"\b(?:login|username|user)\s*[:=]?\s*(?:admin:admin|admin:password|root:root|root:admin|user:user|guest:guest|ubnt:ubnt|support:support)\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        private static readonly string[] DeviceHostMarkers =
        {
            "camera", "nvr", "dvr", "onvif", "hikvision", "dahua", "router",
            "gateway", "iot", "ubiquiti", "tplink", "netgear", "mikrotik"
        };

        private static readonly HashSet<string> MetadataHosts = new(StringComparer.OrdinalIgnoreCase)
        {
            "169.254.169.254", "169.254.170.2", "100.100.100.200", "metadata.google.internal"
        };

        // Provider-documented IPv6 metadata endpoints. Do not classify arbitrary
        // IPv6 ULA or link-local addresses as cloud metadata services.
        private static readonly IPAddress AwsImdsIpv6 = IPAddress.Parse("fd00:ec2::254");
        private static readonly IPAddress GoogleMetadataIpv6 = IPAddress.Parse("fd20:ce::254");
        private const string AwsImdsIpv6Host = "fd00:ec2::254";
        private const string GoogleMetadataIpv6Host = "fd20:ce::254";

        private static readonly HashSet<string> TrustedMetadataAgents = new(StringComparer.OrdinalIgnoreCase)
        {
            "waagent", "waagent.exe", "amazon-ssm-agent", "amazon-ssm-agent.exe",
            "google-guest-agent", "google-guest-agent.exe", "cloud-init", "cloud-init.exe"
        };

        public static bool HasDefaultCredentialAuthenticationAttempt(TrafficRecord record)
        {
            if (record == null || string.IsNullOrWhiteSpace(record.Source) || string.IsNullOrWhiteSpace(record.Destination))
                return false;

            // An actual Telnet connection with a credential-bearing login transcript can be
            // evaluated without HTTP telemetry. Text from unrelated HTTP pages cannot qualify.
            if (record.DestinationPort == 23 && !string.IsNullOrWhiteSpace(record.Info))
                return TelnetLoginWithDefaultPair.IsMatch(record.Info);

            if (string.IsNullOrWhiteSpace(record.HttpMethod)
                || string.IsNullOrWhiteSpace(record.HttpHost)
                || !IsDeviceHost(record.HttpHost, record.DestinationPort))
                return false;

            // The capture parser derives this flag without retaining credentials.
            // If header names are also present, they must not contradict the
            // parser's singleton Authorization contract. A replay or imported
            // record can otherwise claim a trusted flag alongside duplicates.
            if (string.IsNullOrWhiteSpace(record.HttpRequestHeaders))
                return record.HttpBasicDefaultCredentialObserved;

            var authorizationHeaderCount = 0;
            var defaultPairObserved = false;
            var redactedAuthorizationObserved = false;
            foreach (var line in record.HttpRequestHeaders.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf(':');
                if (separator < 0 || !line[..separator].Trim().Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (++authorizationHeaderCount > 1)
                    return false;
                // Legacy/replay headers must obey the same unambiguous singleton
                // contract as live capture. Do not trust a default credential
                // when multiple Authorization fields could be interpreted
                // differently by intermediaries or the target device.
                var authorization = line[(separator + 1)..].Trim();
                redactedAuthorizationObserved = authorization.Equals("[REDACTED]", StringComparison.OrdinalIgnoreCase);
                if (authorization.Length is >= 7 and <= 518
                    && IsKnownDefaultBasicAuthorizationValue(Encoding.ASCII.GetBytes(authorization)))
                    defaultPairObserved = true;
            }

            // Live parser output has redacted Authorization values, so the
            // derived flag remains authoritative for the credential identity,
            // but never overrides contradictory duplicate header evidence.
            return record.HttpBasicDefaultCredentialObserved
                ? authorizationHeaderCount == 0
                    || (authorizationHeaderCount == 1
                        && (redactedAuthorizationObserved || defaultPairObserved))
                : authorizationHeaderCount == 1 && defaultPairObserved;
        }

        public static bool HasCredentialBearingMetadataRequest(TrafficRecord record)
        {
            if (record == null || string.IsNullOrWhiteSpace(record.Destination)
                || string.IsNullOrWhiteSpace(record.HttpHost)
                || string.IsNullOrWhiteSpace(record.HttpUri))
                return false;

            // Host is an HTTP authority, while Destination is the observed
            // network endpoint. IPv6 Host literals require brackets; observed
            // socket addresses do not. Neither field is resolved via DNS.
            if (!TryNormalizeMetadataDestination(record.Destination, out var destination)
                || !TryNormalizeMetadataHost(record.HttpHost, record.DestinationPort, out var host))
                return false;

            // A forged Host cannot authenticate another provider's endpoint.
            // GCP's documented metadata.google.internal alias is accepted at
            // its IPv4 and IPv6 metadata addresses, but never at AWS IMDSv6.
            var isGoogleAlias = host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase)
                && (destination.Equals("169.254.169.254", StringComparison.OrdinalIgnoreCase)
                    || destination.Equals(GoogleMetadataIpv6Host, StringComparison.OrdinalIgnoreCase));
            if (!destination.Equals(host, StringComparison.OrdinalIgnoreCase) && !isGoogleAlias)
                return false;

            // A parsed Host property must not hide contradictory wire headers.
            // RFC 9112 requires HTTP/1.1 recipients to reject duplicate Host
            // fields. If captured header lines are available, require every
            // observed Host field to agree with the validated authority and
            // reject even identical duplicates. Headerless normalized records
            // (e.g. HTTP/2 :authority) retain the existing strict socket check.
            if (!HasConsistentMetadataHostHeader(record, host))
                return false;

            var uri = record.HttpUri.Trim();
            // Credential-path evidence must survive normalization. Dot segments
            // and encoded separators can resolve to a different resource at the
            // metadata server or an intermediary. Do not infer credential access
            // from a textual prefix that may disappear after URI normalization.
            if (HasAmbiguousMetadataPath(uri))
                return false;

            if (Uri.TryCreate(uri, UriKind.Absolute, out var absolute))
            {
                // An absolute-form request target must identify the same
                // authority as the observed Host and network destination.
                // Merely naming some other metadata endpoint is insufficient.
                // Uri.Host can include IPv6 brackets; DnsSafeHost strips them.
                // Normalize the parsed authority without accepting userinfo,
                // zone IDs, alternate ports, or a different provider endpoint.
                var absoluteAuthorityHost = absolute.HostNameType == UriHostNameType.IPv6
                    ? $"[{absolute.DnsSafeHost}]"
                    : absolute.Host;
                if ((absolute.Scheme != Uri.UriSchemeHttp && absolute.Scheme != Uri.UriSchemeHttps)
                    || !string.IsNullOrEmpty(absolute.UserInfo)
                    || !TryNormalizeMetadataHost(absoluteAuthorityHost, record.DestinationPort, out var absoluteHost)
                    || !absoluteHost.Equals(host, StringComparison.OrdinalIgnoreCase)
                    || (record.DestinationPort.HasValue && absolute.Port != record.DestinationPort.Value))
                    return false;
                uri = absolute.AbsolutePath;
            }
            else if (!uri.StartsWith("/", StringComparison.Ordinal) || uri.StartsWith("//", StringComparison.Ordinal))
            {
                return false;
            }

            var queryIndex = uri.IndexOf('?');
            if (queryIndex >= 0)
                uri = uri[..queryIndex];

            // A credential-looking path on the wrong provider's endpoint is
            // not proof of credential retrieval. AWS ECS and Alibaba ECS have
            // distinct metadata addresses; AWS EC2, Azure and GCP share the
            // link-local address, so distinguish those services by their paths.
            // This classifies observable metadata access, never SSRF causality.
            if (host.Equals("169.254.170.2", StringComparison.OrdinalIgnoreCase))
                return MatchesPath(uri, "/v2/credentials");

            if (host.Equals("100.100.100.200", StringComparison.OrdinalIgnoreCase))
                return MatchesPath(uri, "/latest/meta-data/ram/security-credentials");

            if (host.Equals(AwsImdsIpv6Host, StringComparison.OrdinalIgnoreCase))
                return MatchesPath(uri, "/latest/meta-data/iam/security-credentials");

            var googleCredentialPath =
                uri.StartsWith("/computeMetadata/v1/instance/service-accounts/", StringComparison.OrdinalIgnoreCase)
                && uri.EndsWith("/token", StringComparison.OrdinalIgnoreCase);

            if (host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase)
                || host.Equals(GoogleMetadataIpv6Host, StringComparison.OrdinalIgnoreCase))
                return googleCredentialPath;

            // At this point the validated Host/destination pair is the shared
            // 169.254.169.254 address, used by EC2 IMDS, Azure IMDS and GCP.
            return MatchesPath(uri, "/latest/meta-data/iam/security-credentials")
                || MatchesPath(uri, "/metadata/identity/oauth2/token")
                || googleCredentialPath;
        }

        private static bool HasConsistentMetadataHostHeader(TrafficRecord record, string validatedHost)
        {
            if (string.IsNullOrWhiteSpace(record.HttpRequestHeaders))
                return true;

            var observedHostFields = 0;
            foreach (var line in record.HttpRequestHeaders.Split(
                new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf(':');
                if (separator <= 0 || !line[..separator].Trim().Equals(
                    "Host", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (++observedHostFields > 1)
                    return false;

                if (!TryNormalizeMetadataHost(line[(separator + 1)..].Trim(),
                        record.DestinationPort, out var headerHost)
                    || !headerHost.Equals(validatedHost, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }

        private static bool TryNormalizeMetadataDestination(string value, out string normalized)
        {
            normalized = value.Trim().TrimEnd('.');
            // Destination is the observed network endpoint, never a Host header
            // or a DNS name supplied by an application. Accept only the
            // documented numeric IPv4 addresses here; DNS aliases belong in
            // TryNormalizeMetadataHost and require a corroborating socket IP.
            if (MetadataHosts.Contains(normalized))
                return IPAddress.TryParse(normalized, out var ipv4)
                    && ipv4.AddressFamily == AddressFamily.InterNetwork;

            // Captured IP destinations have no brackets or scope identifiers.
            if (normalized.Contains('%') || normalized.Contains('[') || normalized.Contains(']')
                || !IPAddress.TryParse(normalized, out var address)
                || address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            if (address.Equals(AwsImdsIpv6))
                normalized = AwsImdsIpv6Host;
            else if (address.Equals(GoogleMetadataIpv6))
                normalized = GoogleMetadataIpv6Host;
            else
                return false;
            return true;
        }

        private static bool TryNormalizeMetadataHost(string authority, int? destinationPort, out string normalized)
        {
            normalized = string.Empty;
            var value = authority.Trim();
            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                var end = value.IndexOf(']');
                if (end < 2)
                    return false;
                var literal = value[1..end];
                var suffix = value[(end + 1)..];
                if ((suffix.Length > 0 && suffix != ":80")
                    || (suffix.Length > 0 && destinationPort.HasValue && destinationPort.Value != 80)
                    || literal.Contains('%')
                    || !IPAddress.TryParse(literal, out var address)
                    || address.AddressFamily != AddressFamily.InterNetworkV6)
                    return false;

                if (address.Equals(AwsImdsIpv6))
                    normalized = AwsImdsIpv6Host;
                else if (address.Equals(GoogleMetadataIpv6))
                    normalized = GoogleMetadataIpv6Host;
                else
                    return false;
                return true;
            }

            // Bare IPv6 is invalid in HTTP Host; keep the existing strict
            // IPv4/DNS authority allowlist, with optional explicit port 80.
            var explicitHttpPort = value.EndsWith(":80", StringComparison.OrdinalIgnoreCase);
            if (explicitHttpPort)
            {
                value = value[..^3];
                if (destinationPort.HasValue && destinationPort.Value != 80)
                    return false;
            }
            value = value.TrimEnd('.');
            if (!MetadataHosts.Contains(value))
                return false;
            normalized = value;
            return true;
        }

        private static bool HasAmbiguousMetadataPath(string requestTarget)
        {
            // Inspect the original request target BEFORE Uri.TryCreate can
            // canonicalize absolute-form dot segments. Never inspect the query
            // string: Azure's documented credential endpoint needs one.
            var question = requestTarget.IndexOf('?');
            var rawPath = question < 0 ? requestTarget : requestTarget[..question];
            if (rawPath.IndexOf('#') >= 0 || rawPath.IndexOf('\\') >= 0
                || rawPath.Contains("%2e", StringComparison.OrdinalIgnoreCase)
                || rawPath.Contains("%2f", StringComparison.OrdinalIgnoreCase)
                || rawPath.Contains("%5c", StringComparison.OrdinalIgnoreCase)
                || rawPath.Contains("%00", StringComparison.OrdinalIgnoreCase)
                || rawPath.Contains("%25", StringComparison.OrdinalIgnoreCase))
                return true;

            // A path that looks credential-bearing before normalization must
            // not match after an intermediate "/../" or "/./" resolution.
            return rawPath.Split('/').Any(static segment => segment is "." or "..");
        }

        private static bool MatchesPath(string path, string prefix)
            => path.Equals(prefix, StringComparison.OrdinalIgnoreCase)
               || path.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase);

        public static bool IsKnownCloudMetadataAgent(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return false;

            var normalized = processName.Trim().Replace('\\', '/');
            var basename = normalized[(normalized.LastIndexOf('/') + 1)..];
            if (!TrustedMetadataAgents.Contains(basename))
                return false;

            // A familiar executable basename is not sufficient to suppress a
            // suspicious metadata request when the observed executable path is
            // in a commonly user-writable location. Keep basename-only legacy
            // telemetry behavior unchanged, but do not allow path spoofing to
            // masquerade as a recognized guest agent.
            if (normalized.Contains('/')
                && Regex.IsMatch(normalized,
                    @"(?:^|/)(?:tmp|temp|downloads|desktop|appdata|public)(?:/|$)|(?:^|/)dev/shm(?:/|$)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return false;

            return true;
        }

        // A device label is evidence; a keyword buried inside an unrelated
        // domain (e.g. "camerastore.example") is not. Accept common inventory
        // forms such as camera-office, router02 and ubiquiti-router.
        private static readonly Regex DeviceHostLabel = new(
            @"(?:^|[.\-])(?:camera|nvr|dvr|onvif|hikvision|dahua|router|gateway|iot|ubiquiti|tplink|netgear|mikrotik)[0-9]*(?=$|[.\-])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        private static bool IsDeviceHost(string host, int? destinationPort)
        {
            if (string.IsNullOrWhiteSpace(host))
                return false;

            var authority = host.Trim();
            // An HTTP Host is an authority, not a free-form URL or userinfo.
            // Reject parser-confusing values before looking for device labels.
            if (authority.IndexOfAny(new[] { '@', '/', '\\', ',', ' ', '\t', '\r', '\n' }) >= 0)
                return false;

            // HTTP/1.1 Host can include a numeric port. A valid device label
            // must remain recognizable in "router02.lab.internal:8080".
            var colon = authority.IndexOf(':');
            if (colon >= 0)
            {
                if (colon != authority.LastIndexOf(':')
                    || colon == authority.Length - 1
                    || !Regex.IsMatch(authority[(colon + 1)..], @"^[0-9]{1,5}$")
                    || !int.TryParse(authority[(colon + 1)..], out var port)
                    || port is < 1 or > 65535
                    || (destinationPort.HasValue && port != destinationPort.Value))
                    return false;
                authority = authority[..colon];
            }

            return DeviceHostLabel.IsMatch(authority.TrimEnd('.'));
        }

        private static bool ContainsAny(string text, string[] values)
            => values.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));
    }
}
