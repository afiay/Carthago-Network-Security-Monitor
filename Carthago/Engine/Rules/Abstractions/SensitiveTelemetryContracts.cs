// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
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
                || !IsDeviceHost(record.HttpHost))
                return false;

            if (record.HttpBasicDefaultCredentialObserved)
                return true;
            if (string.IsNullOrWhiteSpace(record.HttpRequestHeaders))
                return false;

            foreach (var line in record.HttpRequestHeaders.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf(':');
                if (separator < 0 || !line[..separator].Trim().Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    continue;

                // The synthetic replay/legacy-header path must use the same
                // canonical wire-token comparison as live capture. Never decode
                // observed credentials into a managed plaintext password string.
                var authorization = line[(separator + 1)..].Trim();
                if (authorization.Length is < 7 or > 518)
                    continue;
                if (IsKnownDefaultBasicAuthorizationValue(Encoding.ASCII.GetBytes(authorization)))
                    return true;
            }

            return false;
        }

        public static bool HasCredentialBearingMetadataRequest(TrafficRecord record)
        {
            if (record == null || string.IsNullOrWhiteSpace(record.Destination)
                || string.IsNullOrWhiteSpace(record.HttpHost)
                || string.IsNullOrWhiteSpace(record.HttpUri))
                return false;

            // A forged HTTP Host header on an unrelated destination is not metadata access.
            var destination = record.Destination.Trim().TrimEnd('.');
            var host = record.HttpHost.Trim().TrimEnd('.');

            // Host is an HTTP authority, not a URI. Parsing "http://" + Host
            // would silently accept userinfo (attacker@169.254.169.254) and
            // embedded paths. Allow only the known literal metadata hosts,
            // optionally followed by the standard cleartext HTTP port.
            var explicitHttpPort = host.EndsWith(":80", StringComparison.OrdinalIgnoreCase);
            if (explicitHttpPort)
            {
                host = host[..^3];
                if (record.DestinationPort.HasValue && record.DestinationPort.Value != 80)
                    return false;
            }
            if (!MetadataHosts.Contains(destination) || !MetadataHosts.Contains(host))
                return false;

            // A metadata-looking Host header is not evidence that the TCP
            // destination belongs to that provider. Only accept the same
            // endpoint, or Google's documented DNS alias for 169.254.169.254.
            // Do not resolve untrusted Host values during rule evaluation.
            var isGoogleAlias = destination.Equals("169.254.169.254", StringComparison.OrdinalIgnoreCase)
                                && host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase);
            if (!destination.Equals(host, StringComparison.OrdinalIgnoreCase) && !isGoogleAlias)
                return false;

            var uri = record.HttpUri.Trim();
            if (Uri.TryCreate(uri, UriKind.Absolute, out var absolute))
            {
                // An absolute-form request target must identify the same
                // authority as the observed Host and network destination.
                // Merely naming some other metadata endpoint is insufficient.
                if ((absolute.Scheme != Uri.UriSchemeHttp && absolute.Scheme != Uri.UriSchemeHttps)
                    || !string.IsNullOrEmpty(absolute.UserInfo)
                    || !absolute.Host.Equals(host, StringComparison.OrdinalIgnoreCase)
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

            var googleCredentialPath =
                uri.StartsWith("/computeMetadata/v1/instance/service-accounts/", StringComparison.OrdinalIgnoreCase)
                && uri.EndsWith("/token", StringComparison.OrdinalIgnoreCase);

            if (host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase))
                return googleCredentialPath;

            // At this point the validated Host/destination pair is the shared
            // 169.254.169.254 address, used by EC2 IMDS, Azure IMDS and GCP.
            return MatchesPath(uri, "/latest/meta-data/iam/security-credentials")
                || MatchesPath(uri, "/metadata/identity/oauth2/token")
                || googleCredentialPath;
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
            return TrustedMetadataAgents.Contains(basename);
        }

        private static bool IsDeviceHost(string host)
            => ContainsAny(host, DeviceHostMarkers);

        private static bool ContainsAny(string text, string[] values)
            => values.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));
    }
}
