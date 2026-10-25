// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
            {
                var text = record.Info!;
                return ContainsAny(text, new[] { "login", "username", "password" })
                    && DefaultCredentials.Any(pair => text.Contains(pair, StringComparison.OrdinalIgnoreCase));
            }

            if (string.IsNullOrWhiteSpace(record.HttpMethod)
                || string.IsNullOrWhiteSpace(record.HttpHost)
                || string.IsNullOrWhiteSpace(record.HttpRequestHeaders)
                || !IsDeviceHost(record.HttpHost))
                return false;

            foreach (var line in record.HttpRequestHeaders.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf(':');
                if (separator < 0 || !line[..separator].Trim().Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    continue;

                var authorization = line[(separator + 1)..].Trim();
                if (!authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var encoded = authorization[6..].Trim();
                if (encoded.Length is < 4 or > 512)
                    continue;

                try
                {
                    var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                    if (DefaultCredentials.Contains(credentials))
                        return true;
                }
                catch (FormatException)
                {
                    // An invalid Basic value is not proof that a default credential was used.
                }
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
            if (Uri.TryCreate("http://" + host, UriKind.Absolute, out var parsedHost) && parsedHost.Port == 80)
                host = parsedHost.Host;
            if (!MetadataHosts.Contains(destination) || !MetadataHosts.Contains(host))
                return false;

            var uri = record.HttpUri.Trim();
            if (Uri.TryCreate(uri, UriKind.Absolute, out var absolute))
            {
                if (!MetadataHosts.Contains(absolute.Host))
                    return false;
                uri = absolute.AbsolutePath;
            }

            var queryIndex = uri.IndexOf('?');
            if (queryIndex >= 0)
                uri = uri[..queryIndex];

            return MatchesPath(uri, "/latest/meta-data/iam/security-credentials")
                || MatchesPath(uri, "/latest/meta-data/ram/security-credentials")
                || MatchesPath(uri, "/v2/credentials")
                || MatchesPath(uri, "/metadata/identity/oauth2/token")
                || (uri.StartsWith("/computeMetadata/v1/instance/service-accounts/", StringComparison.OrdinalIgnoreCase)
                    && uri.EndsWith("/token", StringComparison.OrdinalIgnoreCase));
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
