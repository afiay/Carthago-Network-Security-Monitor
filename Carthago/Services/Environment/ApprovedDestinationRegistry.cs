// SPDX-License-Identifier: MIT
// File: Services/Environment/ApprovedDestinationRegistry.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services.EnvironmentTuning
{
    public sealed class ApprovedDestinationRegistry
    {
        private readonly HashSet<string> _mqttBrokers;
        private readonly HashSet<string> _dnsResolvers;
        private readonly HashSet<string> _proxyServers;
        private readonly HashSet<string> _vpnGateways;
        private readonly HashSet<string> _cloudStorageProviders;
        private readonly HashSet<string> _kubernetesApiServers;
        private readonly HashSet<string> _ciCdServers;
        private readonly HashSet<string> _cameraNvrHosts;
        private readonly HashSet<string> _knownDynamicDnsDomains;
        private readonly HashSet<string> _knownRemoteSupportTools;

        public ApprovedDestinationRegistry(EnvironmentTuningOptions? options)
        {
            var approved = options?.Approved ?? new ApprovedEnvironmentOptions();
            _mqttBrokers = ToSet(approved.MqttBrokers);
            _dnsResolvers = ToSet(approved.DnsResolvers);
            _proxyServers = ToSet(approved.ProxyServers);
            _vpnGateways = ToSet(approved.VpnGateways);
            _cloudStorageProviders = ToSet(approved.CloudStorageProviders);
            _kubernetesApiServers = ToSet(approved.KubernetesApiServers);
            _ciCdServers = ToSet(approved.CiCdServers);
            _cameraNvrHosts = ToSet(approved.CameraNvrHosts);
            _knownDynamicDnsDomains = ToSet(approved.KnownDynamicDnsDomains);
            _knownRemoteSupportTools = ToSet(approved.KnownRemoteSupportTools);
        }

        public bool IsApprovedMqttBroker(string? value) => Match(_mqttBrokers, value);
        public bool IsApprovedDnsResolver(string? value) => Match(_dnsResolvers, value);
        public bool IsApprovedProxyServer(string? value) => Match(_proxyServers, value);
        public bool IsApprovedVpnGateway(string? value) => Match(_vpnGateways, value);
        public bool IsApprovedCloudStorageProvider(string? value) => Match(_cloudStorageProviders, value);
        public bool IsApprovedKubernetesApiServer(string? value) => Match(_kubernetesApiServers, value);
        public bool IsApprovedCiCdServer(string? value) => Match(_ciCdServers, value);
        public bool IsApprovedCameraNvrHost(string? value) => Match(_cameraNvrHosts, value);
        public bool IsKnownDynamicDnsDomain(string? value) => Match(_knownDynamicDnsDomains, value, allowDomainSuffix: true);
        public bool IsKnownRemoteSupportTool(string? value) => Match(_knownRemoteSupportTools, value, allowDomainSuffix: true);

        private static HashSet<string> ToSet(IEnumerable<string>? values)
            => values?
                .Select(Normalize)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
               ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static bool Match(HashSet<string> values, string? candidate, bool allowDomainSuffix = false)
        {
            var normalized = Normalize(candidate);
            if (string.IsNullOrWhiteSpace(normalized) || values.Count == 0)
                return false;

            if (values.Contains(normalized))
                return true;

            return allowDomainSuffix && values.Any(value => normalized.Equals(value, StringComparison.OrdinalIgnoreCase)
                || normalized.EndsWith('.' + value, StringComparison.OrdinalIgnoreCase));
        }

        internal static string Normalize(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            var normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
            if (normalized.StartsWith("https://", StringComparison.Ordinal))
                normalized = normalized[8..];
            else if (normalized.StartsWith("http://", StringComparison.Ordinal))
                normalized = normalized[7..];

            var slash = normalized.IndexOf('/');
            if (slash >= 0)
                normalized = normalized[..slash];

            return normalized;
        }
    }
}
