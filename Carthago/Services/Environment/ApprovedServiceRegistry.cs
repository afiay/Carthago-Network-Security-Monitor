// SPDX-License-Identifier: MIT
// File: Services/Environment/ApprovedServiceRegistry.cs
namespace Carthago.Services.EnvironmentTuning
{
    public sealed class ApprovedServiceRegistry
    {
        private readonly ApprovedDestinationRegistry _destinations;

        public ApprovedServiceRegistry(ApprovedDestinationRegistry destinations)
            => _destinations = destinations;

        public bool IsApprovedMqttBroker(string? value) => _destinations.IsApprovedMqttBroker(value);
        public bool IsApprovedDnsResolver(string? value) => _destinations.IsApprovedDnsResolver(value);
        public bool IsApprovedProxyServer(string? value) => _destinations.IsApprovedProxyServer(value);
        public bool IsApprovedVpnGateway(string? value) => _destinations.IsApprovedVpnGateway(value);
        public bool IsApprovedCloudStorageProvider(string? value) => _destinations.IsApprovedCloudStorageProvider(value);
        public bool IsApprovedKubernetesApiServer(string? value) => _destinations.IsApprovedKubernetesApiServer(value);
        public bool IsApprovedCiCdServer(string? value) => _destinations.IsApprovedCiCdServer(value);
        public bool IsApprovedCameraNvrHost(string? value) => _destinations.IsApprovedCameraNvrHost(value);
        public bool IsKnownDynamicDnsDomain(string? value) => _destinations.IsKnownDynamicDnsDomain(value);
        public bool IsKnownRemoteSupportTool(string? value) => _destinations.IsKnownRemoteSupportTool(value);
    }
}
