// SPDX-License-Identifier: MIT
// File: Services/Environment/EnvironmentTuningOptions.cs
using System.Collections.Generic;

namespace Carthago.Services.EnvironmentTuning
{
    public sealed class EnvironmentTuningOptions
    {
        public ApprovedEnvironmentOptions Approved { get; set; } = new();
    }

    public sealed class ApprovedEnvironmentOptions
    {
        public List<string> MqttBrokers { get; set; } = new();
        public List<string> DnsResolvers { get; set; } = new();
        public List<string> ProxyServers { get; set; } = new();
        public List<string> VpnGateways { get; set; } = new();
        public List<string> CloudStorageProviders { get; set; } = new();
        public List<string> AdminHosts { get; set; } = new();
        // Opt-in exact, time-bounded SMB2 maintenance scope; empty by default.
        public List<Smb2MaintenanceScope> Smb2MaintenanceScopes { get; set; } = new();
        // Explicit Redis server inventory for verified-audit candidates only.
        // Absence means unconfigured, never automatically trusted.
        public List<string> RedisServers { get; set; } = new();
        public List<string> DomainControllers { get; set; } = new();
        public List<string> KubernetesApiServers { get; set; } = new();
        public List<string> CiCdServers { get; set; } = new();
        public List<string> OtSegments { get; set; } = new();
        public List<string> ModbusControllers { get; set; } = new();
        public List<string> BacnetControllers { get; set; } = new();
        public List<string> CameraNvrHosts { get; set; } = new();
        public List<string> KnownDynamicDnsDomains { get; set; } = new();
        public List<string> KnownRemoteSupportTools { get; set; } = new();
    }
}
