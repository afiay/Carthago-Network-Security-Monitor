// SPDX-License-Identifier: MIT
// File: Services/Environment/ApprovedAssetRegistry.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Carthago.Models;

namespace Carthago.Services.EnvironmentTuning
{
    public enum ApprovedAssetDisposition
    {
        None,
        Shadow
    }

    public sealed record ApprovedAssetDecision(
        ApprovedAssetDisposition Disposition,
        string Reason,
        string ConfigKey,
        string MatchedValue);

    public sealed class ApprovedAssetRegistry
    {
        private static readonly JsonSerializerOptions FileJsonOptions = new()
        {
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        private static ApprovedAssetRegistry _current = new(new EnvironmentTuningOptions());

        private readonly ApprovedDestinationRegistry _destinations;
        private readonly ApprovedServiceRegistry _services;
        private readonly HashSet<string> _adminHosts;
        private readonly HashSet<string> _domainControllers;
        private readonly HashSet<string> _modbusControllers;
        private readonly HashSet<string> _bacnetControllers;
        private readonly string[] _otSegments;

        public ApprovedAssetRegistry(EnvironmentTuningOptions? options)
        {
            Options = options ?? new EnvironmentTuningOptions();
            _destinations = new ApprovedDestinationRegistry(Options);
            _services = new ApprovedServiceRegistry(_destinations);
            _adminHosts = ToSet(Options.Approved.AdminHosts);
            _domainControllers = ToSet(Options.Approved.DomainControllers);
            _modbusControllers = ToSet(Options.Approved.ModbusControllers);
            _bacnetControllers = ToSet(Options.Approved.BacnetControllers);
            _otSegments = Options.Approved.OtSegments?.Where(static value => !string.IsNullOrWhiteSpace(value)).Select(static value => value.Trim()).ToArray()
                ?? Array.Empty<string>();
        }

        public static ApprovedAssetRegistry Current => _current;
        public EnvironmentTuningOptions Options { get; }

        public static void Configure(EnvironmentTuningOptions? options)
        {
            var registry = new ApprovedAssetRegistry(options);
            _current = registry;
            EnvironmentAssessmentService.Configure(EnvironmentAssessmentService.FromOptions(options ?? new EnvironmentTuningOptions(), registry));
        }

        public static void Load(string path = "environment-tuning.json")
        {
            if (!File.Exists(path))
            {
                Configure(new EnvironmentTuningOptions());
                return;
            }

            var json = File.ReadAllText(path);
            var options = JsonSerializer.Deserialize<EnvironmentTuningOptions>(json, FileJsonOptions) ?? new EnvironmentTuningOptions();
            Configure(options);
        }

        public bool HasApprovedOtSegments => _otSegments.Length > 0;
        public bool HasApprovedModbusControllers => _modbusControllers.Count > 0;
        public bool HasApprovedBacnetControllers => _bacnetControllers.Count > 0;
        public bool HasAnyOtControllerConfiguration => HasApprovedModbusControllers || HasApprovedBacnetControllers;
        public bool HasKnownDynamicDnsDomains => Options.Approved.KnownDynamicDnsDomains.Count > 0;

        public bool IsAdminHost(string? value) => Match(_adminHosts, value);
        public bool IsDomainController(string? value) => Match(_domainControllers, value);
        public bool IsApprovedModbusController(string? value) => Match(_modbusControllers, value);
        public bool IsApprovedBacnetController(string? value) => Match(_bacnetControllers, value);
        public bool IsInApprovedOtSegment(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || _otSegments.Length == 0)
                return false;

            foreach (var segment in _otSegments)
            {
                if (IpMatchesSegment(ip, segment))
                    return true;
            }

            return false;
        }

        public ApprovedAssetDecision? Evaluate(string ruleId, DetectionEvent evt, TrafficRecord record, string? profileName)
        {
            if (evt == null || record == null || string.IsNullOrWhiteSpace(ruleId))
                return null;

            var destination = FirstNonEmpty(evt.DestinationHost, evt.DestinationIp, record.HttpHost, record.Sni, record.DnsQname, record.Destination);
            var source = FirstNonEmpty(evt.SourceIp, record.Source);

            return ruleId.ToUpperInvariant() switch
            {
                "R028" when _services.IsApprovedDnsResolver(destination) || _services.IsApprovedDnsResolver(evt.DestinationIp) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved external DNS resolver.", "Approved.DnsResolvers", destination ?? evt.DestinationIp ?? string.Empty),

                "R098" when _services.IsKnownDynamicDnsDomain(destination) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Known dynamic DNS domain approved for this environment.", "Approved.KnownDynamicDnsDomains", destination ?? string.Empty),

                "R113" when _services.IsApprovedMqttBroker(destination) || _services.IsApprovedMqttBroker(evt.DestinationIp) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved MQTT broker.", "Approved.MqttBrokers", destination ?? evt.DestinationIp ?? string.Empty),

                "R119" when _services.IsApprovedCameraNvrHost(source) || _services.IsApprovedCameraNvrHost(destination) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved camera or NVR host.", "Approved.CameraNvrHosts", source ?? destination ?? string.Empty),

                "R120" when IsApprovedModbusController(source) || IsApprovedModbusController(destination) || IsInApprovedOtSegment(record.Source) || IsInApprovedOtSegment(record.Destination) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved OT segment or Modbus controller.", IsApprovedModbusController(source) || IsApprovedModbusController(destination) ? "Approved.ModbusControllers" : "Approved.OtSegments", source ?? destination ?? string.Empty),

                "R121" when IsAdminHost(source) || IsApprovedBacnetController(destination) || IsInApprovedOtSegment(record.Source) || IsInApprovedOtSegment(record.Destination) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved BACnet admin/controller activity.", IsAdminHost(source) ? "Approved.AdminHosts" : IsApprovedBacnetController(destination) ? "Approved.BacnetControllers" : "Approved.OtSegments", source ?? destination ?? string.Empty),

                "R148" when _services.IsKnownDynamicDnsDomain(destination) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Known dynamic DNS domain approved for this environment.", "Approved.KnownDynamicDnsDomains", destination ?? string.Empty),

                "R264" when string.Equals(profileName, "Research", StringComparison.OrdinalIgnoreCase) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Research profile allows Tor validation traffic to stay visible without paging.", "Profile.Research", "Research"),

                "R472" when _services.IsKnownRemoteSupportTool(destination) || _services.IsKnownRemoteSupportTool(record.ProcessName) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved remote support tool.", "Approved.KnownRemoteSupportTools", destination ?? record.ProcessName ?? string.Empty),

                "R485" when (IsAdminHost(source) || IsApprovedBacnetController(source) || IsInApprovedOtSegment(record.Source))
                            && (IsApprovedBacnetController(destination) || IsInApprovedOtSegment(record.Destination)) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "BACnet write between approved management/OT source and approved controller/OT destination.",
                        "Approved.BacnetControllers+Approved.OtSegments", $"{source} -> {destination}"),

                "R516" when _services.IsKnownRemoteSupportTool(destination) || _services.IsApprovedProxyServer(destination) || _services.IsApprovedVpnGateway(destination) =>
                    new ApprovedAssetDecision(ApprovedAssetDisposition.Shadow, "Approved tunnel or remote-support destination.", _services.IsKnownRemoteSupportTool(destination) ? "Approved.KnownRemoteSupportTools" : _services.IsApprovedVpnGateway(destination) ? "Approved.VpnGateways" : "Approved.ProxyServers", destination ?? string.Empty),

                _ => null
            };
        }

        private static HashSet<string> ToSet(IEnumerable<string>? values)
            => values?
                .Select(ApprovedDestinationRegistry.Normalize)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
               ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static bool Match(HashSet<string> values, string? candidate)
        {
            var normalized = ApprovedDestinationRegistry.Normalize(candidate);
            return !string.IsNullOrWhiteSpace(normalized) && values.Contains(normalized);
        }

        private static string? FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }

            return null;
        }

        private static bool IpMatchesSegment(string ipText, string segment)
        {
            if (string.IsNullOrWhiteSpace(ipText) || string.IsNullOrWhiteSpace(segment))
                return false;

            if (!IPAddress.TryParse(ipText, out var ip))
                return false;

            if (!segment.Contains('/'))
                return ipText.StartsWith(segment, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(ipText, segment, StringComparison.OrdinalIgnoreCase);

            var parts = segment.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var prefixLength))
                return false;

            var ipBytes = ip.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();
            if (ipBytes.Length != networkBytes.Length)
                return false;

            var fullBytes = prefixLength / 8;
            var remainderBits = prefixLength % 8;
            for (var i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != networkBytes[i])
                    return false;
            }

            if (remainderBits == 0)
                return true;

            var mask = (byte)(0xFF << (8 - remainderBits));
            return (ipBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }
    }
}
