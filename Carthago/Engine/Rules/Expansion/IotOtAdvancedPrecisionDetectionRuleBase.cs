// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/IotOtAdvancedPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.IotOt;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class IotOtAdvancedPrecisionDetectionRuleBase : IotOtPrecisionDetectionRuleBase
    {
        private static readonly HashSet<int> Dnp3Ports = new() { 20000 };
        private static readonly HashSet<int> S7Ports = new() { 102 };
        private static readonly HashSet<int> CipPorts = new() { 44818 };
        private static readonly HashSet<int> ProfinetPorts = new() { 34964 };
        private static readonly HashSet<int> OpcUaPorts = new() { 4840 };
        private static readonly HashSet<int> MdnsPorts = new() { 5353 };
        private static readonly HashSet<int> PrinterPorts = new() { 515, 631, 9100 };
        private static readonly HashSet<int> OnvifPorts = new() { 3702 };
        private static readonly HashSet<int> NtpPorts = new() { 123 };
        private static readonly HashSet<int> CleartextHttpPorts = new() { 80, 8080, 8000, 8008, 8888 };

        private static readonly string[] SmartHomeHubVendorHosts =
        {
            "tuya", "smartthings", "philips-hue", "meethue", "aqara", "eufy", "xiaomi", "mi.com", "home-assistant", "nabucasa"
        };

        private static readonly string[] SmartHomeHubProcessHints =
        {
            "homeassistant", "hass", "hub", "bridge", "gateway", "tuya", "hue", "aqara", "eufy", "xiaomi", "smartthings"
        };

        private static readonly string[] AutomationProcessHints =
        {
            "python", "powershell", "pwsh", "cmd", "wscript", "cscript", "curl", "wget", "node", "perl", "java"
        };

        private static readonly string[] WorkstationProcessHints =
        {
            "python", "powershell", "pwsh", "cmd", "curl", "wget", "chrome", "msedge", "edge", "firefox", "brave", "iexplore", "putty"
        };

        private static readonly string[] CameraProcessHints =
        {
            "camera", "nvr", "dvr", "onvif", "rtsp", "hikvision", "dahua", "axis"
        };

        protected IotOtAdvancedPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected static RulePrecisionProfile CreateIotOtAdvancedProfile(
            string ruleId,
            RulePrecisionMaturity maturity,
            RuleRuntimeMode defaultMode,
            IReadOnlyCollection<RuleTelemetryKind> requiredTelemetry,
            IReadOnlyCollection<string> requiredFields,
            IReadOnlyCollection<string> evidenceFields,
            IReadOnlyCollection<string> positiveConditions,
            IReadOnlyCollection<string> negativeConditions,
            int minimumConfidence,
            int? threshold,
            TimeSpan? window,
            TimeSpan? cooldown,
            string? distinctBy,
            IReadOnlyCollection<string> falsePositives,
            IReadOnlyCollection<string> tuningKnobs,
            IReadOnlyCollection<string> requiredTests)
            => CreateIotOtProfile(
                ruleId,
                maturity,
                defaultMode,
                requiredTelemetry,
                requiredFields,
                evidenceFields,
                positiveConditions,
                negativeConditions,
                minimumConfidence,
                threshold,
                window,
                cooldown,
                distinctBy,
                falsePositives,
                tuningKnobs,
                requiredTests);

        protected static bool IsInternalToExternal(TrafficRecord record)
            => IsInternalAddress(record.Source) && IsExternalAddress(record.Destination);

        protected static bool IsUnexpectedSegmentCrossing(TrafficRecord record)
            => IsExternalAddress(record.Source)
               || IsExternalAddress(record.Destination)
               || (IsInternalAddress(record.Source) && IsInternalAddress(record.Destination) && !SharesSame24(record.Source, record.Destination));

        protected static bool IsDnp3Context(TrafficRecord record)
        {
            var text = Text(record);
            return Dnp3Ports.Contains(record.SourcePort ?? -1)
                   || Dnp3Ports.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "dnp3")
                   || ContainsAnyValue(record.ApplicationService, "dnp3")
                   || (ContainsAnyValue(text, "dnp3") && ContainsAnyValue(text, "outstation", "master", "integrity", "crob", "freeze", "operate", "select"));
        }

        protected static bool IsS7Context(TrafficRecord record)
        {
            var text = Text(record);
            return S7Ports.Contains(record.SourcePort ?? -1)
                   || S7Ports.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "s7", "s7comm")
                   || ContainsAnyValue(record.ApplicationService, "s7", "s7comm")
                   || (ContainsAnyValue(text, "s7", "s7comm", "plc") && ContainsAnyValue(text, "setup communication", "read var", "write var", "job"));
        }

        protected static bool IsCipContext(TrafficRecord record)
        {
            var text = Text(record);
            return CipPorts.Contains(record.SourcePort ?? -1)
                   || CipPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "cip", "ethernet/ip", "ethernetip")
                   || ContainsAnyValue(record.ApplicationService, "cip", "ethernet/ip", "ethernetip")
                   || (ContainsAnyValue(text, "cip", "ethernet/ip", "ethernetip") && ContainsAnyValue(text, "listidentity", "list identity", "registersession", "forward open"));
        }

        protected static bool HasCipDiscoverySemantics(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAnyValue(text, "listidentity", "list identity", "cip discovery", "discover");
        }

        protected static bool IsProfinetContext(TrafficRecord record)
        {
            var text = Text(record);
            return ProfinetPorts.Contains(record.SourcePort ?? -1)
                   || ProfinetPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "profinet", "dcp")
                   || ContainsAnyValue(record.ApplicationService, "profinet", "dcp")
                   || (ContainsAnyValue(text, "profinet", "dcp") && ContainsAnyValue(text, "identify", "name of station", "station name", "set name"));
        }

        protected static bool HasProfinetDiscoverySemantics(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAnyValue(text, "identify all", "identify", "dcp identify", "name of station", "station name");
        }

        protected static bool IsOpcUaContext(TrafficRecord record)
        {
            var text = Text(record);
            return OpcUaPorts.Contains(record.SourcePort ?? -1)
                   || OpcUaPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "opc ua", "opcua")
                   || ContainsAnyValue(record.ApplicationService, "opc ua", "opcua")
                   || ContainsAnyValue(text, "opc ua", "opcua", "opc.tcp://", "createsession", "browse request", "read request", "write request", "writevalue");
        }

        protected static bool IsMdnsContext(TrafficRecord record)
        {
            var text = Text(record);
            return MdnsPorts.Contains(record.SourcePort ?? -1)
                   || MdnsPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "mdns", "bonjour")
                   || ContainsAnyValue(record.ApplicationService, "mdns", "bonjour")
                   || ContainsAnyValue(text, "_services._dns-sd._udp", "mdns", "bonjour");
        }

        protected static bool HasMdnsEnumerationSemantics(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAnyValue(record.DnsQname, "_services._dns-sd._udp")
                   || ContainsAnyValue(text, "_services._dns-sd._udp", "service enumeration", "bonjour browse");
        }

        protected static bool IsPrinterAdminContext(TrafficRecord record)
        {
            var text = Text(record);
            return PrinterPorts.Contains(record.SourcePort ?? -1)
                   || PrinterPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "ipp", "jetdirect", "printer")
                   || ContainsAnyValue(record.ApplicationService, "ipp", "jetdirect", "printer")
                   || ContainsAnyValue(text, "ipp", "printer", "jetdirect", "pjl", "cups");
        }

        protected static bool HasPrinterAdminSemantics(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAnyValue(record.HttpUri, "/printers/", "/ipp", "/admin", "/jobs")
                   || ContainsAnyValue(text, "@pjl", "printer attributes", "get-printer-attributes", "ipp/2.0", "cups");
        }

        protected static bool IsOnvifContext(TrafficRecord record)
        {
            var text = Text(record);
            return OnvifPorts.Contains(record.SourcePort ?? -1)
                   || OnvifPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAnyValue(record.ApplicationProtocol, "onvif", "ws-discovery")
                   || ContainsAnyValue(record.ApplicationService, "onvif", "ws-discovery")
                   || ContainsAnyValue(text, "onvif", "ws-discovery", "probe", "probes");
        }

        protected static bool HasOnvifDiscoverySemantics(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAnyValue(text, "probe", "probe match", "ws-discovery", "onvif discovery");
        }

        protected static bool IsCleartextHttp(TrafficRecord record)
        {
            var protocol = FirstNonEmpty(record.ApplicationProtocol, record.ApplicationService, record.Protocol) ?? string.Empty;
            return !string.IsNullOrWhiteSpace(record.HttpMethod)
                   && !ContainsAnyValue(protocol, "https", "tls", "ssl")
                   && !ContainsAnyValue(record.Info, "https://")
                   && (!record.DestinationPort.HasValue || CleartextHttpPorts.Contains(record.DestinationPort.Value) || record.DestinationPort.Value == 80);
        }

        protected static bool LooksLikeFirmwareArtifact(TrafficRecord record)
        {
            var text = string.Join(" ", new[] { record.HttpUri, record.HttpRequestHeaders, record.Info }.Where(static value => !string.IsNullOrWhiteSpace(value))!);
            return ContainsAnyValue(text, "firmware", "upgrade", "ota", "update.bin", ".bin", ".img", ".fw", ".trx", ".rom");
        }

        protected static bool HasDefaultWebAdminPath(TrafficRecord record)
            => ContainsAnyValue(record.HttpUri, "/login.cgi", "/goform/", "/setup.cgi", "/webcm", "/cgi-bin/luci", "/boaform/");

        protected static bool HasDefaultAdminCredential(TrafficRecord record)
            => HasDefaultCredentialToken(record)
               || ContainsAnyValue(Text(record), "admin/password", "password=admin", "username=admin");

        protected static bool IsSmartHomeHubVendorHost(string? host)
            => ContainsAnyValue(host, SmartHomeHubVendorHosts);

        protected static bool IsHubLikeProcess(string? processName)
            => ContainsAnyValue(processName, SmartHomeHubProcessHints);

        protected static bool HasSmartHomeHubTelemetryContext(TrafficRecord record)
            => ContainsAnyValue(Text(record), "telemetry", "heartbeat", "sync", "device status", "cloud api", "hub")
               || IsHubLikeProcess(record.ProcessName);

        protected static bool IsZigbee2MqttBridge(TrafficRecord record)
            => ContainsAnyValue(Text(record), "zigbee2mqtt", "z2m") || ContainsAnyValue(record.ProcessName, "zigbee2mqtt", "z2m");

        protected static bool HasRetainIndicator(TrafficRecord record)
            => ContainsAnyValue(Text(record), "retain=1", "retain true", "retain=true", "retained", "retained message");

        protected static bool HasWillIndicator(TrafficRecord record)
            => ContainsAnyValue(Text(record), "last will", "will topic", "will message", "lwt");

        protected static bool IsSuspiciousMqttControlTopic(string? topic)
        {
            var normalized = NormalizeTopic(topic);
            return ContainsAnyValue(normalized, "/cmd", "/command", "/control", "/admin", "/bridge", "/broadcast", "/all", "$sys")
                   || LooksLikeWildcardTopic(normalized);
        }

        protected static bool IsAutomationLikeProcess(string? processName)
            => ContainsAnyValue(processName, AutomationProcessHints);

        protected static bool IsWorkstationLikeProcess(string? processName)
            => ContainsAnyValue(processName, WorkstationProcessHints);

        protected static bool IsCameraLikeProcess(string? processName)
            => ContainsAnyValue(processName, CameraProcessHints);

        protected static bool HasModbusWriteSemantics(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAnyValue(text, "write single coil", "write single register", "write multiple coils", "write multiple registers", "function 5", "function 6", "function 15", "function 16");
        }

        protected static bool HasBacnetWhoIsIAmSemantics(TrafficRecord record)
            => ContainsAnyValue(Text(record), "who-is", "whois", "i-am", "iam");

        protected static bool HasNtpAmplificationSemantics(TrafficRecord record)
        {
            var text = Text(record);
            return record.IsUdp
                   && (NtpPorts.Contains(record.SourcePort ?? -1) || NtpPorts.Contains(record.DestinationPort ?? -1))
                   && ContainsAnyValue(text, "monlist", "ntpdc", "mode 7", "readvar", "read variables");
        }

        protected static bool ContainsAnyValue(string? value, IEnumerable<string> needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        protected static bool ContainsAnyValue(string? value, params string[] needles)
            => ContainsAnyValue(value, (IEnumerable<string>)needles);
    }
}
