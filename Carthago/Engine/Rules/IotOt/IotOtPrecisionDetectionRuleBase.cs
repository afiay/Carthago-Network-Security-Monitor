// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.IotOt
{
    public abstract class IotOtPrecisionDetectionRuleBase : PrecisionTelemetryDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<int> MqttPorts = new() { 1883, 8883, 8884 };
        private static readonly HashSet<int> CoapPorts = new() { 5683, 5684 };
        private static readonly HashSet<int> RtspPorts = new() { 554, 8554 };
        private static readonly HashSet<int> BacnetPorts = new() { 47808 };
        private static readonly HashSet<int> ModbusPorts = new() { 502 };
        private static readonly HashSet<int> TelnetPorts = new() { 23 };
        private static readonly HashSet<int> UpnpPorts = new() { 1900 };

        private static readonly string[] PublicMqttBrokerHosts =
        {
            "shiftr.io", "hivemq.cloud", "cloudmqtt.com", "emqxsl.com", "mqtt-dashboard.com", "broker.hivemq.com", "test.mosquitto.org"
        };

        private static readonly string[] DeviceKeywords =
        {
            "camera", "nvr", "dvr", "onvif", "rtsp", "hikvision", "dahua", "axis",
            "router", "switch", "gateway", "zigbee", "zigbee2mqtt", "coap",
            "mqtt", "plc", "modbus", "bacnet", "hvac", "iot", "ubiquiti", "tplink", "dlink", "netgear", "mikrotik"
        };

        private static readonly string[] BacnetAdminKeywords =
        {
            "niagara", "metasys", "ecostruxure", "desigo", "bms", "building", "hvac", "administrator", "admin"
        };

        private static readonly Regex TopicRegex = new(@"(?i)topic\s*[:=]\s*(?<topic>[^\s,;]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        protected IotOtPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        internal static void ResetSharedStateForReplay()
        {
            TimeWindows.Clear();
            DistinctWindows.Clear();
            CooldownWindows.Clear();
        }

        protected RuleEvaluationResult NoMatch()
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId);

        protected RuleEvaluationResult MatchIot(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            string protocolFamily,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder> configureConfidence,
            int count = 1,
            TimeSpan? window = null,
            string? cooldownKey = null)
        {
            var record = context.Record;
            var host = BestHost(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("iot.protocolFamily", protocolFamily, "iot-ot"),
                new("iot.host", Descriptor.RuleId is "R223" or "R224" or "R225" or "R226" or "R227" or "R228" or "R229" or "R230" or "R231" or "R232" or "R233" or "R234" or "R235" ? "[REDACTED]" : string.IsNullOrWhiteSpace(host) ? record.Destination ?? "unknown" : host, "iot-ot")
            };

            if (record.DestinationPort.HasValue)
                items.Add(new DetectionEvidenceItem("network.destinationPort", record.DestinationPort.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "network"));
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));
            // IoT/OT Info may contain credentials, device identifiers, RTSP URLs or
            // private discovery payloads. For R113-R122 never persist raw Info
            // in either legacy or structured evidence, including shadow events.
            if (Descriptor.RuleId is not ("R113" or "R114" or "R115" or "R116" or "R117" or "R118" or "R119" or "R120" or "R121" or "R122" or "R223" or "R224" or "R225" or "R226" or "R227" or "R228" or "R229" or "R230" or "R231" or "R232" or "R233" or "R234" or "R235")
                && !string.IsNullOrWhiteSpace(record.Info))
                items.Add(new DetectionEvidenceItem("iot.info", ShortText(record.Info!, 220), "iot-ot"));

            if (evidenceItems != null)
                items.AddRange(evidenceItems);

            var evt = CreateDetectionEvent(
                context,
                severity,
                summary,
                items,
                configureConfidence,
                count,
                window.HasValue ? (int)window.Value.TotalSeconds : 0);

            var effectiveCooldownKey = string.IsNullOrWhiteSpace(cooldownKey) ? null : $"{Descriptor.RuleId}:{cooldownKey}";
            var cooldown = PrecisionProfile.Cooldown ?? TimeSpan.Zero;
            if (effectiveCooldownKey != null
                && cooldown > TimeSpan.Zero
                && IsSuppressedByCooldown(effectiveCooldownKey, context.TimestampUtc, cooldown, out var remaining))
            {
                SuppressForCooldown(evt, $"Rule-owned cooldown active for {remaining.TotalSeconds:F0}s.");
                EvidenceBuilder.AppendEvidence(evt, "suppression.remainingSeconds", Math.Ceiling(remaining.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule");
            }

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        protected static IEnumerable<DetectionEvidenceItem> AnalystContext(
            string whyMatched,
            string severityReason,
            string falsePositiveNotes,
            params string[] recommendedActions)
        {
            var items = new List<DetectionEvidenceItem>();
            if (!string.IsNullOrWhiteSpace(whyMatched))
                items.Add(new DetectionEvidenceItem("analyst.whyMatched", whyMatched.Trim(), "rule"));
            if (!string.IsNullOrWhiteSpace(severityReason))
                items.Add(new DetectionEvidenceItem("analyst.severityReason", severityReason.Trim(), "rule"));
            if (!string.IsNullOrWhiteSpace(falsePositiveNotes))
                items.Add(new DetectionEvidenceItem("analyst.falsePositives", falsePositiveNotes.Trim(), "rule"));

            for (var index = 0; index < recommendedActions.Length; index++)
            {
                if (!string.IsNullOrWhiteSpace(recommendedActions[index]))
                    items.Add(new DetectionEvidenceItem($"response.recommended.{index + 1}", recommendedActions[index].Trim(), "rule"));
            }

            return items;
        }

        protected static string BestHost(TrafficRecord record)
            => NormalizeHost(FirstNonEmpty(record.HttpHost, record.Sni, record.DnsQname, record.Destination)) ?? string.Empty;

        protected static string Text(TrafficRecord record)
            => string.Join(" ", new[]
            {
                record.Info,
                record.Protocol,
                record.ApplicationProtocol,
                record.ApplicationService,
                record.HttpMethod,
                record.HttpHost,
                record.HttpUri,
                record.HttpUserAgent,
                record.HttpRequestHeaders,
                record.Sni,
                record.DnsQname,
                record.DnsQtype,
                record.ProcessName
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

        protected static bool IsInternalAddress(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost))
                return false;

            var host = ipOrHost.Trim();
            if (!IPAddress.TryParse(host, out var ip))
            {
                var normalized = NormalizeHost(host) ?? string.Empty;
                return normalized.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".corp", StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith(".home", StringComparison.OrdinalIgnoreCase);
            }

            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || bytes[0] == 127
                    || (bytes[0] == 169 && bytes[1] == 254);
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return ip.IsIPv6LinkLocal
                    || ip.IsIPv6SiteLocal
                    || host.StartsWith("fc", StringComparison.OrdinalIgnoreCase)
                    || host.StartsWith("fd", StringComparison.OrdinalIgnoreCase)
                    || IPAddress.IsLoopback(ip);
            }

            return false;
        }

        protected static bool IsExternalAddress(string? ipOrHost)
            => !string.IsNullOrWhiteSpace(ipOrHost) && !IsMulticastOrBroadcast(ipOrHost) && !IsInternalAddress(ipOrHost);

        protected static bool IsMqtt(TrafficRecord record)
        {
            var text = Text(record);
            return MqttPorts.Contains(record.SourcePort ?? -1)
                   || MqttPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(record.ApplicationProtocol, "mqtt")
                   || ContainsAny(record.ApplicationService, "mqtt")
                   || ContainsAny(text, "connack", "subscribe", "publish", "puback", "pubrel", "clientid=");
        }

        protected static bool IsPublicMqttBroker(string? host)
            => MatchesAnyHost(host, PublicMqttBrokerHosts);

        protected static bool IsUpnp(TrafficRecord record)
        {
            var text = Text(record);
            return UpnpPorts.Contains(record.SourcePort ?? -1)
                   || UpnpPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(record.ApplicationProtocol, "ssdp", "upnp")
                   || ContainsAny(record.ApplicationService, "ssdp", "upnp")
                   || (record.IsUdp && ContainsAny(text, "upnp", "ssdp", "m-search", "ssdp:discover"));
        }

        protected static bool IsTelnetContext(TrafficRecord record)
        {
            var text = Text(record);
            return TelnetPorts.Contains(record.SourcePort ?? -1)
                   || TelnetPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(text, "telnet", "login:", "password:", "username");
        }

        protected static bool IsCameraNvrContext(TrafficRecord record)
        {
            var text = Text(record);
            return RtspPorts.Contains(record.SourcePort ?? -1)
                   || RtspPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(text, "camera", "nvr", "dvr", "rtsp", "onvif", "hikvision", "dahua", "axis");
        }

        protected static bool IsModbusContext(TrafficRecord record)
        {
            var text = Text(record);
            return ModbusPorts.Contains(record.SourcePort ?? -1)
                   || ModbusPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(record.ApplicationProtocol, "modbus")
                   || ContainsAny(record.ApplicationService, "modbus")
                   || (ContainsAny(text, "modbus") && ContainsAny(text, "register", "coil", "function"));
        }

        protected static bool IsBacnetContext(TrafficRecord record)
            => BacnetPorts.Contains(record.SourcePort ?? -1)
               || BacnetPorts.Contains(record.DestinationPort ?? -1)
               || ContainsAny(record.ApplicationProtocol, "bacnet")
               || ContainsAny(record.ApplicationService, "bacnet");

        protected static bool IsCoapZigbeeContext(TrafficRecord record)
        {
            var text = Text(record);
            return CoapPorts.Contains(record.SourcePort ?? -1)
                   || CoapPorts.Contains(record.DestinationPort ?? -1)
                   || ContainsAny(record.ApplicationProtocol, "coap", "zigbee")
                   || ContainsAny(record.ApplicationService, "coap", "zigbee")
                   || (ContainsAny(text, "zigbee2mqtt", "gateway", "zcl") && ContainsAny(record.ProcessName, "gateway", "zigbee", "iot"));
        }

        protected static bool IsDefaultCredentialContext(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, "authorization", "basic ", "login", "username", "password", "telnet", "http", "admin", "factory default");
        }

        protected static bool HasDefaultCredentialToken(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, "admin:admin", "admin:password", "root:root", "root:admin", "user:user", "guest:guest", "ubnt:ubnt", "support:support", "default password", "factory default");
        }

        protected static bool IsLikelyIotDeviceTarget(TrafficRecord record)
        {
            var text = Text(record);
            return ContainsAny(text, DeviceKeywords)
                   || RtspPorts.Contains(record.DestinationPort ?? -1)
                   || MqttPorts.Contains(record.DestinationPort ?? -1)
                   || record.DestinationPort is 23 or 554 or 8554;
        }

        protected static bool IsLikelyBacnetAdminProcess(string? processName, string? info)
            => ContainsAny(processName, BacnetAdminKeywords) || ContainsAny(info, BacnetAdminKeywords);

        protected static bool IsLikelyBrowserProcess(string? processName)
            => ContainsAny(processName, "chrome", "msedge", "edge", "firefox", "brave", "opera", "iexplore", "safari");

        protected static bool IsMulticastOrBroadcast(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost))
                return false;

            if (!IPAddress.TryParse(ipOrHost.Trim(), out var ip))
                return ContainsAny(ipOrHost, "255.255.255.255");

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                return bytes[0] >= 224 && bytes[0] <= 239 || ip.Equals(IPAddress.Broadcast);
            }

            return ip.IsIPv6Multicast;
        }

        protected static bool SharesSame24(string? left, string? right)
        {
            if (!IPAddress.TryParse(left, out var leftIp) || !IPAddress.TryParse(right, out var rightIp))
                return false;

            if (leftIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || rightIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            var leftBytes = leftIp.GetAddressBytes();
            var rightBytes = rightIp.GetAddressBytes();
            return leftBytes[0] == rightBytes[0] && leftBytes[1] == rightBytes[1] && leftBytes[2] == rightBytes[2];
        }

        protected static string ExtractTopic(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            var match = TopicRegex.Match(text);
            return match.Success ? match.Groups["topic"].Value : string.Empty;
        }

        protected static string NormalizeTopic(string? topic)
            => string.IsNullOrWhiteSpace(topic) ? string.Empty : topic.Trim().Trim('"', '\'');

        protected static bool LooksLikeWildcardTopic(string? topic)
        {
            var normalized = NormalizeTopic(topic);
            return normalized.Contains("/#", StringComparison.Ordinal)
                   || normalized.Contains("/+", StringComparison.Ordinal)
                   || string.Equals(normalized, "#", StringComparison.Ordinal)
                   || string.Equals(normalized, "+", StringComparison.Ordinal);
        }

        protected static int CountWindowEvents(string key, DateTime now, TimeSpan window)
        {
            var list = TimeWindows.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(now);
                list.RemoveAll(timestamp => now - timestamp > window);
                return list.Count;
            }
        }

        protected static int CountDistinctValues(string key, string value, DateTime now, TimeSpan window)
        {
            var map = DistinctWindows.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            map[value] = now;
            foreach (var item in map.ToArray())
            {
                if (now - item.Value > window)
                    map.TryRemove(item.Key, out _);
            }

            return map.Count;
        }

        protected static int IntSetting(string ruleId, string key, int defaultValue, int min, int max)
            => RuleEngine.GetRuleIntSetting(ruleId, key, defaultValue, min, max);

        protected static RulePrecisionProfile CreateIotOtProfile(
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
        {
            return new RulePrecisionProfile(
                ruleId,
                maturity,
                defaultMode,
                new HashSet<RuleTelemetryKind>(requiredTelemetry),
                new HashSet<string>(requiredFields, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(new[] { "process.name", "geo.country", "whois.organization" }, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(evidenceFields, StringComparer.OrdinalIgnoreCase),
                positiveConditions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                negativeConditions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                minimumConfidence,
                threshold,
                window,
                cooldown,
                distinctBy,
                falsePositives.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                tuningKnobs.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Array.Empty<string>(),
                requiredTests.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        protected static string ShortText(string value, int maxLength = 160)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
                return value;

            return value[..maxLength] + "...";
        }

        private static bool ContainsAny(string? value, IEnumerable<string> needles)
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

        private static bool ContainsAny(string? value, params string[] needles)
            => ContainsAny(value, (IEnumerable<string>)needles);

        private static bool MatchesAnyHost(string? host, IEnumerable<string> suffixes)
        {
            var normalizedHost = NormalizeHost(host) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalizedHost))
                return false;

            foreach (var suffix in suffixes)
            {
                var normalizedSuffix = NormalizeHost(suffix) ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(normalizedSuffix)
                    && (string.Equals(normalizedHost, normalizedSuffix, StringComparison.OrdinalIgnoreCase)
                        || normalizedHost.EndsWith("." + normalizedSuffix, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            return false;
        }

        private static string? NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return null;

            var trimmed = host.Trim().TrimEnd('.').ToLowerInvariant();
            if ((trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                && Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
            {
                return absolute.Host.Trim().TrimEnd('.').ToLowerInvariant();
            }

            if (trimmed.Contains('/') && Uri.TryCreate("https://" + trimmed, UriKind.Absolute, out var partial))
                return partial.Host.Trim().TrimEnd('.').ToLowerInvariant();

            if (trimmed.Count(character => character == ':') == 1
                && trimmed.Contains('.')
                && trimmed.LastIndexOf(':') > trimmed.LastIndexOf(']'))
            {
                trimmed = trimmed[..trimmed.LastIndexOf(':')];
            }

            return trimmed;
        }

        private static bool IsSuppressedByCooldown(string key, DateTime now, TimeSpan cooldown, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            if (CooldownWindows.TryGetValue(key, out var previous) && now - previous < cooldown)
            {
                remaining = cooldown - (now - previous);
                return true;
            }

            CooldownWindows[key] = now;
            return false;
        }
    }
}
