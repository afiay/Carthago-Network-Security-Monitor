// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
// File: Engine/Rules/Expansion/R557_OutboundModbusWritePublicSubnetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates one private IPv4 source issuing bounded Modbus/TCP write
    /// requests to three distinct public destination /24 networks. This is a multi-target
    /// request pattern, not a confirmed write, login, or process change.
    /// </summary>
    public sealed class R557_OutboundModbusWritePublicSubnetFanoutRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R557",
            Name: "Outbound Modbus Write Public-Subnet Fanout",
            Category: "IotOtAdvanced",
            Description: "One RFC1918 source issues bounded Modbus/TCP write requests to three distinct globally routable destination /24s within five minutes; no server outcome is inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R557.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R557",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port", "iot_or_ot_context" },
            evidenceFields: new[] { "modbus.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "Existing PacketHandler and bounded Modbus MBAP/function recognition must identify a client-to-server write request.",
                "One RFC1918 IPv4 source must address three distinct public IPv4 destination /24 networks on TCP/502 within five minutes.",
                "Each observation must have a unique packet ID and coherent TCP/IPv4, source-port and bounded payload-length metadata."
            },
            negativeConditions: new[]
            {
                "Reject Modbus reads, responses, port-only guesses, private destinations, same-/24 retries and contradictory protocol metadata.",
                "Reject missing or malformed TCP/IP context, duplicate packet IDs and out-of-order timestamps.",
                "Do not infer device authorization, authenticated source identity, write acknowledgement, register values, process change or exploitation."
            },
            minimumConfidence: 90,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "private_source+distinct_public_destination_24",
            falsePositives: new[]
            {
                "Approved remote engineering, multi-site controller maintenance, vendor gateways and OT integration tests can produce the same request pattern.",
                "Capture vantage point can obscure NAT and asset roles; source IP and packet metadata do not authenticate the operator or controller."
            },
            tuningKnobs: new[] { "Mode", "ApprovedEngineeringHosts", "ApprovedPublicOtEndpoints", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "bounded Modbus write-positive and read/response negative",
                "port-only, truncated, malformed and contradictory evidence",
                "distinct-public-/24, duplicate, out-of-order and concurrency controls",
                "window expiration and cooldown suppression",
                "redaction, registry uniqueness, candidate/Shadow and confidence-floor invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R557_OutboundModbusWritePublicSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch236240Evidence.ModbusWrite(record)
                || record.IpVersion != 4
                || record.L4Len is null or < 12 or > 260
                || record.Length < record.L4Len.Value + 40
                || record.SourcePort is null or < 1024 or > 65535
                || record.DestinationPort != 502
                || record.Sni != null || record.Alpn != null || record.HttpHost != null || record.HttpUri != null
                || record.HttpMethod != null || record.DnsQname != null || record.DnsQtype != null
                || record.DnsRcode != null
                || record.HttpRequestHeaders != null || record.DnsAnswers != null
                || !IsRfc1918Ipv4(record.Source)
                || !TryPublic24(record.Destination, out var destinationSubnet))
                return NoMatch();

            var key = IPAddress.Parse(record.Source!).ToString();
            var count = _observations.Observe(key, destinationSubnet, record.Id,
                context.TimestampUtc, ObservationWindow, distinctTargets: true);
            if (count != 3)
                return NoMatch();

            lock (_cooldownGate)
            {
                if (_lastEmission.TryGetValue(key, out var previous)
                    && context.TimestampUtc >= previous
                    && context.TimestampUtc - previous < Cooldown)
                    return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

                if (_lastEmission.Count >= 4096 && !_lastEmission.ContainsKey(key))
                {
                    var expired = new List<string>();
                    foreach (var entry in _lastEmission)
                        if (context.TimestampUtc - entry.Value >= Cooldown)
                            expired.Add(entry.Key);
                    foreach (var expiredKey in expired)
                        _lastEmission.Remove(expiredKey);
                    if (_lastEmission.Count >= 4096)
                        return NoMatch();
                }
                _lastEmission[key] = context.TimestampUtc;
            }

            // Do not use MatchIot for this newer ID: its legacy evidence path
            // can retain raw Info. Emit only bounded, typed aggregate evidence.
            var evidence = new[]
            {
                new DetectionEvidenceItem("modbus.operation", "write.request", "bounded-packet-parser"),
                new DetectionEvidenceItem("matched_conditions", "parsed_modbus_write,private_to_public,three_distinct_public_24s", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "502", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Outbound Modbus write-request public-subnet fanout observed (outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.48, "parsed-modbus-write-request");
                    confidence.AddEvidence(0.30, "private-to-public-modbus-boundary");
                    confidence.AddCorrelation(0.18, "three-distinct-public-subnets");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool IsRfc1918Ipv4(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168);
        }

        private static bool TryPublic24(string? address, out string subnet)
        {
            subnet = string.Empty;
            if (!IsPublicUnicastIpv4(address)) return false;
            var bytes = IPAddress.Parse(address!).GetAddressBytes();
            subnet = string.Concat(bytes[0].ToString(CultureInfo.InvariantCulture), ".",
                bytes[1].ToString(CultureInfo.InvariantCulture), ".",
                bytes[2].ToString(CultureInfo.InvariantCulture));
            return true;
        }

        private static bool IsPublicUnicastIpv4(string? address)
        {
            if (!NetworkBatch226230Evidence.Public(address)
                || !IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (b[0] is 0 or 10 or 127 or >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 192 && (b[1] == 0 || b[1] == 2 || b[1] == 88 && b[2] == 99)
                || b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            return true;
        }
    }
}
