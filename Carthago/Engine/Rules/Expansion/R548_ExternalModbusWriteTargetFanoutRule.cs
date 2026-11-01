// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R548_ExternalModbusWriteTargetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Flags a single public IPv4 source addressing parsed Modbus/TCP write
    /// requests to three distinct private targets. This is a multi-target
    /// request pattern, not a confirmed write, login, or process change.
    /// </summary>
    public sealed class R548_ExternalModbusWriteTargetFanoutRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R548",
            Name: "External Modbus Write Target Fanout",
            Category: "IotOtAdvanced",
            Description: "One public IPv4 source addresses parsed Modbus/TCP write requests to three distinct RFC1918 targets within five minutes; no server outcome is inferred.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R548.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R548",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port", "iot_or_ot_context" },
            evidenceFields: new[] { "modbus.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "Existing PacketHandler and bounded Modbus MBAP/function recognition must identify a client-to-server write request.",
                "One public unicast IPv4 source must address three distinct RFC1918 IPv4 destinations on TCP/502 within five minutes.",
                "Each observation must have a unique packet ID and coherent TCP/IPv4, source-port and bounded payload-length metadata."
            },
            negativeConditions: new[]
            {
                "Reject Modbus reads, responses, port-only guesses, internal maintenance traffic, one-target retries and contradictory protocol metadata.",
                "Reject missing or malformed TCP/IP context, duplicate packet IDs and out-of-order timestamps.",
                "Do not infer device authorization, authenticated source identity, write acknowledgement, register values, process change or exploitation."
            },
            minimumConfidence: 90,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "public_source+distinct_rfc1918_modbus_target",
            falsePositives: new[]
            {
                "Authorized remote engineering, VPN/NAT gateway forwarding, multi-PLC commissioning and maintenance can produce the same request pattern.",
                "Capture vantage point can obscure pre-NAT addresses; source IP and packet metadata do not authenticate the operator."
            },
            tuningKnobs: new[] { "Mode", "ApprovedEngineeringHosts", "ApprovedOtGateways", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "bounded Modbus write-positive and read/response negative",
                "port-only, truncated, malformed and contradictory evidence",
                "distinct-target, duplicate, out-of-order and concurrency controls",
                "window expiration and cooldown suppression",
                "redaction, registry uniqueness, candidate/Shadow and confidence-floor invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R548_ExternalModbusWriteTargetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch236240Evidence.ModbusWrite(record)
                || record.IpVersion != 4
                || record.L4Len is null or < 12 or > 260
                || record.SourcePort is null or < 1 or > 65535 or 502
                || record.DestinationPort != 502
                || record.Sni != null || record.HttpHost != null || record.HttpUri != null
                || record.HttpRequestHeaders != null || record.DnsAnswers != null
                || !IsPublicUnicastIpv4(record.Source)
                || !IsRfc1918Ipv4(record.Destination))
                return NoMatch();

            var key = record.Source!;
            var count = _observations.Observe(key, record.Destination, record.Id,
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
                new DetectionEvidenceItem("matched_conditions", "parsed_modbus_write,public_to_rfc1918,three_distinct_targets", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "502", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Critical,
                "External Modbus write-request target fanout observed (outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.48, "parsed-modbus-write-request");
                    confidence.AddEvidence(0.30, "public-to-private-modbus-boundary");
                    confidence.AddCorrelation(0.18, "three-distinct-private-targets");
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

        private static bool IsPublicUnicastIpv4(string? address)
        {
            if (!NetworkBatch226230Evidence.Public(address)
                || !IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (b[0] is 0 or 10 or 127 or >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 192 && (b[1] == 0 || b[1] == 88 && b[2] == 99)
                || b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            return true;
        }
    }
}
