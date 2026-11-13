// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2725, AN1870.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R968_PublicModbusSameRegisterWriteBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R968", Name: "Public Modbus repeated same-register write requests", Category: "IotOtAdvanced",
            Description: "Five distinct client source ports deliver capture-qualified Modbus TCP function 06 first requests to the same private peer, unit and register within ten seconds. Scan-cycle deviation, authorization and write outcome are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R968.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R968", Name = "Public Modbus repeated same-register write requests", Category = "IotOtAdvanced",
            Description = "workbook.R2725 AN1870: narrow same-point cross-connection burst; no claim of scan-cycle violation or physical effect.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "modbus.single_register_write.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Five separate source ports with complete SYN-anchored first client function 06 requests to one destination/unit/register within ten seconds." },
            NegativeConditions = new[] { "Read, different point/peer/source, incomplete framing, absent SYN boundary, retransmissions, repeated port and stale observations do not satisfy the burst." },
            FalsePositives = new[] { "Authorized commissioning, recovery, reconnecting control clients and maintenance can produce the same pattern." },
            MinimumConfidence = 80, WindowThreshold = 5, Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "source_destination_unit_register_distinct_client_ports",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw TCP capture positive and read negative", "MBAP boundaries, missing SYN and retransmission", "same-point/peer/source isolation",
                "four versus five and ten-second boundary", "duplicate IDs/reverse UTC, cooldown and independent instances", "privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly RegisterBurstWindow _window = new();
        public R968_PublicModbusSameRegisterWriteBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 502 || r.SourcePort == 502 || r.L4Len != 12 ||
                r.ModbusSingleRegisterWritePoint is not uint point ||
                r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null || r.DnsIsResponse ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + point;
            if (!_window.Observe(key, r.SourcePort!.Value, r.Id, context.TimestampUtc)) return NoMatch();
            // Cooldown is scoped to this exact point as well as both peers.
            var status = _cooldown.Observe(r.Source!, r.Destination + "|" + point, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2725", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "five_capture_decoded_distinct_port_same_register_writes", "rule"),
                new DetectionEvidenceItem("outcome", "request_burst_only_scan_cycle_authorization_and_effect_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Repeated external Modbus single-register write requests to one point observed; authorization, scan-cycle deviation and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.48, "complete_modbus_request_structure");
                    confidence.AddEvidence(0.30, "public_to_private_management_boundary");
                    confidence.AddCorrelation(0.12, "same_point_distinct_port_burst");
                }, count: 5, windowSeconds: 10);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }

    // Per-rule bounded sliding window. Retain at most 32 observations for
    // each of 512 point keys; no register value or wire payload is stored.
    internal sealed class RegisterBurstWindow
    {
        private sealed class Slot
        {
            internal DateTime Latest = DateTime.MinValue;
            internal readonly List<(int Port, Guid Id, DateTime At)> Entries = new();
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
        internal bool Observe(string key, int port, Guid id, DateTime at)
        {
            if (at.Kind != DateTimeKind.Utc || id == Guid.Empty || port is < 1 or > 65535)
                return false;
            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots.Where(x => at >= x.Value.Latest &&
                            at - x.Value.Latest > TimeSpan.FromMinutes(10)).Select(x => x.Key).ToArray())
                            _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }
                    slot = new Slot();
                    _slots.Add(key, slot);
                }
                if (at <= slot.Latest || slot.Entries.Any(x => x.Id == id)) return false;
                slot.Entries.RemoveAll(x => at - x.At > TimeSpan.FromSeconds(10));
                if (slot.Entries.Any(x => x.Port == port) || slot.Entries.Count >= 32) return false;
                slot.Entries.Add((port, id, at));
                slot.Latest = at;
                return slot.Entries.Count >= 5;
            }
        }
    }
}
