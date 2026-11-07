// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2744.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R771_PublicSnmpQueryBurstToPrivateHostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R771",
            Name: "Public-source SNMP/161 query burst to private host",
            Category: "IotOtAdvanced",
            Description: "A public source sends twelve coherent UDP/161 observations to one private host within ten seconds. SNMP GETBULK/GETNEXT semantics, community strings, authentication state, exact OIDs and MIB-dump completion are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R771.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R771",
            Name = "Public-source SNMP/161 query burst to private host",
            Category = "IotOtAdvanced",
            Description = "workbook.R2744: the workbook analytic describes SNMP MIB enumeration and repeated GETBULK/GETNEXT queries. Carthago lacks SNMP PDU/OID decoding, so this candidate keeps only an external high-rate UDP/161 query shape.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "udp", "destination.port", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and this rule's exact independent predicate.",
                "Process attribution is best-effort local tuple enrichment, not authenticated endpoint process identity.",
                "Stateful candidates accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command lines, approved asset role, credentials, authentication success, C2 control, transfer completion, DoS impact or compromise."
            },
            FalsePositives = new[] { "External monitoring relays, managed-service providers, inventory scanners and authorized SNMP diagnostics can legitimately generate short query bursts." },
            MinimumConfidence = 78,
            WindowThreshold = 12,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_source+private_snmp_target+udp161_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped case and benign near miss",
                "missing/contradictory telemetry",
                "duplicate ID, reverse-time and expiry for stateful candidates",
                "cooldown suppression and recovery",
                "privacy/redaction, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _window = new();

        public R771_PublicSnmpQueryBurstToPrivateHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.PublicSnmpToPrivate(r)
                || !_window.Observe(r.Source + "|" + r.Destination,
                    r.Id, r.L4Len!.Value, context.TimestampUtc, 12, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2744", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_source_private_snmp_udp161_burst", "rule"),
                new DetectionEvidenceItem("outcome", "snmp_port_query_burst_only_mib_semantics_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public-source SNMP/161 query burst to a private host observed; PDU type, OIDs, credentials and MIB-dump outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 12,
                windowSeconds: 10);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
