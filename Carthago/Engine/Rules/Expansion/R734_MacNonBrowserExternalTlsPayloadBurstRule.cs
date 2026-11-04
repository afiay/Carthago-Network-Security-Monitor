// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook workbook.R1949.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R734_MacNonBrowserExternalTlsPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R734",
            Name: "macOS non-browser process external TLS payload burst",
            Category: "ExfiltrationAdvanced",
            Description: "A non-browser macOS scripting/utility process produces four substantial TLS/443 payload observations to one public peer within two minutes. Known text-storage, code-repository and cloud-storage service families are excluded to avoid overlap. File reads, compression, unique transfer bytes and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R734.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R734",
            Name = "macOS non-browser process external TLS payload burst",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1949: the source analytic requires abnormal encrypted connections by non-browser binaries after sensitive file access/compression. Carthago retains only exact non-browser process attribution plus a bounded TLS payload burst and explicitly excludes service families handled by neighboring rules.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet fields plus the exact process/network predicate defined by this independent candidate.",
                "Correlated rules accept only unique packet IDs in monotonic UTC order inside a bounded rule-owned window.",
                "Only the observed process association, network shape, request classification or packet burst is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, invalid endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command-line arguments, asset role, file access, successful transfer, authenticated endpoint state, C2, DoS impact, exploit success or compromise."
            },
            FalsePositives = new[] { "Developer tools, automation, package managers, backup, monitoring and administrator scripts commonly produce outbound TLS from non-browser processes." },
            MinimumConfidence = 78,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+mac_nonbrowser_pid+public_tls_peer+payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse time and window expiry for correlated candidates",
                "cooldown suppression and recovery",
                "fixed evidence privacy, Candidate Shadow and unique registry"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research666TimedWindow _timed = new();

        public R734_MacNonBrowserExternalTlsPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research726Evidence.Tls443(r)
                || !Research726Evidence.MacNonBrowser(r)
                || Research726Evidence.TextStorageHost(r.Sni)
                || Research726Evidence.CodeRepositoryHost(r.Sni)
                || Research716Evidence.CloudStorageHost(r.Sni)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1949", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mac_nonbrowser_external_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "external_tls_payload_burst_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "macOS non-browser external TLS payload burst observed; file access, compression, unique bytes, transfer semantics and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
