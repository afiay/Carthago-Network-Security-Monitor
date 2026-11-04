// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2382.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R722_BitsadminSuspiciousExtensionHttpGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R722",
            Name: "Bitsadmin suspicious-extension cleartext HTTP GET",
            Category: "HttpApi",
            Description: "A bitsadmin.exe process is associated with an outbound cleartext HTTP GET whose URI ends in a script, executable, archive, webshell, or similar high-risk extension. Command-line BITS flags, local target path, response, file write, and completed download are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R722.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R722",
            Name = "Bitsadmin suspicious-extension cleartext HTTP GET",
            Category = "HttpApi",
            Description = "Workbook R2382: the Sigma source uses process command line and suspicious target extension. Carthago narrows this to the existing process attribution plus parsed HTTP GET path. R686 owns direct-IP Bitsadmin GET and R696 owns file-sharing service contact; neither requires this extension predicate.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "http.method", "http.uri", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet, parser, and best-effort process fields for this exact independent predicate.",
                "Multi-observation rules use bounded unique packet IDs with UTC ordering and a fixed rule-owned window.",
                "Only the observable network/request/process association is claimed; endpoint or server outcome is not inferred."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, and free-form Info-only indicators.",
                "Reject duplicate packet IDs, stale/out-of-order observations, and cooldown repeats.",
                "Do not infer authentication, command-line arguments, file reads/writes, transfer completion, exploit success, or compromise."
            },
            FalsePositives = new[] { "Software deployment, administrative packaging, patch distribution, and incident-response collection can legitimately retrieve archives, scripts, DLLs, or web assets through BITS." },
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+bitsadmin_pid+peer+suspicious_extension",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R722_BitsadminSuspiciousExtensionHttpGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET"
                || !Research676Evidence.PrivateToPublic(r)
                || !Research716Evidence.Process(r, "bitsadmin.exe")
                || !Research716Evidence.SuspiciousDownloadExtension(uri))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2382", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "bitsadmin_http_get_suspicious_extension", "rule"),
                new DetectionEvidenceItem("outcome", "bitsadmin_suspicious_extension_request_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Bitsadmin-associated suspicious-extension HTTP GET observed; command-line flags, local file write, response, and download completion are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
