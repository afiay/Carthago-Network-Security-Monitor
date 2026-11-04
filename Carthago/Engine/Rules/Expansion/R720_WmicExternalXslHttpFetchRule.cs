// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2325.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R720_WmicExternalXslHttpFetchRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R720",
            Name: "WMIC process cleartext external XSL fetch",
            Category: "EvasionInfra",
            Description: "A locally attributed wmic.exe process issues a cleartext outbound HTTP GET for an .xsl or .xslt resource. The /format command-line switch, XSL script contents, in-memory execution, application-control bypass, and code execution are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R720.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R720",
            Name = "WMIC process cleartext external XSL fetch",
            Category = "EvasionInfra",
            Description = "Workbook R2325: the Sigma source detects SquiblyTwo from WMIC command-line /format usage. Carthago has no command line, so this candidate implements only the narrower observable network consequence: an external XSL fetch by wmic.exe.",
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
            FalsePositives = new[] { "Legitimate WMI formatting, inventory tooling, administrative scripts, or lab testing can fetch remote XSL resources." },
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+wmic_pid+external_xsl_peer",
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

        public R720_WmicExternalXslHttpFetchRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET"
                || !Research676Evidence.PrivateToPublic(r)
                || !Research716Evidence.Process(r, "wmic.exe")
                || !(uri.Split('?')[0].EndsWith(".xsl", StringComparison.OrdinalIgnoreCase)
                    || uri.Split('?')[0].EndsWith(".xslt", StringComparison.OrdinalIgnoreCase)))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2325", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "wmic_external_xsl_http_get", "rule"),
                new DetectionEvidenceItem("outcome", "wmic_remote_xsl_fetch_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "WMIC-associated external XSL HTTP fetch observed; SquiblyTwo command line, XSL contents, and code execution are unknown.",
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
