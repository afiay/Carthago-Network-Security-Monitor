// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2783.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R725_CurlWgetBrowserUserAgentHttpGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R725",
            Name: "Curl or Wget cleartext GET with browser-like User-Agent",
            Category: "HttpApi",
            Description: "Curl or Wget is associated with an outbound cleartext HTTP GET carrying a browser-like Mozilla User-Agent. Interactive-shell or scheduled-job context and spoofing intent are not visible, so this is only an observable process/header mismatch.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R725.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R725",
            Name = "Curl or Wget cleartext GET with browser-like User-Agent",
            Category = "HttpApi",
            Description = "Workbook R2783: the source analytic correlates command-line tools, user/session context, and spoofed User-Agent behavior. Carthago retains the exact process plus parsed User-Agent but not shell ancestry, so this rule detects only the mismatch and keeps it separate from R642 POST and R682 Rundll32/MSHTA heartbeat predicates.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "http.method", "http.user_agent", "process.name", "process.id" },
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
            FalsePositives = new[] { "Compatibility testing, scraping, web automation, application health checks, and legitimate scripts often set browser-like User-Agent strings deliberately." },
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+curl_or_wget_pid+browser_user_agent_peer",
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

        public R725_CurlWgetBrowserUserAgentHttpGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                || method != "GET"
                || !Research676Evidence.PrivateToPublic(r)
                || !Research716Evidence.Process(r, "curl.exe", "curl", "wget.exe", "wget")
                || !Research716Evidence.BrowserLikeUserAgent(r.HttpUserAgent))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2783", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "curl_wget_browser_like_user_agent_get", "rule"),
                new DetectionEvidenceItem("outcome", "process_user_agent_mismatch_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Curl/Wget browser-like User-Agent HTTP GET observed; shell ancestry, spoofing intent, response, and security outcome are unknown.",
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
