// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R220_PasteServiceHighVolumePostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R220_PasteServiceHighVolumePostRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R220",
            Name: "Paste Service High Volume POST",
            Category: "CloudDev",
            Description: "Detects repeated or non-trivial POST, PUT, or PATCH requests to paste or file-drop services, while suppressing simple page views and low-context browser traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R220.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R220",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The destination must be a paste or file-drop provider.",
                "The request must use a posting or upload method and include volume or upload-oriented context.",
                "Repeated posting bursts should remain visible even when each individual POST is modest."
            },
            negativeConditions: new[]
            {
                "Do not alert on GET-only reads or landing-page traffic.",
                "Do not alert on low-context browser requests with trivial payload volume."
            },
            minimumConfidence: 82,
            threshold: 5,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "destination",
            falsePositives: new[] { "Approved troubleshooting, secure-transfer, or analyst workflows can legitimately post to paste or file-drop services." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "MinimumPayloadBytes", "CooldownSeconds" },
            requiredTests: new[] { "positive paste post burst sample", "negative paste landing page sample" });

        public R220_PasteServiceHighVolumePostRule() : base(Rule, Profile) { }

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch216220Evidence.Paste(record, out var provider))
                return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 900, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 100);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 200_000, 8_000, 50_000_000);
            var large = NetworkBatch216220Evidence.DeclaredBytes(record, out var declared) && declared >= minimumPayloadBytes;
            var key = NetworkBatch216220Evidence.SafeKey(record);
            if (!_observations.Observe(record, key, record.Id.ToString("N"), context.TimestampUtc,
                window, 0, out var count, out _))
                return NoMatch();
            if (!large && count < threshold)
                return NoMatch();
            if (IsLikelyBrowserProcess(record.ProcessName) && !large && count < threshold + 1)
                return NoMatch();
            var matchedConditions = new List<string> { "typed_http", "paste_provider", "post_method" };
            if (large) matchedConditions.Add("large_declared_content_length");
            if (count >= threshold) matchedConditions.Add("distinct_post_request_threshold");
            var evidence = new List<DetectionEvidenceItem>
            {
                new("provider", provider, "cloud"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source made repeated distinct paste-service upload requests or declared a large request body.",
                "Observed requests and declared body length do not establish successful data delivery.",
                "Approved troubleshooting and secure-transfer workflows can look identical.",
                "Correlate with application responses and endpoint file activity.",
                "Confirm whether the source and provider are sanctioned."));
            return MatchHttpApi(context, SeverityLevel.High,
                "Paste or file-drop posting requests observed", "PasteServiceHighVolumePost",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.24, "paste-or-drop-provider");
                    confidence.AddEvidence(0.16, "posting-method");
                    if (NetworkBatch216220Evidence.Multipart(record)) confidence.AddEvidence(0.14, "multipart-request");
                    if (count >= threshold) confidence.AddEvidence(0.12, "posting-burst-threshold");
                    if (large) confidence.AddEvidence(0.10, "large-declared-content-length");
                    if (IsLikelyAutomationProcess(record)) confidence.AddCorrelation(0.10, "automation-process");
                }, count, window, key);
        }
    }
}

