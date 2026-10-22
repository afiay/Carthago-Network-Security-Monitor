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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!HasHttpContext(record) || string.IsNullOrWhiteSpace(host) || !IsPasteOrDropHost(host) || !IsUploadMethod(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 900, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 100);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 200_000, 8_000, 50_000_000);
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{ProviderIdentity(host)}", context.TimestampUtc, window);
            var bytes = TransferBytes(record);
            var uploadHint = HasPasteUploadHint(record);
            var automation = IsLikelyAutomationProcess(record);
            if (!uploadHint && !automation && bytes < minimumPayloadBytes && count < threshold)
                return NoMatch();

            if (IsLikelyBrowserProcess(record.ProcessName) && !automation && !uploadHint && bytes < minimumPayloadBytes * 2L && count < threshold + 1)
                return NoMatch();

            var matchedConditions = new List<string> { "paste_or_drop_provider", "posting_method" };
            if (uploadHint) matchedConditions.Add("upload_or_document_hint");
            if (automation) matchedConditions.Add("automation_process");
            if (count >= threshold) matchedConditions.Add("posting_burst_threshold");
            if (bytes >= minimumPayloadBytes) matchedConditions.Add("non_trivial_payload");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source posted data to a paste or file-drop provider with either repeated burst behavior or non-trivial upload context.",
                "Severity is High because paste and drop services are common exfiltration channels when data is posted rather than merely viewed.",
                "Approved secure-transfer workflows or analyst troubleshooting can resemble this activity. Validate whether the provider and posting process are sanctioned.",
                "Review whether the requests created new pastes or uploaded documents rather than reading existing content.",
                "Correlate with endpoint file activity to determine what may have been posted."));

            return MatchCloudDev(
                context,
                SeverityLevel.High,
                "Paste or file-drop posting activity observed",
                "PasteServiceHighVolumePost",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "paste-or-drop-provider");
                    confidence.AddEvidence(0.16, "posting-method");
                    if (uploadHint) confidence.AddEvidence(0.14, "upload-or-document-hint");
                    if (count >= threshold) confidence.AddEvidence(0.12, "posting-burst-threshold");
                    if (bytes >= minimumPayloadBytes) confidence.AddEvidence(0.10, "non-trivial-payload");
                    if (automation) confidence.AddCorrelation(0.10, "automation-process");
                },
                count,
                window,
                $"{record.Source}:{ProviderIdentity(host)}");
        }
    }
}
