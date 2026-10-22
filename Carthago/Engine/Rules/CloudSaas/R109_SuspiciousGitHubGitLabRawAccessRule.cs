// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R109_SuspiciousGitHubGitLabRawAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R109_SuspiciousGitHubGitLabRawAccessRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R109",
            Name: "Suspicious GitHub / GitLab Raw Access",
            Category: "CloudSaas",
            Description: "Detects suspicious access to raw Git or gist content when the request shape, payload path, automation context, or repetition makes it more than routine repository browsing.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R109.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R109",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[]
            {
                "cloud.host", "http.uri", "process.name", "count", "window_seconds", "host.classifier", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The host and URI must resolve to raw-content access, not ordinary repository browsing.",
                "The request should also carry payload-path, automation, transfer-size, or repetition context.",
                "Generic Git or repo web views should not match."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary github.com or gitlab.com blob views.",
                "Do not alert on single tiny browser fetches without payload indicators.",
                "Do not alert when raw-content classification is absent."
            },
            minimumConfidence: 72,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Developers and automation pipelines may legitimately fetch raw content from code hosting platforms.",
                "Browser-based inspection of configuration snippets can look similar when paths are short and content is small."
            },
            tuningKnobs: new[] { "Mode", "MinimumPayloadBytes", "RepeatThreshold", "WindowSeconds" },
            requiredTests: new[]
            {
                "positive scripted raw-content sample",
                "negative repository-browse sample",
                "negative small browser fetch sample"
            });

        public R109_SuspiciousGitHubGitLabRawAccessRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Determine whether the request fetched a script, binary, archive, or staged payload from raw-content infrastructure and whether the process aligns with normal developer or CI activity.";

        protected override string? TuningHintOverride
            => "Tune repetition and payload-size thresholds, but keep raw-host or raw-URI classification mandatory so ordinary repository browsing stays suppressed.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host) || !IsInternalAddress(record.Source) || !IsExternalAddress(record.Destination))
                return NoMatch();

            if (!TryClassifyGitRawAccess(host, record.HttpUri, out var classifier))
                return NoMatch();

            var bytes = TransferBytes(record);
            var payloadHint = HasGitPayloadHint(record);
            var automation = IsLikelyAutomationProcess(record);
            var repeatWindow = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var repeatThreshold = IntSetting(Descriptor.RuleId, "RepeatThreshold", 3, 2, 64);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 250_000, 16_000, 50_000_000);
            var repeatCount = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{ProviderIdentity(host)}", context.TimestampUtc, repeatWindow);

            if (!payloadHint && !automation && bytes < minimumPayloadBytes && repeatCount < repeatThreshold)
                return NoMatch();

            if (IsLikelyBrowserProcess(record.ProcessName) && !payloadHint && bytes < minimumPayloadBytes * 2L && repeatCount < repeatThreshold + 1)
                return NoMatch();

            var severity = payloadHint || automation ? SeverityLevel.High : SeverityLevel.Medium;
            var matchedConditions = new List<string> { "raw_git_content_access", "supporting_context" };
            if (payloadHint) matchedConditions.Add("payload_path_indicator");
            if (automation) matchedConditions.Add("automation_process");
            if (repeatCount >= repeatThreshold) matchedConditions.Add("repeated_raw_fetches");

            var whyMatched = $"{record.Source} accessed {classifier} on {host} with {repeatCount} matching request(s) in {repeatWindow.TotalMinutes:F0} minutes.";
            var severityReason = severity == SeverityLevel.High
                ? "Severity is High because the raw-content access also included payload-path or automation indicators."
                : "Severity is Medium because the rule matched raw-content infrastructure with enough supporting repetition or transfer volume to exceed routine browsing.";
            var falsePositives = "Developer workflows, CI systems, and configuration management can legitimately fetch raw content. Validate the requesting process and repository path before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("host.classifier", classifier, "cloud"),
                new("count", repeatCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)repeatWindow.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Inspect the raw-content path for scripts, binaries, archives, or staged payloads.",
                "Validate whether the requesting process belongs to a developer, CI, or sanctioned automation workflow.",
                "Correlate with subsequent execution, file-write, or persistence activity on the source."));

            return MatchCloud(
                context,
                severity,
                $"Suspicious raw Git content access observed on {host}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "raw-content-classification");
                    if (payloadHint) confidence.AddEvidence(0.18, "payload-path-indicator");
                    if (automation) confidence.AddCorrelation(0.16, "automation-process");
                    if (repeatCount >= repeatThreshold) confidence.AddEvidence(0.10, "repeated-raw-fetches");
                    if (bytes >= minimumPayloadBytes) confidence.AddEvidence(0.08, "non-trivial-transfer");
                },
                count: repeatCount,
                window: repeatWindow,
                cooldownKey: $"{record.Source}:{ProviderIdentity(host)}");
        }
    }
}
