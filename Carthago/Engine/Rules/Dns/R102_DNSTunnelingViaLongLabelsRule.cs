// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R102_DNSTunnelingViaLongLabelsRule.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R102_DNSTunnelingViaLongLabelsRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R102",
            Name: "DNS Tunneling via Long Labels",
            Category: "Dns",
            Description: "Flags suspiciously long or repeated high-entropy DNS labels in structured DNS telemetry, while excluding common validation and mail-authentication records.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R102.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R102",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_qtype" },
            evidenceFields: new[]
            {
                "dns.qname", "dns.maxLabelLength", "dns.queryLength", "dns.entropy", "dns.longestLabelEntropy", "dns.longLabelCount", "dns.uniqueCharactersInLongestLabel",
                "count", "window_seconds", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "The query must contain a very long and high-entropy label with TXT-like or multi-label context, or repeat a suspicious query shape.",
                "Validation and mail-authentication records should be excluded."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "Do not infer DNS tunneling from port 53 alone.",
                "Do not alert solely on domain keywords without long-label or high-entropy evidence."
            },
            minimumConfidence: 80,
            threshold: 2,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+root_domain",
            falsePositives: new[]
            {
                "SPF, DKIM, ACME, and some SaaS verification records can legitimately contain long labels.",
                "Certain telemetry or anti-spam workflows may generate long TXT-oriented DNS queries."
            },
            tuningKnobs: new[] { "Mode", "LabelLengthThreshold", "WindowSeconds", "CooldownSeconds", "QueryLengthThreshold", "EntropyThreshold", "RepeatThreshold" },
            requiredTests: new[]
            {
                "positive long-label DNS sample",
                "negative missing DNS telemetry",
                "negative benign validation domain sample",
                "evidence and confidence assertion"
            });

        public R102_DNSTunnelingViaLongLabelsRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("SPF, DKIM, ACME, and verification records", "Tune with validation-domain allowlists or stricter entropy requirements before reducing the rule broadly.")
        };

        protected override string? InvestigationHintOverride
            => "Inspect the left-hand labels, qtype, and repeated query cadence to determine whether the source is embedding data into DNS labels.";

        protected override string? TuningHintOverride
            => "Tune by entropy, query-length, and repeat thresholds. Keep the rule anchored to DNS qname structure and repeated behavior, not destination text.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query))
                return NoMatch();

            if (LooksLikeBenignValidationQuery(query))
                return NoMatch();

            var root = RootDomain(query);
            var labels = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var labelThreshold = IntSetting(Descriptor.RuleId, "LabelLengthThreshold", 50, 20, 63);
            var maxLabelLength = labels.Length == 0 ? 0 : labels.Max(static label => label.Length);
            var longestLabel = labels.OrderByDescending(static label => label.Length).FirstOrDefault() ?? string.Empty;
            var longestLabelEntropy = ShannonEntropy(longestLabel);
            var uniqueCharacterCount = longestLabel.Distinct().Count();
            var longLabelCount = labels.Count(label => label.Length >= labelThreshold);
            var queryLength = query.Length;
            var entropy = ShannonEntropy(query.Replace(".", string.Empty, StringComparison.Ordinal));
            var queryLengthThreshold = IntSetting(Descriptor.RuleId, "QueryLengthThreshold", 180, 60, 255);
            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 3.50, 2.0, 8.0);
            var repeatThreshold = IntSetting(Descriptor.RuleId, "RepeatThreshold", 2, 1, 20);
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 300, 30, 3600));
            var repeatCount = CountWindowEvents($"{Descriptor.RuleId}:{context.Record.Source}:{root}", context.TimestampUtc, window);
            var txtLikeQuery = IsTxtLikeDnsQueryType(context.Record.DnsQtype);
            var exceptionallyLongLabel = maxLabelLength >= Math.Min(63, labelThreshold + 8);
            var monolithicTxtLabel = txtLikeQuery && maxLabelLength >= labelThreshold + 4 && uniqueCharacterCount <= 3;
            var strongSingleQuery = monolithicTxtLabel || (maxLabelLength >= labelThreshold
                && longestLabelEntropy >= entropyThreshold
                && (txtLikeQuery || exceptionallyLongLabel || longLabelCount >= 2));
            var repeatedLongQuery = repeatCount >= repeatThreshold
                && (monolithicTxtLabel || longestLabelEntropy >= entropyThreshold)
                && (maxLabelLength >= Math.Max(20, labelThreshold - 4) || queryLength >= queryLengthThreshold);

            if (IsKnownTelemetryRoot(root) && !repeatedLongQuery && !txtLikeQuery)
                return NoMatch();

            if (!strongSingleQuery && !repeatedLongQuery)
                return NoMatch();

            var matchedConditions = new List<string> { "dns_qname_present", "dns_tunneling_label_shape" };
            if (longestLabelEntropy >= entropyThreshold) matchedConditions.Add("high_entropy_dns_query");
            if (strongSingleQuery) matchedConditions.Add("long_single_label");
            if (repeatedLongQuery) matchedConditions.Add("repeated_long_query_shape");
            if (txtLikeQuery) matchedConditions.Add("tunnel_favored_qtype");
            if (monolithicTxtLabel) matchedConditions.Add("monolithic_txt_label");

            var whyMatched = monolithicTxtLabel
                ? $"The DNS query '{query}' contains an unusually long TXT-style label with only {uniqueCharacterCount} distinct characters, which is consistent with padded or chunked tunnel content."
                : strongSingleQuery
                ? $"The DNS query '{query}' contains a label of length {maxLabelLength} with label entropy {longestLabelEntropy:F2} and supporting context that favors tunneling."
                : $"The DNS query '{query}' repeatedly appeared {repeatCount} times with a suspicious long-label shape within {window.TotalMinutes:F0} minutes.";
            var severityReason = "Severity is High because the rule matched structured DNS label length, entropy, and behavioral context that are consistent with tunneling, not a generic suspicious string.";
            var falsePositives = "SPF, DKIM, ACME, and some validation records can contain long labels. Validate qtype, repeated behavior, and business context before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.maxLabelLength", maxLabelLength.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.queryLength", queryLength.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.longestLabelEntropy", longestLabelEntropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.longLabelCount", longLabelCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.uniqueCharactersInLongestLabel", uniqueCharacterCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("count", repeatCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Inspect the qtype, label contents, and follow-on queries from the same source for staged data exfiltration or command polling.",
                "Review whether the domain is a mail-authentication, certificate-validation, or vendor verification record.",
                "Allowlist only well-understood validation roots after confirming the traffic is expected."));

            return MatchDns(
                context,
                SeverityLevel.High,
                $"Long-label or high-entropy DNS tunneling pattern observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    if (monolithicTxtLabel) confidence.AddEvidence(0.28, "monolithic-txt-label");
                    else confidence.AddEvidence(0.30, "high-entropy-longest-label");
                    if (strongSingleQuery) confidence.AddEvidence(0.22, "long-single-label");
                    if (maxLabelLength >= labelThreshold + 4) confidence.AddEvidence(0.10, "very-long-label");
                    if (repeatedLongQuery) confidence.AddEvidence(0.18, "repeated-long-query-shape");
                    if (txtLikeQuery)
                    {
                        confidence.AddCorrelation(0.10, "tunnel-favored-qtype");
                    }
                    if (!IsKnownTelemetryRoot(root)) confidence.AddCorrelation(0.08, "non-approved-root");
                },
                count: repeatCount,
                window: window,
                cooldownKey: $"{context.Record.Source}:{root}");
        }
    }
}
