// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R146_TlsHandshakeFailureSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R146_TlsHandshakeFailureSpikeRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R146",
            Name: "TLS Handshake Failure Spike",
            Category: "TlsPki",
            Description: "Detects thresholded spikes of TLS handshake failures for the same source and destination.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R146.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R146",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "count" },
            positiveConditions: new[]
            {
                "The record must contain explicit TLS handshake failure evidence.",
                "A short-window burst threshold must be reached."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated handshake failures.",
                "Do not alert on successful TLS handshakes."
            },
            minimumConfidence: 72,
            threshold: 12,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Expired trust stores, certificate rollovers, and proxy outages can create short-lived failure spikes."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive tls handshake failure spike sample",
                "negative isolated handshake failure sample"
            });

        public R146_TlsHandshakeFailureSpikeRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch141145Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            // The current adapter has no typed failure-status field. Only a bounded
            // parser summary on an otherwise attributed TLS/TCP record is considered.
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || !NetworkBatch146152Evidence.HandshakeFailure(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 300, 60, 3600));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 12, 3, 500);
            var key = $"{record.Source}:{record.Destination}:{record.DestinationPort}";
            if (!_observations.Observe(key, record.Id, context.TimestampUtc, window, out var count)
                || count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "attributed_tls_tcp,handshake_failure_summary,independent_threshold", "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A single source produced repeated attributed TLS handshake failure summaries for one destination socket.",
                "Severity is Medium: failures can reflect scanning or ordinary certificate/configuration outages.",
                "A packet summary is not an independently verified TLS alert. Investigate capture provenance before escalation.",
                "Correlate error codes with full TLS parser events and certificate rollover schedules.",
                "Review whether other clients are encountering the same server issue."));
            return MatchTls(context, SeverityLevel.Medium, "TLS handshake failure burst observed",
                "TlsHandshakeFailures", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-context");
                    confidence.AddEvidence(0.18, "handshake-failure");
                    confidence.AddEvidence(0.18, "threshold-reached");
                }, count, window, NetworkBatch136140Evidence.Fingerprint(key));
        }
    }
}
