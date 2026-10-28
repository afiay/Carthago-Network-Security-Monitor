// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R269_SecurityToolUpdateBlockIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R269_SecurityToolUpdateBlockIndicatorRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R269",
            Name: "Security Tool Update Block Indicator",
            Category: "EvasionInfra",
            Description: "Detects security tool update block indicator only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R269.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R269",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 75,
            threshold: 3,
            window: TimeSpan.FromMinutes(30),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Outages, maintenance windows, captive portals, and proxy misconfiguration can produce legitimate failures." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R269 evidence-gated sample", "negative R269 descriptor-only sample", "negative R269 missing telemetry sample" });

        public R269_SecurityToolUpdateBlockIndicatorRule() : base(Rule, Profile) { }

        private readonly NetworkBatch266270Evidence.DistinctWindow _failures = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch266270Evidence.SecurityUpdateDnsFailure(r, out var code)) return NoMatch();
            var key = r.Destination + "|" + r.Source + "|" + r.DnsQname!.ToLowerInvariant() + "|" + code;
            var count = _failures.Observe(r, context.TimestampUtc, key, TimeSpan.FromMinutes(30));
            if (count < 3) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_dns_response,known_update_domain,distinct_failure_responses", "rule"),
                new("dns.failureCategory", code, "dns"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidence.AddRange(AnalystContext("Three distinct DNS SERVFAIL/REFUSED responses were observed for an exact known security-update hostname.",
                "DNS resolution failure is not proof of deliberate blocking, tampering or failed security-tool updates.",
                "Resolver outages, maintenance and policy can produce these responses.",
                "Verify resolver health and the endpoint's actual update status."));
            return MatchEvasionInfra(context, SeverityLevel.Medium,
                "Repeated security-update domain DNS resolution failures (blocking unverified)", "SecurityUpdateBlock",
                evidence, c => { c.AddEvidence(0.34, "typed-dns-response"); c.AddEvidence(0.22, "exact-update-domain"); c.AddEvidence(0.18, "distinct-responses"); },
                count: count, window: Profile.Window, cooldownKey: key + ":update-dns-failure");
        }
    }
}
