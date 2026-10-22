// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R542_ReplayBenchmarkRegressionRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R542_ReplayBenchmarkRegressionRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R542", "Replay Benchmark Regression", "PlatformHealthAdvanced",
            "Detects explicit replay-benchmark precision/recall/performance regressions emitted by the test/replay subsystem.", SeverityLevel.High, "Rules.R542.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R542", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline }, new[] { "platform_health_event", "replay_benchmark", "regression_signal" },
            new[] { "benchmark.name", "matched_conditions" },
            new[] { "The event must come from replay benchmark/test telemetry.", "The event must indicate regression in precision, recall, expected matches, latency, or false-positive budget." },
            new[] { "Do not alert on ordinary replay execution success.", "Do not alert on manually accepted baseline updates." },
            86, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "benchmark",
            new[] { "Intentional baseline updates can appear as regressions until approved." },
            new[] { "Mode", "CooldownSeconds", "ApprovedBaselineVersion" },
            new[] { "positive replay precision regression", "negative replay pass" });
        public R542_ReplayBenchmarkRegressionRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "replay benchmark", "replay", "benchmark", "golden corpus", "regression test")) return NoMatch();
            if (!ContainsAny(text, "regression", "failed", "precision drop", "recall drop", "false positive", "expected match", "latency regression", "budget exceeded")) return NoMatch();
            if (ContainsAny(text, "baseline approved", "accepted baseline", "passed")) return NoMatch();
            var bench = MetricKey(r);
            var e = new List<DetectionEvidenceItem> { new("benchmark.name", bench, "benchmark"), new("matched_conditions", "platform_health,replay_benchmark,regression", "rule") };
            e.AddRange(AnalystContext("Replay benchmark telemetry reported a detection-quality or performance regression.", "Severity is High because rule precision can degrade before analysts see production symptoms.", "Expected baseline changes should be explicitly approved and versioned.", "Compare changed rules, parser updates, and benchmark corpus deltas.", "Block content-pack promotion until benchmark regression is triaged."));
            return MatchPlatformHealth(context, SeverityLevel.High, "Replay benchmark regression reported", "ReplayBenchmarkRegression", e,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.30, "replay-benchmark-context"); c.AddEvidence(0.26, "regression-signal"); }, cooldownKey: bench);
        }
    }
}
