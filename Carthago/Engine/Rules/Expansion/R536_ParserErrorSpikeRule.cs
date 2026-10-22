// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R536_ParserErrorSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R536_ParserErrorSpikeRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R536", "Parser Error Spike", "PlatformHealthAdvanced",
            "Detects parser-error spikes only from explicit parser/platform-health telemetry or repeated parser failure events in a short window.",
            SeverityLevel.High, "Rules.R536.Enabled", true);

        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R536", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload }, new[] { "platform_health_event", "parser", "error_signal" },
            new[] { "parser.name", "platform.windowCount", "matched_conditions" },
            new[] { "The event must reference parser errors, malformed records, decode failures, or parse exceptions.", "A spike/surge signal or repeated events in the time window must be present." },
            new[] { "Do not alert on one malformed external packet.", "Do not alert on application errors unrelated to parsing/normalization." },
            84, 4, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15), "parser",
            new[] { "Malformed lab traffic, replay corpora, and parser development tests can create expected spikes." },
            new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            new[] { "positive parser error spike", "negative single malformed packet" });

        public R536_ParserErrorSpikeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record; var text = Text(record);
            if (!IsPlatformHealthRecord(record) || !ContainsAny(text, "parser", "parse", "decoder", "normalizer", "normalization")) return NoMatch();
            if (!ContainsAny(text, "error", "exception", "failed", "failure", "malformed", "invalid", "decode")) return NoMatch();
            var explicitSpike = ContainsAny(text, "spike", "surge", "burst", "above baseline", "excessive");
            var parser = MetricKey(record);
            var key = $"{Descriptor.RuleId}:{parser}";
            var count = CountWindowEvents(key, context.TimestampUtc, TimeSpan.FromMinutes(5));
            if (!explicitSpike && count < 4) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> { new("parser.name", parser, "parser"), new("platform.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "platform-health"), new("matched_conditions", explicitSpike ? "platform_health,parser_error,explicit_spike" : "platform_health,parser_error,window_threshold", "rule") };
            evidence.AddRange(AnalystContext("Parser/platform health telemetry shows a repeated or explicit spike in parse failures.", "Severity is High because parser failures can blind multiple detection rules or corrupt evidence quality.", "Malformed replay data or parser tests can be legitimate.", "Identify the parser and sample dropped/malformed records.", "Check whether a sensor, protocol decoder, or payload normalizer was recently changed."));
            return MatchPlatformHealth(context, SeverityLevel.High, "Parser error spike observed", "ParserErrorSpike", evidence,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.24, "parser-context"); c.AddEvidence(0.24, "error-semantics"); if (explicitSpike) c.AddEvidence(0.14, "explicit-spike"); else c.AddCorrelation(0.10, "window-threshold"); }, count, TimeSpan.FromMinutes(5), key);
        }
    }
}
