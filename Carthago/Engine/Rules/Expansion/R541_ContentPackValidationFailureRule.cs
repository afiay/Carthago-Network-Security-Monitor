// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R541_ContentPackValidationFailureRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R541_ContentPackValidationFailureRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R541", "Content Pack Validation Failure", "PlatformHealthAdvanced",
            "Detects schema, signature, duplicate-ID, or compatibility validation failures when loading rule/content packs.", SeverityLevel.Medium, "Rules.R541.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R541", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "content_pack", "validation_failure" },
            new[] { "content_pack.name", "matched_conditions" },
            new[] { "The event must reference content-pack/rule-pack validation.", "The event must include failure semantics such as schema error, duplicate rule ID, invalid signature, or incompatible version." },
            new[] { "Do not alert on a successfully skipped optional pack.", "Do not alert on user preview/import cancellation." },
            86, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "content-pack",
            new[] { "Development packs under active editing can fail validation before they are ready." },
            new[] { "Mode", "CooldownSeconds", "AllowUnsignedDevelopmentPacks" },
            new[] { "positive duplicate rule id validation failure", "negative optional pack skipped" });
        public R541_ContentPackValidationFailureRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "content pack", "content-pack", "rule pack", "rule-pack")) return NoMatch();
            if (!ContainsAny(text, "validation failed", "validation failure", "schema", "duplicate", "invalid", "signature", "incompatible", "rejected")) return NoMatch();
            if (ContainsAny(text, "skipped optional", "preview canceled", "cancelled")) return NoMatch();
            var pack = MetricKey(r);
            var e = new List<DetectionEvidenceItem> { new("content_pack.name", pack, "content-pack"), new("matched_conditions", "platform_health,content_pack,validation_failure", "rule") };
            e.AddRange(AnalystContext("A content/rule pack failed validation before activation.", "Severity is Medium because invalid packs can prevent expected detections from loading or can hide duplicate/unsafe rule definitions.", "Development packs can fail during authoring and should be separated from production pack loading.", "Inspect validation errors for duplicate RuleId, schema version, unsupported fields, or invalid signatures.", "Do not activate the pack until all validation errors are resolved."));
            return MatchPlatformHealth(context, SeverityLevel.Medium, "Content pack validation failed", "ContentPackValidationFailure", e,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.30, "content-pack-context"); c.AddEvidence(0.26, "validation-failure"); }, cooldownKey: pack);
        }
    }
}
