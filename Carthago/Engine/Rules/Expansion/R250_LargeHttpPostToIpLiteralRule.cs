// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R250_LargeHttpPostToIpLiteralRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R250_LargeHttpPostToIpLiteralRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R250", "Large HTTP POST To IP Literal", "ExfiltrationAdvanced", "Detects large HTTP upload requests to raw IP-literal external targets, suppressing normal host-based SaaS traffic.", SeverityLevel.High, "Rules.R250.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R250", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow }, new[] { "source", "ip_literal_destination", "http_post", "bytes" }, new[] { "network.destinationPort", "flow.bytes", "http.path", "matched_conditions" }, new[] { "Request must be HTTP POST/PUT/PATCH.", "Target must be an external IP literal or hostless HTTP target.", "Transfer volume must be large." }, new[] { "Do not alert on named SaaS/cloud hosts.", "Do not alert on small telemetry posts." }, 83, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "source+destination+http-ip", new[] { "Appliances may upload diagnostics to vendor IPs without DNS, but this should be allowlisted." }, new[] { "Mode", "MinimumBytes", "ApprovedIpLiteralDestinations" }, new[] { "positive large POST to IP sample", "negative small API POST sample" });
        public R250_LargeHttpPostToIpLiteralRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !HasHttpContext(record) || !IsUploadMethod(record) || !IsIpLiteralTarget(record) || TransferBytes(record) < 20 * 1024 * 1024) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "http_upload,ip_literal_target,large_transfer"));
            evidence.AddRange(AnalystContext("A large HTTP upload targeted an external raw IP literal rather than a named service host.", "Severity is High because hostless IP-literal uploads reduce attribution and are common in ad hoc exfiltration infrastructure.", "Some vendor appliances upload diagnostics to fixed IPs; allowlist known destinations.", "Resolve ownership/ASN of the destination IP.", "Check whether the source normally uploads large HTTP payloads."));
            return MatchExfiltration(context, SeverityLevel.High, "Large HTTP upload to IP-literal target", "LargeHttpPostToIpLiteral", evidence, c => { c.AddEvidence(0.26, "large-http-upload"); c.AddEvidence(0.24, "ip-literal-target"); c.AddEvidence(0.12, "external-destination"); }, cooldownKey: CooldownIdentity(record, "http-ip-post"));
        }
    }
}
