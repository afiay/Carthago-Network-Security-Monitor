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
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch246250Evidence.IpLiteralPost(record, out var declared)
                || IsLikelyApprovedSyncOrBackup(record)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "cleartext_http,ip_literal_host,declared_large_body", "rule"),
                new("http.declaredBodyBytes", declared.ToString(System.Globalization.CultureInfo.InvariantCulture), "http"),
                new("http.transfer_status", "request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext("A cleartext HTTP upload request to an external IP literal declared a large body.",
                "Content-Length is client-declared, not proof of transmitted bytes.",
                "Approved diagnostics to fixed IPs can resemble this request.",
                "Corroborate actual transfer bytes and destination authorization."));
            return MatchExfiltration(context, SeverityLevel.High,
                "Large declared HTTP upload to IP literal", "LargeHttpPostToIpLiteral", evidence,
                c => { c.AddEvidence(0.26, "declared-large-body"); c.AddEvidence(0.24, "ip-literal-host"); c.AddEvidence(0.12, "external-http-request"); },
                cooldownKey: record.Source + ":" + record.Destination + ":http-ip");

        }
    }
}
