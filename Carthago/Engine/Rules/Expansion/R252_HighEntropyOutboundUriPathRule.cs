// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R252_HighEntropyOutboundUriPathRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R252_HighEntropyOutboundUriPathRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R252", "High Entropy Outbound URI Path", "ExfiltrationAdvanced", "Detects outbound HTTP requests with long high-entropy URI path tokens only when paired with upload/automation/volume evidence.", SeverityLevel.Medium, "Rules.R252.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R252", RulePrecisionMaturity.Experimental, RuleRuntimeMode.Shadow, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow }, new[] { "source", "external_destination", "http_uri", "entropy" }, new[] { "http.path", "uri.entropy", "matched_conditions" }, new[] { "URI path must contain a long high-entropy token.", "Traffic must be outbound to external target.", "Upload method, automation process, or transfer volume must support exfil intent." }, new[] { "Do not alert on CDN cache-busting alone.", "Do not alert on browser-only static asset requests." }, 74, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "source+root_domain+entropy_path", new[] { "CDNs and object storage can use high-entropy paths; keep this rule in detect-only until tuned." }, new[] { "Mode", "EntropyThreshold", "MinimumTokenLength", "ApprovedCDNRules" }, new[] { "positive high entropy upload URI sample", "negative CDN asset token sample" });
        public R252_HighEntropyOutboundUriPathRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch251255Evidence.HighEntropy(record, out var entropy)
                || IsLikelyApprovedSyncOrBackup(record)
                || IsLikelyBrowserProcess(record.ProcessName)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "parsed_http_upload,high_entropy_path,non_browser", "rule"),
                new("uri.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "http")
            };
            evidence.AddRange(AnalystContext("An outbound cleartext HTTP upload request used a high-entropy path token.",
                "Opaque paths may be legitimate identifiers, not proof of exfiltration.",
                "Signed URLs and object-storage tokens can match; preserve Shadow mode.",
                "Corroborate request purpose without copying token values."));
            return MatchExfiltration(context, SeverityLevel.Medium,
                "High-entropy outbound upload URI path", "HighEntropyUriPath", evidence,
                c => { c.AddEvidence(0.24, "high-entropy-path"); c.AddEvidence(0.18, "upload-request"); c.AddEvidence(0.10, "external-destination"); },
                cooldownKey: record.Source + ":" + record.Destination + ":entropy");

        }
    }
}
