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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !HasHighEntropyPath(record, out var entropy, out var sample)) return NoMatch();
            var supporting = IsUploadMethod(record) || IsLikelyAutomationProcess(record) || TransferBytes(record) >= 256 * 1024;
            if (!supporting || (IsLikelyBrowserProcess(record.ProcessName) && !IsUploadMethod(record))) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "high_entropy_uri_path,external_destination,supporting_upload_or_automation")) { new("uri.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "http"), new("uri.entropySample", sample, "http") };
            evidence.AddRange(AnalystContext("An outbound URI path contained a long high-entropy token together with upload, automation, or volume evidence.", "Severity is Medium/DetectOnly because high-entropy URI paths can be benign in CDNs and object stores, but become suspicious with upload support.", "CDNs, signed URLs, and cache-busting can match. Validate before escalation.", "Check whether the destination is object storage/CDN.", "Correlate with file-upload or chunking rules from the same source."));
            return MatchExfiltration(context, SeverityLevel.Medium, "High-entropy outbound URI path with exfil support", "HighEntropyUriPath", evidence, c => { c.AddEvidence(0.24, "high-entropy-path"); c.AddEvidence(0.18, "supporting-upload-or-automation"); c.AddEvidence(0.10, "external-destination"); }, cooldownKey: CooldownIdentity(record, "entropy-uri"));
        }
    }
}
