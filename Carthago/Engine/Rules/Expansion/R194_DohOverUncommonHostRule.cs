// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R194_DohOverUncommonHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R194_DohOverUncommonHostRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly string[] ApprovedDohHosts =
        {
            "cloudflare-dns.com", "dns.google", "dns.quad9.net", "dns.adguard-dns.com",
            "family.adguard-dns.com", "dns.nextdns.io", "mozilla.cloudflare-dns.com", "one.one.one.one"
        };

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R194",
            Name: "DoH Over Uncommon Host",
            Category: "DnsAdvanced",
            Description: "Detects DNS-over-HTTPS semantics on external hosts that are not approved public resolvers, instead of matching any dns-query path.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R194.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R194",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must have concrete HTTP DoH semantics such as /dns-query or application/dns-message headers.",
                "The destination host must be external and not part of an approved DoH provider list."
            },
            negativeConditions: new[]
            {
                "Do not alert on approved public DoH providers.",
                "Do not alert on ordinary web paths that merely contain the string dns-query without DoH semantics."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Enterprises may intentionally use custom private DoH gateways; tune approved hosts rather than disabling the rule globally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive uncommon doh host sample", "negative approved doh host sample" });

        public R194_DohOverUncommonHostRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch191195Evidence.Doh(record, out var host, out var method)
                || IsApprovedDohHost(host) || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "typed_doh_request_shape,external_host,unapproved_provider", "rule"),
                new("doh.method", method, "http")
            };
            evidence.AddRange(AnalystContext(
                "A wire-attributed HTTP request had DoH-shaped headers and URI semantics against an external host not in the static resolver list; request-body DNS payload is not inspected.",
                "Severity is Medium because custom or covert DoH endpoints can bypass enterprise resolver policy and DNS monitoring.",
                "Some enterprises intentionally deploy private DoH gateways. Validate whether the destination host is part of an approved internal or vendor-managed resolver design.",
                "Review the calling process, user agent, and follow-on encrypted DNS behavior from the same source.",
                "Confirm whether the destination host is an approved DoH endpoint."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Unapproved DNS-over-HTTPS host observed",
                "DohUncommonHost",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "doh-semantics");
                    confidence.AddEvidence(0.18, "external-host");
                    confidence.AddEvidence(0.18, "unapproved-provider");
                    if (!IsBrowserLikeUserAgent(record) && !string.IsNullOrWhiteSpace(record.ProcessName)) confidence.AddCorrelation(0.08, "non-browser-process");
                },
                cooldownKey: $"{record.Source}:{NetworkBatch166170Evidence.Key(host)}");
        }

        private static bool IsApprovedDohHost(string host)
        {
            foreach (var approved in ApprovedDohHosts)
            {
                if (host.Equals(approved, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + approved, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
