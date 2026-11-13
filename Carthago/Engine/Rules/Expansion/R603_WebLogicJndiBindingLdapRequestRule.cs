// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero tests/builds executed.
// Original workbook research: R3037. Request-only classification, not exploitation evidence.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R603_WebLogicJndiBindingLdapRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R603",
            Name: "WebLogic JNDI binding handle LDAP URI request",
            Category: "HttpApi",
            Description: "WebLogic GET query includes JndiBindingHandle, LDAP reference and AdminServer; JNDI lookup outcome unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R603.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R603", Name = "WebLogic JNDI binding handle LDAP URI request", Category = "HttpApi",
            Description = "WebLogic GET query includes JndiBindingHandle, LDAP reference and AdminServer; JNDI lookup outcome unknown.", Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination_or_host", "http.method", "http.uri", "protocol_or_port" },
            EvidenceFields = new[] { "http.signature", "http.method", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require a bounded parser-labeled cleartext HTTP request with coherent IP/TCP metadata.",
                "Match the independent rule-specific HTTP method/URI/header conjunction only.",
                "Request signature never establishes exploitation, compromised host or server response."
            },
            NegativeConditions = new[]
            {
                "No port-only, Info-only, other protocol, TLS, DNS/Redis, or synthetic evidence assertions.",
                "Reject missing required fields, malformed requests, benign near misses, duplicates and old timestamps.",
                "Never assert successful authentication, command execution, disclosure or persistence."
            },
            FalsePositives = new[] { "Authorized scanner, replay, attack simulation and maintenance traffic can resemble this request." },
            MinimumConfidence = 84, WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "one_specific_method_uri_headers_request_per_exact_source_destination",
            TuningKnobs = new[] { "Mode", "ApprovedMaintenanceWindows", "ApprovedScanners" },
            RequiredTests = new[]
            {
                "exact request positive and benign near miss negative",
                "wrong method and missing or contradictory parser fields",
                "duplicate ID, out-of-order timestamp, cooldown and bounded state",
                "redacted structured evidence and no server outcome inference",
                "candidate shadow mode and unique sequential registry entry"
            }
        });

        private readonly PortableR603Detector _detector = new();
        public R603_WebLogicJndiBindingLdapRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var observed = _detector.Evaluate(context.Packet, out var method);
            if (observed == WebSignatureObservation.None) return NoMatch();
            if (observed == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("http.signature", "workbook.R3037.request_shape", "http-request-fields"),
                new DetectionEvidenceItem("http.method", method, "http-request-fields"),
                new DetectionEvidenceItem("matched_conditions", "specific_http_request_shape", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Specific suspicious HTTP request shape observed; response and exploitation outcome unknown",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.43, "structured-http-request");
                    confidence.AddEvidence(0.36, "rule-specific-request-signature");
                    confidence.AddCorrelation(0.12, "coherent-network-metadata");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

    }
}
