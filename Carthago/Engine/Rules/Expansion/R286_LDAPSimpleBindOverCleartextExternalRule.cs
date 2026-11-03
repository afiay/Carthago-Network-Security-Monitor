// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R286_LDAPSimpleBindOverCleartextExternalRule.cs
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R286_LDAPSimpleBindOverCleartextExternalRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R286",
            Name: "LDAP Simple Bind Over Cleartext External",
            Category: "IdentityAdvanced",
            Description: "Shadow-only candidate for a verified plaintext LDAPv3 nonanonymous simple BindRequest crossing an internal/external boundary; no authentication outcome inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R286.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R286",
            Name = "LDAP Simple Bind Over Cleartext External",
            Category = "IdentityAdvanced",
            Description = "Captured LDAPv3 simple BindRequest with nonempty DN/credential, not successful authentication.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RequiredTelemetry = new[] { RuleTelemetryKind.Packet, RuleTelemetryKind.Flow, RuleTelemetryKind.Directory },
            RequiredFields = new[] { "source", "destination", "capture_only_ldap_simple_bind" },
            EvidenceFields = new[] { "ldap.request_shape", "ldap.direction", "matched_conditions" },
            PositiveConditions = new[] { "Require a complete SYN-anchored, first client TCP/389 payload with a valid LDAPv3 BER nonempty simple BindRequest.", "Require an internal/external boundary; do not claim authentication success or a recovered password." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "ldap simple bind", "simple bind", "cleartext", "bindrequest", "password" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "ldap" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 389 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R286 captured LDAPv3 simple bind Shadow", "negative R286 SASL and anonymous bind", "negative R286 missing SYN, wrong direction, TLS, fragmentation and spoofed import", "negative R286 privacy, boundary and profile invariants" },
            RequireCleartext = true,
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R286_LDAPSimpleBindOverCleartextExternalRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!record.LdapCleartextSimpleBindObserved
                || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.DestinationPort != 389
                || !string.Equals(record.ApplicationProtocol, "ldap.bind.simple", StringComparison.Ordinal)
                || record.Sni != null || record.TlsVersion != null || record.Alpn != null
                || record.HttpMethod != null || record.HttpUri != null || record.HttpRequestHeaders != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "LDAP_SIMPLE_BIND_PARSE_UNAVAILABLE",
                    "Only a capture-derived, complete plaintext LDAPv3 simple BindRequest can qualify; labels and imported observations cannot.");

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch(RuleNoMatchReasonCategory.BoundaryMismatch,
                    "LDAP_SIMPLE_BIND_EXTERNAL_BOUNDARY_REQUIRED",
                    "A verified internal/external boundary is required for R286.");

            if (ApprovedAssetRegistry.Current.IsAdminHost(record.Source))
                return NoMatch(RuleNoMatchReasonCategory.AssetAllowed,
                    "LDAP_SIMPLE_BIND_APPROVED_ADMIN_SOURCE",
                    "An explicitly approved management source is excluded from this candidate.");

            var result = MatchCloudDev(context, SeverityLevel.High,
                "Plaintext LDAPv3 simple BindRequest across trust boundary (authentication outcome unknown)",
                "IdentityAdvanced",
                new[]
                {
                    new DetectionEvidenceItem("ldap.request_shape", "v3.simple-bind.nonempty", "packet-handler"),
                    new DetectionEvidenceItem("ldap.direction", "client-to-server.tcp389", "packet-handler"),
                    new DetectionEvidenceItem("matched_conditions", "complete_ber_simple_bind,cleartext,cross_boundary", "rule")
                }, confidence =>
                {
                    confidence.AddEvidence(0.46, "bounded-ldap-ber-simple-bind");
                    confidence.AddEvidence(0.22, "nonanonymous-cleartext-request");
                    confidence.AddCorrelation(0.18, "internal-external-boundary");
                }, count: 1, window: Spec.Window,
                cooldownKey: $"{record.Source}:{record.Destination}:ldap-simple-bind");

            // Keep historic profile metadata intact for existing contracts,
            // while independently prohibiting actual Alert delivery for this
            // newly connected candidate until quality/source review.
            if (result.Events.Count > 0
                && result.Events[0].SuppressionStatus == DetectionSuppressionStatus.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            foreach (var evt in result.Events)
                ShadowForWeakEvidence(evt, "R286 capture-only candidate; no independently confirmed LDAP authentication outcome or detection-quality admission.");
            return result;
        }
    }
}
