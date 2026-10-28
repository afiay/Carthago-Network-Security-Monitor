// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R349_LDAPKerberoastSPNEnumerationRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R349_LDAPKerberoastSPNEnumerationRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R349",
            Name: "LDAP Kerberoast SPN Enumeration",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R349 requires verified operation and provenance; packet-only indicators return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R349.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R349",
            Name = "LDAP Kerberoast SPN Enumeration",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R349 requires verified operation and provenance; packet-only indicators return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "LDAP Kerberoast SPN Enumeration requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "kerberoast", "serviceprincipalname", "spn enumeration", "ldap filter" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "ldap", "kerberos" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 389, 636, 88 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R349 evidence-gated sample", "negative R349 descriptor-only sample", "negative R349 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R349_LDAPKerberoastSPNEnumerationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // A network port or textual SQL/LDAP descriptor is not an authenticated operation audit.
            // The capture adapter does not parse trustworthy TDS/LDAP request and result provenance.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "LDAP_SPN_SEARCH_AUDIT_UNAVAILABLE",
                "Kerberoast-related SPN enumeration requires parsed authenticated LDAP search and KDC ticket evidence before attributing roasting intent.");
        }
    }
}
