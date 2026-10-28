// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R336_DRSUAPIReplicationAttemptRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R336_DRSUAPIReplicationAttemptRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R336",
            Name: "DRSUAPI Replication Attempt",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R336 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R336.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R336",
            Name = "DRSUAPI Replication Attempt",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R336 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "DRSUAPI Replication Attempt requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "drsuapi", "replication", "dcsync", "getncchanges", "directory replication" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "drsuapi", "dcerpc" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 135, 445, 139 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R336 evidence-gated sample", "negative R336 descriptor-only sample", "negative R336 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R336_DRSUAPIReplicationAttemptRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // No authenticated protocol operation/outcome producer is connected to the capture path.
            // Packet text, generic service ports and unverified enrichment cannot prove this behavior.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "DRSUAPI_REPLICATION_AUDIT_UNAVAILABLE",
                "DRSUAPI strings and RPC ports do not prove a replication request or unauthorized DCSync. Require parsed RPC interface and operation, authenticated principal, domain controller identity and outcome.");
        }
    }
}
