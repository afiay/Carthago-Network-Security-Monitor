// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R333_SMBNullSessionEnumerationRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R333_SMBNullSessionEnumerationRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R333",
            Name: "SMB Null Session Enumeration",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R333 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R333.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R333",
            Name = "SMB Null Session Enumeration",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R333 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "SMB Null Session Enumeration requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "null session", "anonymous", "ipc$", "tree connect", "anonymous logon" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "smb", "cifs" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 445, 139 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R333 evidence-gated sample", "negative R333 descriptor-only sample", "negative R333 missing telemetry sample" },
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R333_SMBNullSessionEnumerationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // No authenticated application/session outcome producer is connected to this capture path.
            // Packet descriptions, paths and ports are not sufficient proof of this behavior.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "SMB_SESSION_AUTH_AUDIT_UNAVAILABLE",
                "SMB port and IPC$ vocabulary do not prove anonymous SMB authentication or enumeration. Require validated SMB session identity, tree connect and enumeration outcome.");
        }
    }
}
