// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R343_PowerShellRemotingEncodedCommandRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R343_PowerShellRemotingEncodedCommandRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R343",
            Name: "PowerShell Remoting Encoded Command",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R343 requires verified operation and provenance; packet-only indicators return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R343.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R343",
            Name = "PowerShell Remoting Encoded Command",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R343 requires verified operation and provenance; packet-only indicators return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "PowerShell Remoting Encoded Command requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "powershell remoting", "encodedcommand", "-enc", "wsman", "winrm" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = new[] { "powershell", "pwsh", "wsmprovhost" },
            ProtocolIndicators = new[] { "winrm", "wsman" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 5985, 5986 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            CorroboratedEvidenceWeight = 0.10,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R343 evidence-gated sample", "negative R343 descriptor-only sample", "negative R343 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R343_PowerShellRemotingEncodedCommandRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Capture exposes network observations, not authenticated operation/outcome audit.
            // Do not promote text indicators, port hints or unverified enrichment to attack evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "WINRM_COMMAND_AUDIT_UNAVAILABLE",
                "PowerShell remoting encoded-command attribution requires trusted WinRM operation and process command-line audit; Info text and port 5985/5986 are insufficient.");
        }
    }
}
