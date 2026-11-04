// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2742.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R724_NetworkUtilityPublicIpDiscoveryServiceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R724",
            Name: "Network utility contact to public-IP discovery service",
            Category: "NetworkDiscovery",
            Description: "Curl, Wget, or PowerShell is associated with an outbound HTTP/TLS contact to a bounded public-IP discovery service. The user's intent, shell command, returned public IP, subsequent behavior, and malicious purpose are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R724.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R724",
            Name = "Network utility contact to public-IP discovery service",
            Category = "NetworkDiscovery",
            Description = "Workbook R2742: the source analytic detects Internet connection discovery using ping/traceroute/curl/wget. Carthago cannot see shell intent or command arguments, so this rule is restricted to exact network-utility process attribution and known public-IP discovery service hosts.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination_or_host", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet, parser, and best-effort process fields for this exact independent predicate.",
                "Multi-observation rules use bounded unique packet IDs with UTC ordering and a fixed rule-owned window.",
                "Only the observable network/request/process association is claimed; endpoint or server outcome is not inferred."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, and free-form Info-only indicators.",
                "Reject duplicate packet IDs, stale/out-of-order observations, and cooldown repeats.",
                "Do not infer authentication, command-line arguments, file reads/writes, transfer completion, exploit success, or compromise."
            },
            FalsePositives = new[] { "Installation scripts, diagnostics, VPN clients, deployment automation, support tooling, and administrators commonly query public-IP discovery services." },
            MinimumConfidence = 76,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+network_utility_pid+ip_discovery_service",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R724_NetworkUtilityPublicIpDiscoveryServiceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research716Evidence.Process(r, "curl.exe", "curl", "wget.exe", "wget", "powershell.exe", "pwsh.exe"))
                return NoMatch();
            
            var httpMatch = WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                && method == "GET"
                && Research676Evidence.PrivateToPublic(r)
                && Research716Evidence.PublicIpDiscoveryHost(r.HttpHost);
            
            var tlsMatch = Research716Evidence.OutboundTls443(r)
                && Research716Evidence.PublicIpDiscoveryHost(r.Sni);
            
            if (!httpMatch && !tlsMatch) return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2742", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "network_utility_public_ip_discovery_service_contact", "rule"),
                new DetectionEvidenceItem("outcome", "internet_discovery_service_contact_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Network utility contacted a public-IP discovery service; command intent, returned address, and follow-on use are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
