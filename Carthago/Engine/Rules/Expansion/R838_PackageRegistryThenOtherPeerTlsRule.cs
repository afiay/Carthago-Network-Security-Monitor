// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1217.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R838_PackageRegistryThenOtherPeerTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R838", Name: "Package client registry TLS then different-peer TLS", Category: "CommandControl",
            Description: "Same npm, pip or dotnet process and PID contacts a known package registry then a different public peer on TCP/8443; no package tampering or malicious build claimed.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R838.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R838", Name = "Package client registry TLS then different-peer TLS", Category = "CommandControl",
            Description = "workbook.R1217: Same npm, pip or dotnet process and PID contacts a known package registry then a different public peer on TCP/8443; no package tampering or malicious build claimed.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Typed IPv4 packet predicate and independent UTC-bounded observation match.",
                "No unobserved endpoint execution, authentication or causality asserted."
            },
            NegativeConditions = new[] {
                "Missing or contradictory typed fields, repeated IDs, reverse UTC order and stale state fail closed.",
                "No encrypted contents interpreted; no benign authorization inferred."
            },
            FalsePositives = new[] {
                "Authorized automation, infrastructure updates, diagnostics and red-team traffic can share the observable shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "package_registry_then_other_peer_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "specific positive/benign case", "missing/contradictory evidence",
                "duplicate and expired observation", "cooldown recovery", "raw Info excluded",
                "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();
        public R838_PackageRegistryThenOtherPeerTlsRule() : base(Rule, Profile) { }

        private static bool ValidTls(TrafficRecord record) =>
            Research786NetworkEvidence.TcpData(record)
            && !string.IsNullOrWhiteSpace(record.TlsVersion) && !string.IsNullOrWhiteSpace(record.Sni)
            && record.HttpMethod == null && record.HttpUri == null && record.DnsQname == null
            && !record.DnsIsResponse
            && !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase);

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!ValidTls(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "npm", "npm.exe", "node", "node.exe", "pip", "pip.exe", "dotnet", "dotnet.exe")) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (r.DestinationPort == 443 && (string.Equals(r.Sni, "registry.npmjs.org", StringComparison.OrdinalIgnoreCase)
                || string.Equals(r.Sni, "pypi.org", StringComparison.OrdinalIgnoreCase)
                || string.Equals(r.Sni, "api.nuget.org", StringComparison.OrdinalIgnoreCase)))
            {
                _peers.Observe(key, r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (r.DestinationPort != 8443 || r.L4Len is < 256 or > 4096
                || !_peers.Observe(key, r.Destination!, r.Id, context.TimestampUtc, false)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1217", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "package_registry_then_other_peer_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Package client registry TLS then different-peer TLS observed; provenance, authorization and outcome unverified.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_independent_observable_predicate");
                    confidence.AddCorrelation(0.12, "bounded_utc_correlation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

