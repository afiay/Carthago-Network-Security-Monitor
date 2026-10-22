// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R450_NATSBrokerExternalAccessRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R450_NATSBrokerExternalAccessRule : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R450",
            Name: "NATS Broker External Access",
            Category: "DatabaseServiceExposure",
            Description: "Detects NATS Broker External Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R450.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R450",
            Name = "NATS Broker External Access",
            Category = "DatabaseServiceExposure",
            Description = "Detects NATS Broker External Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "database_destination", "database_protocol_or_query_marker" },
            EvidenceFields = new[] { "network.destinationPort", "database.service", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "NATS Broker External Access requires observable DatabaseServiceExposure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved DBA hosts, migration jobs, ETL workers, backup servers, and monitoring systems may access database services externally; tune them explicitly." },
            TextIndicators = new[] { "nats broker external access", "nats", "broker", "login", "auth", "select", "query", "export", "dump", "anonymous", "config", "replication" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 4222, 6222, 8222 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(15),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+databaseserviceexposure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDatabaseClients", "ApprovedBackupHosts", "AllowedDbPorts", "ExportByteThreshold" },
            RequiredTests = new[] { "positive R450 evidence-gated sample", "negative R450 descriptor-only sample", "negative R450 missing telemetry sample", "negative R450 approved-admin sample" },
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R450_NATSBrokerExternalAccessRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
