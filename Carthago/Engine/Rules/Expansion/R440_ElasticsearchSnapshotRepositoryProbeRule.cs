// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R440_ElasticsearchSnapshotRepositoryProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R440_ElasticsearchSnapshotRepositoryProbeRule : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R440",
            Name: "Elasticsearch Snapshot Repository Probe",
            Category: "DatabaseServiceExposure",
            Description: "Detects Elasticsearch Snapshot Repository Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R440.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R440",
            Name = "Elasticsearch Snapshot Repository Probe",
            Category = "DatabaseServiceExposure",
            Description = "Detects Elasticsearch Snapshot Repository Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "database_destination", "database_protocol_or_query_marker" },
            EvidenceFields = new[] { "network.destinationPort", "database.service", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "Elasticsearch Snapshot Repository Probe requires observable DatabaseServiceExposure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved DBA hosts, migration jobs, ETL workers, backup servers, and monitoring systems may access database services externally; tune them explicitly." },
            TextIndicators = new[] { "elasticsearch snapshot repository probe", "elasticsearch", "snapshot", "repository", "login", "auth", "select", "query", "export", "dump", "anonymous", "config", "replication" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/_cluster/health", "/_cat/indices", "/_snapshot" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 9200, 9300 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(15),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+databaseserviceexposure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDatabaseClients", "ApprovedBackupHosts", "AllowedDbPorts", "ExportByteThreshold" },
            RequiredTests = new[] { "positive R440 evidence-gated sample", "negative R440 descriptor-only sample", "negative R440 missing telemetry sample", "negative R440 approved-admin sample" },
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R440_ElasticsearchSnapshotRepositoryProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
