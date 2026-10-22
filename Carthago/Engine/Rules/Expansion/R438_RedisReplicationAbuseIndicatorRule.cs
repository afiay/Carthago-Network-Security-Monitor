// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R438_RedisReplicationAbuseIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R438_RedisReplicationAbuseIndicatorRule : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R438",
            Name: "Redis Replication Abuse Indicator",
            Category: "DatabaseServiceExposure",
            Description: "Detects Redis Replication Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R438.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R438",
            Name = "Redis Replication Abuse Indicator",
            Category = "DatabaseServiceExposure",
            Description = "Detects Redis Replication Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "database_destination", "database_protocol_or_query_marker" },
            EvidenceFields = new[] { "network.destinationPort", "database.service", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "Redis Replication Abuse Indicator requires observable DatabaseServiceExposure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved DBA hosts, migration jobs, ETL workers, backup servers, and monitoring systems may access database services externally; tune them explicitly." },
            TextIndicators = new[] { "redis replication abuse indicator", "redis", "replication", "abuse", "login", "auth", "select", "query", "export", "dump", "anonymous", "config" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "config set", "slaveof", "replicaof" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "redis" },
            Methods = new[] { "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 6379 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(15),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+databaseserviceexposure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDatabaseClients", "ApprovedBackupHosts", "AllowedDbPorts", "ExportByteThreshold" },
            RequiredTests = new[] { "positive R438 evidence-gated sample", "negative R438 descriptor-only sample", "negative R438 missing telemetry sample", "negative R438 approved-admin sample" },
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R438_RedisReplicationAbuseIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
