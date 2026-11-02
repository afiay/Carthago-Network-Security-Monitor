// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R437_RedisCONFIGSETIndicatorRule.cs
using System;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R437_RedisCONFIGSETIndicatorRule : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R437",
            Name: "Redis CONFIG SET Indicator",
            Category: "DatabaseServiceExposure",
            Description: "Detects Redis CONFIG SET Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R437.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R437",
            Name = "Redis CONFIG SET Indicator",
            Category = "DatabaseServiceExposure",
            Description = "Detects Redis CONFIG SET Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "database_destination", "database_protocol_or_query_marker" },
            EvidenceFields = new[] { "network.destinationPort", "database.service", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "Redis CONFIG SET Indicator requires observable DatabaseServiceExposure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved DBA hosts, migration jobs, ETL workers, backup servers, and monitoring systems may access database services externally; tune them explicitly." },
            TextIndicators = new[] { "redis config set indicator", "redis", "config", "login", "auth", "select", "query", "export", "dump", "anonymous", "replication" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "config set", "slaveof", "replicaof" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "redis" },
            Methods = new[] { "post", "put", "connect", "get" },
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
            RequiredTests = new[] { "positive R437 evidence-gated sample", "negative R437 descriptor-only sample", "negative R437 missing telemetry sample", "negative R437 approved-admin sample" },
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R437_RedisCONFIGSETIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;

            if (record.RedisRespConfigSetReplyErrorObserved)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "REDIS_CONFIG_SET_SERVER_REJECTED",
                    "A correlated RESP2 error reply was observed; no CONFIG SET acceptance or configuration change can be claimed.");

            if (record.RedisRespConfigSetReplyOkObserved)
            {
                // The correlated +OK is an unauthenticated wire reply.
                // A source allowlist is mandatory even for candidate evaluation.
                // Neither a spoofable wire reply nor the absence of an allowlist
                // may be promoted to a security incident.
                if (!record.IsTcp || record.SourcePort != 6379
                    || string.IsNullOrWhiteSpace(record.Source)
                    || string.IsNullOrWhiteSpace(record.Destination))
                    return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                        "REDIS_CONFIG_SET_CORRELATED_ENDPOINTS_UNAVAILABLE",
                        "Source, destination and Redis server direction are required to evaluate a correlated command reply.");

                var approvals = ApprovedAssetRegistry.Current;
                if (!approvals.HasApprovedAdminHosts)
                    return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                        "REDIS_CONFIG_SET_ADMIN_CLIENT_POLICY_UNCONFIGURED",
                        "Configure Approved.AdminHosts to classify the client of a correlated CONFIG SET reply; no default approval or unapproved status is inferred.");

                if (approvals.IsAdminHost(record.Destination))
                    return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                        "REDIS_CONFIG_SET_APPROVED_ADMIN_CLIENT",
                        "The correlated client is on the configured admin-host allowlist; this does not establish a completed configuration change.");

                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "REDIS_CONFIG_SET_UNAPPROVED_CLIENT_REQUIRES_SERVER_IDENTITY",
                    "The correlated client is not on the configured admin-host allowlist, but server identity, trusted audit and authorization context remain insufficient for an alert.");
            }

            // Bare command shape, ports, Info, or request/response text remain
            // subject to the original hard missing-producer evidence boundary.
            return EvaluateSpec(context, Spec);
        }
    }
}
