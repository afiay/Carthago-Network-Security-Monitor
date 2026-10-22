// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleCatalogValidation.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public enum RuleCatalogValidationSeverity
    {
        Info,
        Warning,
        Error,
        Critical
    }

    public sealed record RuleCatalogValidationFinding(
        string? RuleId,
        RuleCatalogValidationSeverity Severity,
        string Code,
        string Message,
        string Dimension)
    {
        public bool IsCritical => Severity == RuleCatalogValidationSeverity.Critical;
        public bool IsError => Severity is RuleCatalogValidationSeverity.Error or RuleCatalogValidationSeverity.Critical;
    }

    public sealed record RuleCatalogValidationReport(IReadOnlyList<RuleCatalogValidationFinding> Findings)
    {
        public bool HasCriticalErrors => Findings.Any(static finding => finding.IsCritical);
        public bool HasErrors => Findings.Any(static finding => finding.IsError);
        public IReadOnlyList<RuleCatalogValidationFinding> CriticalErrors => Findings.Where(static finding => finding.IsCritical).ToArray();
        public IReadOnlyList<RuleCatalogValidationFinding> Errors => Findings.Where(static finding => finding.IsError).ToArray();
        public IReadOnlyList<RuleCatalogValidationFinding> Warnings => Findings.Where(static finding => finding.Severity == RuleCatalogValidationSeverity.Warning).ToArray();
        public IReadOnlyList<RuleCatalogValidationFinding> Infos => Findings.Where(static finding => finding.Severity == RuleCatalogValidationSeverity.Info).ToArray();

        public static RuleCatalogValidationReport Empty { get; } = new(Array.Empty<RuleCatalogValidationFinding>());
    }

    public sealed class RuleCatalogValidator
    {
        public RuleCatalogValidationReport Validate(IEnumerable<IDetectionRule> rules)
        {
            if (rules == null) throw new ArgumentNullException(nameof(rules));

            var ruleList = rules.Where(static rule => rule != null).ToArray();
            var findings = new List<RuleCatalogValidationFinding>();

            ValidateDuplicates(ruleList, findings);

            foreach (var rule in ruleList)
            {
                ValidateRule(rule, findings);
            }

            return new RuleCatalogValidationReport(findings
                .OrderByDescending(static finding => finding.Severity)
                .ThenBy(static finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static finding => finding.Code, StringComparer.OrdinalIgnoreCase)
                .ToArray());
        }

        private static void ValidateDuplicates(IReadOnlyList<IDetectionRule> rules, List<RuleCatalogValidationFinding> findings)
        {
            foreach (var duplicate in rules
                .GroupBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase)
                .Where(static group => group.Count() > 1))
            {
                findings.Add(new RuleCatalogValidationFinding(
                    duplicate.Key,
                    RuleCatalogValidationSeverity.Critical,
                    "DUPLICATE_RULE_ID",
                    $"RuleId '{duplicate.Key}' is registered {duplicate.Count()} times.",
                    "CatalogIdentity"));
            }

            foreach (var duplicate in rules
                .GroupBy(static rule => rule.Descriptor.ConfigKey, StringComparer.OrdinalIgnoreCase)
                .Where(static group => !string.IsNullOrWhiteSpace(group.Key) && group.Count() > 1))
            {
                var affectedRuleIds = duplicate
                    .Select(static rule => rule.Descriptor.RuleId)
                    .Where(static id => !string.IsNullOrWhiteSpace(id))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var message = $"ConfigKey '{duplicate.Key}' is used by: {string.Join(", ", affectedRuleIds)}.";

                findings.Add(new RuleCatalogValidationFinding(
                    null,
                    RuleCatalogValidationSeverity.Critical,
                    "DUPLICATE_CONFIG_KEY",
                    message,
                    "CatalogIdentity"));

                foreach (var affectedRuleId in affectedRuleIds)
                {
                    findings.Add(new RuleCatalogValidationFinding(
                        affectedRuleId,
                        RuleCatalogValidationSeverity.Critical,
                        "DUPLICATE_CONFIG_KEY",
                        message,
                        "CatalogIdentity"));
                }
            }
        }

        private static void ValidateRule(IDetectionRule rule, List<RuleCatalogValidationFinding> findings)
        {
            var descriptor = rule.Descriptor;
            var ruleId = descriptor.RuleId;

            if (string.IsNullOrWhiteSpace(ruleId))
            {
                findings.Add(new RuleCatalogValidationFinding(null, RuleCatalogValidationSeverity.Critical, "MISSING_RULE_ID", "A rule has an empty RuleId.", "CatalogIdentity"));
                return;
            }

            if (!RuleIdValidator.IsValid(ruleId))
            {
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "INVALID_RULE_ID", $"RuleId '{ruleId}' does not match the expected core R000 or content-pack rule ID format.", "CatalogIdentity"));
            }

            if (string.IsNullOrWhiteSpace(descriptor.Name))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "MISSING_NAME", "Rule has no display name.", "Metadata"));
            if (string.IsNullOrWhiteSpace(descriptor.Category))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_CATEGORY", "Rule has no category.", "Metadata"));
            if (string.IsNullOrWhiteSpace(descriptor.Description))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_DESCRIPTION", "Rule has no description.", "Metadata"));
            if (string.IsNullOrWhiteSpace(descriptor.ConfigKey))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "MISSING_CONFIG_KEY", "Rule has no config key.", "Policy"));
            if (!Enum.IsDefined(typeof(SeverityLevel), descriptor.DefaultSeverity))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "INVALID_SEVERITY", $"Rule severity '{descriptor.DefaultSeverity}' is not valid.", "Policy"));

            ValidateIntelligence(rule, findings);
            ValidatePrecision(rule, findings);
        }

        private static void ValidateIntelligence(IDetectionRule rule, List<RuleCatalogValidationFinding> findings)
        {
            var ruleId = rule.Descriptor.RuleId;
            var intelligence = rule.Intelligence;
            if (intelligence == null)
            {
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "MISSING_INTELLIGENCE", "Rule has no RuleIntelligence metadata.", "Intelligence"));
                return;
            }

            if (!string.Equals(intelligence.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "INTELLIGENCE_RULE_ID_MISMATCH", $"RuleIntelligence.RuleId is '{intelligence.RuleId}'.", "Intelligence"));
            if (intelligence.Revision < 1)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "INVALID_REVISION", "RuleIntelligence.Revision should be >= 1.", "Intelligence"));
            if (intelligence.TelemetryRequirements == null || intelligence.TelemetryRequirements.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_TELEMETRY_REQUIREMENTS", "RuleIntelligence has no telemetry requirements.", "Telemetry"));
            if (string.IsNullOrWhiteSpace(intelligence.InvestigationHint))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_INVESTIGATION_HINT", "Rule has no analyst investigation hint.", "AnalystWorkflow"));
            if (string.IsNullOrWhiteSpace(intelligence.TuningHint))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Info, "MISSING_TUNING_HINT", "Rule has no tuning hint.", "AnalystWorkflow"));
            if (intelligence.KnownFalsePositives == null || intelligence.KnownFalsePositives.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_FALSE_POSITIVE_NOTES", "Rule has no known false-positive notes.", "FalsePositiveControl"));
        }

        private static void ValidatePrecision(IDetectionRule rule, List<RuleCatalogValidationFinding> findings)
        {
            var descriptor = rule.Descriptor;
            var ruleId = descriptor.RuleId;
            var intelligenceProfile = rule.Intelligence?.PrecisionProfile;
            if (intelligenceProfile == null)
            {
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_PRECISION_PROFILE", "RuleIntelligence has no explicit precision profile; default catalog profile will be used.", "Precision"));
            }

            var profile = intelligenceProfile ?? RulePrecisionCatalog.GetProfile(descriptor);
            if (profile == null)
            {
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "MISSING_PRECISION_PROFILE", "Rule has no precision profile.", "Precision"));
                return;
            }

            if (!string.Equals(profile.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "PRECISION_RULE_ID_MISMATCH", $"Precision profile RuleId is '{profile.RuleId}'.", "Precision"));
            if (profile.RequiredTelemetry == null || profile.RequiredTelemetry.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "MISSING_REQUIRED_TELEMETRY", "Precision profile has no required telemetry kinds.", "Telemetry"));
            if (profile.RequiredFields == null || profile.RequiredFields.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "MISSING_REQUIRED_FIELDS", "Precision profile has no required fields.", "Telemetry"));
            if (profile.EvidenceFields == null || profile.EvidenceFields.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_EVIDENCE_FIELDS", "Precision profile has no evidence fields.", "Evidence"));
            if (profile.PositiveConditions == null || profile.PositiveConditions.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_POSITIVE_CONDITIONS", "Precision profile has no positive evidence conditions.", "Evidence"));
            if (profile.NegativeConditions == null || profile.NegativeConditions.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_NEGATIVE_CONDITIONS", "Precision profile has no negative evidence gates.", "Evidence"));
            if (profile.MinimumConfidence is < 0 or > 100)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Error, "INVALID_CONFIDENCE", "MinimumConfidence must be between 0 and 100.", "Precision"));
            if (profile.FalsePositiveNotes == null || profile.FalsePositiveNotes.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_PRECISION_FALSE_POSITIVES", "Precision profile has no false-positive notes.", "FalsePositiveControl"));
            if (profile.RequiredTests == null || profile.RequiredTests.Count == 0)
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "MISSING_REQUIRED_TESTS", "Precision profile has no required test categories.", "Testability"));

            if (RequiresState(profile) && profile.Window == null && profile.Threshold == null && string.IsNullOrWhiteSpace(profile.DistinctBy))
            {
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "STATE_REQUIREMENT_UNDECLARED", "Rule appears stateful but does not declare a window, threshold, or DistinctBy key.", "Statefulness"));
            }

            if (UsesBoundaryLogic(profile) && (profile.RequiredEnvironmentConfig == null || profile.RequiredEnvironmentConfig.Count == 0))
            {
                findings.Add(new RuleCatalogValidationFinding(ruleId, RuleCatalogValidationSeverity.Warning, "BOUNDARY_CONFIG_UNDECLARED", "Rule appears to use internal/external boundary logic but does not declare required environment configuration.", "EnvironmentPolicy"));
            }
        }

        private static bool RequiresState(RulePrecisionProfile profile)
            => ContainsAny(profile.PositiveConditions, "burst", "repeated", "sequence", "window", "baseline", "rate", "volume", "storm", "surge")
               || ContainsAny(profile.EvidenceFields, "count", "baseline", "window", "interval", "previous", "sequence");

        private static bool UsesBoundaryLogic(RulePrecisionProfile profile)
            => ContainsAny(profile.PositiveConditions, "external", "internal", "internet", "egress", "ingress", "public", "private")
               || ContainsAny(profile.RequiredFields, "network_boundary", "internal_external", "approved_destination");

        private static bool ContainsAny(IEnumerable<string>? values, params string[] needles)
        {
            if (values == null) return false;
            foreach (var value in values)
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                foreach (var needle in needles)
                {
                    if (value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }
            }

            return false;
        }
    }
}
