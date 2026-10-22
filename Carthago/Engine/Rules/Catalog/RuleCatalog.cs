// SPDX-License-Identifier: MIT
// File: Engine/Rules/Catalog/RuleCatalog.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;

namespace Carthago.Engine.Rules.Catalog
{
    public static class RuleCatalog
    {
        private static readonly Lazy<IReadOnlyList<IDetectionRule>> _rules = new(() =>
            RuleRegistry.CreateDefaultRules().OrderBy(r => r.Descriptor.RuleId, StringComparer.Ordinal).ToArray());

        private static readonly Lazy<IReadOnlyList<RuleDescriptor>> _descriptors = new(() =>
            _rules.Value.Select(r => r.Descriptor).ToArray());
        private static readonly Lazy<IReadOnlyList<IDetectionRule>> _availableRules = new(() =>
            RuleRegistry.CreateAvailableRules().OrderBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase).ToArray());
        private static readonly Lazy<IReadOnlyList<RuleDescriptor>> _availableDescriptors = new(() =>
            _availableRules.Value.Select(static rule => rule.Descriptor).ToArray());

        public static IReadOnlyList<IDetectionRule> Rules => _rules.Value;
        public static IReadOnlyList<RuleDescriptor> All => _descriptors.Value;
        public static IReadOnlyList<RuleIntelligence> Intelligence => _rules.Value.Select(r => r.Intelligence).ToArray();
        public static IReadOnlyList<IDetectionRule> AvailableRules => _availableRules.Value;
        public static IReadOnlyList<RuleDescriptor> AllAvailable => _availableDescriptors.Value;

        public static RuleDescriptor? Find(string ruleId) => All.FirstOrDefault(d => string.Equals(d.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));

        public static RuleCatalogValidationReport ValidateStructured()
            => new RuleCatalogValidator().Validate(Rules);

        public static IReadOnlyList<RuleHealthSnapshot> HealthSnapshots()
            => new RuleHealthSnapshotService(ruleProvider: () => Rules).Snapshot();

        public static IReadOnlyList<string> Validate()
        {
            var errors = new List<string>();
            var duplicateIds = All.GroupBy(d => d.RuleId, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToArray();
            if (duplicateIds.Length > 0) errors.Add("Duplicate RuleId: " + string.Join(", ", duplicateIds));

            var duplicateConfig = All.GroupBy(d => d.ConfigKey, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToArray();
            if (duplicateConfig.Length > 0) errors.Add("Duplicate ConfigKey: " + string.Join(", ", duplicateConfig));

            for (var i = 1; i <= 49; i++)
            {
                var expected = $"R{i:000}";
                if (Find(expected) == null) errors.Add($"Missing preserved rule {expected}");
            }

            var registryIds = RuleRegistry.CreateDefaultRules().Select(r => r.Descriptor.RuleId).OrderBy(id => id, StringComparer.Ordinal).ToArray();
            var catalogIds = All.Select(d => d.RuleId).OrderBy(id => id, StringComparer.Ordinal).ToArray();
            if (!registryIds.SequenceEqual(catalogIds, StringComparer.Ordinal)) errors.Add("RuleRegistry and RuleCatalog do not agree.");

            foreach (var rule in Rules)
            {
                var intel = rule.Intelligence;
                if (intel == null) errors.Add($"{rule.Descriptor.RuleId} has no RuleIntelligence.");
                else
                {
                    if (!string.Equals(intel.RuleId, rule.Descriptor.RuleId, StringComparison.OrdinalIgnoreCase))
                        errors.Add($"{rule.Descriptor.RuleId} intelligence RuleId mismatch.");
                    if (intel.Revision < 1) errors.Add($"{rule.Descriptor.RuleId} intelligence revision must be >= 1.");
                    if (intel.TelemetryRequirements == null || intel.TelemetryRequirements.Count == 0)
                        errors.Add($"{rule.Descriptor.RuleId} has no telemetry requirements.");
                    if (string.IsNullOrWhiteSpace(intel.InvestigationHint))
                        errors.Add($"{rule.Descriptor.RuleId} has no investigation hint.");
                }

                var precision = RulePrecisionCatalog.GetProfile(rule.Descriptor);
                if (!string.Equals(precision.RuleId, rule.Descriptor.RuleId, StringComparison.OrdinalIgnoreCase))
                    errors.Add($"{rule.Descriptor.RuleId} precision profile RuleId mismatch.");
                if (precision.RequiredTelemetry.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} precision profile has no required telemetry.");
                if (precision.RequiredFields.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} precision profile has no required fields.");
                if (precision.EvidenceFields.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} precision profile has no evidence fields.");
                if (precision.PositiveConditions.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} precision profile has no positive conditions.");
                if (precision.NegativeConditions.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} precision profile has no negative conditions.");
                if (precision.RequiredTests.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} precision profile has no required tests.");
            }

            return errors;
        }

        public static IReadOnlyList<string> ValidateAvailable()
        {
            var errors = new List<string>();
            var duplicateIds = AllAvailable.GroupBy(static descriptor => descriptor.RuleId, StringComparer.OrdinalIgnoreCase)
                .Where(static group => group.Count() > 1)
                .Select(static group => group.Key)
                .ToArray();
            if (duplicateIds.Length > 0)
                errors.Add("Duplicate available RuleId: " + string.Join(", ", duplicateIds));

            foreach (var rule in AvailableRules)
            {
                if (!RuleIdValidator.IsValid(rule.Descriptor.RuleId))
                    errors.Add($"Invalid RuleId format: {rule.Descriptor.RuleId}");
                if (rule.Intelligence == null)
                    errors.Add($"{rule.Descriptor.RuleId} has no RuleIntelligence.");
                else if (rule.Intelligence.TelemetryRequirements == null || rule.Intelligence.TelemetryRequirements.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} has no telemetry requirements.");

                var precision = RulePrecisionCatalog.GetProfile(rule.Descriptor);
                if (precision.RequiredTelemetry.Count == 0 || precision.RequiredFields.Count == 0)
                    errors.Add($"{rule.Descriptor.RuleId} has an incomplete precision profile.");
            }

            return errors;
        }
    }
}
