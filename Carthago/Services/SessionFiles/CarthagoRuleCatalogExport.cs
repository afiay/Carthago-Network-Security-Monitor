// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Models;

namespace Carthago.Services.SessionFiles;

internal sealed record CarthagoRuleCatalogRow(
    string RuleId,
    string RuleName,
    string Category,
    string Description,
    string DefaultSeverity,
    bool EnabledByDefault,
    string ConfigKey,
    bool IsPlanned,
    string? MissingTelemetry,
    string Maturity,
    string SignalKind,
    int Revision,
    string? PrecisionMaturity,
    string? DefaultMode,
    int? MinimumConfidence,
    int? Threshold,
    double? WindowSeconds,
    double? CooldownSeconds,
    string? DistinctBy,
    string RequiredTelemetry,
    string RequiredFields,
    string OptionalEnrichmentFields,
    string EvidenceFields,
    string AttackTactics,
    string AttackTechniqueIds,
    string Tags,
    string FalsePositiveNotes,
    string InvestigationHint,
    string TuningHint,
    int ObservedEvents,
    DateTime? MostRecentUtc,
    bool AlertEmissionsNotIndependentlyVerified);

internal static class CarthagoRuleCatalogExport
{
    internal static IReadOnlyList<CarthagoRuleCatalogRow> Build(IEnumerable<DetectionEvent> alerts)
    {
        ArgumentNullException.ThrowIfNull(alerts);
        var observed = alerts
            .Where(a => !string.IsNullOrWhiteSpace(a.RuleId))
            .GroupBy(a => a.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => new ObservedRuleStats(group.Count(), group.Max(a => a.TimestampUtc)),
                StringComparer.OrdinalIgnoreCase);

        return RuleRegistry.CreateDefaultRules()
            .GroupBy(rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(rule => RuleIdValidator.CoreOrder(rule.Descriptor.RuleId))
            .Select(rule =>
            {
                RuleDescriptor descriptor = rule.Descriptor;
                RuleIntelligence intelligence = rule.Intelligence;
                RulePrecisionProfile? precision = intelligence.PrecisionProfile;
                observed.TryGetValue(descriptor.RuleId, out ObservedRuleStats? stat);

                return new CarthagoRuleCatalogRow(
                    descriptor.RuleId,
                    descriptor.Name,
                    descriptor.Category,
                    descriptor.Description,
                    descriptor.DefaultSeverity.ToString(),
                    descriptor.EnabledByDefault,
                    descriptor.ConfigKey,
                    descriptor.IsPlanned,
                    descriptor.MissingTelemetry,
                    intelligence.Maturity.ToString(),
                    intelligence.SignalKind.ToString(),
                    intelligence.Revision,
                    precision?.Maturity.ToString(),
                    precision?.DefaultMode.ToString(),
                    precision?.MinimumConfidence,
                    precision?.Threshold,
                    precision?.Window?.TotalSeconds,
                    precision?.Cooldown?.TotalSeconds,
                    precision?.DistinctBy,
                    Join(precision?.RequiredTelemetry.Select(value => value.ToString())),
                    Join(precision?.RequiredFields),
                    Join(precision?.OptionalEnrichmentFields),
                    Join(precision?.EvidenceFields),
                    Join(intelligence.AttackTactics),
                    Join(intelligence.AttackTechniqueIds),
                    Join(intelligence.Tags),
                    Join(intelligence.KnownFalsePositives.Select(note => note.Scenario)),
                    intelligence.InvestigationHint,
                    intelligence.TuningHint,
                    stat?.Count ?? 0,
                    stat?.MostRecentUtc,
                    true);
            })
            .ToArray();
    }

    private static string Join(IEnumerable<string>? values)
        => values == null
            ? string.Empty
            : string.Join(" | ", values
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase));

    private sealed record ObservedRuleStats(int Count, DateTime MostRecentUtc);
}
