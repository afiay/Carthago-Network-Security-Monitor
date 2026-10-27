// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R066_FirstTimeCountryForHostRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNetworkState _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R066", Name: "First-Time Country for Host", Category: "AssetInventory",
            Description: "Corroborated first-seen destination country against a ready durable baseline; not a country-risk verdict.",
            DefaultSeverity: SeverityLevel.Low, ConfigKey: "Rules.R066.Enabled", EnabledByDefault: true);

        private static bool Country(string? raw, out string code)
        {
            code = "";
            var value = raw?.Trim();
            if (value?.Length != 2 || value[0] < 'A' && value[0] < 'a'
                || value[0] > 'Z' && value[0] > 'z'
                || value[1] < 'A' && value[1] < 'a'
                || value[1] > 'Z' && value[1] > 'z') return false;
            code = value.ToUpperInvariant();
            return code != "ZZ" && code != "XX" && code != "AP" && code != "EU";
        }

        public override async ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetNetworkEvidence.Outbound(context, out var source, out _))
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId);
            var record = context.Record;
            var hasGeo = !string.IsNullOrWhiteSpace(record.DstCountryIso2);
            var hasWhois = !string.IsNullOrWhiteSpace(record.WhoisCountry);
            if (!hasGeo && !hasWhois) return RuleEvaluationResult.NoMatch(Descriptor.RuleId);
            if (hasGeo && !Country(record.DstCountryIso2, out _)
                || hasWhois && !Country(record.WhoisCountry, out _))
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId);
            Country(hasGeo ? record.DstCountryIso2 : record.WhoisCountry, out var country);
            if (hasGeo && hasWhois && !string.Equals(record.DstCountryIso2!.Trim(),
                record.WhoisCountry!.Trim(), StringComparison.OrdinalIgnoreCase))
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId);
            var matched = await AssetNetworkBaseline.Observe(_state, context, "host_country",
                source, country, 3, cancellationToken).ConfigureAwait(false);
            return matched ? RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetNetworkEvidence.Alert(Descriptor, context,
                    "New destination country corroborated against a ready persisted baseline."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId);
        }
    }
}
