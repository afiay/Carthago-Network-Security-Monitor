// SPDX-License-Identifier: MIT
// File: Interop/Sigma/SigmaRuleExporter.cs
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Interop.Sigma
{
    public sealed class SigmaRuleExporter
    {
        public SigmaRuleExport Export(IDetectionRule rule)
        {
            var d = rule.Descriptor;
            var i = rule.Intelligence;
            return new SigmaRuleExport
            {
                Title = d.Name,
                Id = d.RuleId,
                Status = i.Maturity.ToString().ToLowerInvariant(),
                Description = d.Description,
                References = i.References.Select(r => r.Url).Distinct().ToList(),
                Tags = i.Tags.Concat(i.AttackTechniqueIds.Select(t => "attack." + t.ToLowerInvariant())).Distinct().ToList(),
                FalsePositives = i.KnownFalsePositives.Select(fp => fp.Scenario).ToList(),
                Level = d.DefaultSeverity.ToString().ToLowerInvariant(),
                SignalKind = i.SignalKind.ToString(),
                IsBehavioral = i.SignalKind is RuleSignalKind.Behavioral or RuleSignalKind.Baseline or RuleSignalKind.Correlation or RuleSignalKind.ProtocolAnomaly,
                ExportNote = "Carthago behavioral heuristics are exported as metadata. They are not automatically valid Sigma/SIEM queries or Suricata packet signatures."
            };
        }

        public string ExportJson(IDetectionRule rule) => JsonSerializer.Serialize(Export(rule), new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } });
    }
}
