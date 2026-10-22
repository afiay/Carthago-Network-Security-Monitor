using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Models;

namespace Carthago.Tests
{
    public sealed class RuleReplaySample
    {
        public string Name { get; set; } = string.Empty;
        public List<TrafficRecord> Records { get; set; } = new();
        public List<string> ExpectedMatches { get; set; } = new();
        public List<string> ExpectedNonMatches { get; set; } = new();
        public double ExpectedMinimumConfidence { get; set; }
    }

    public static class RuleReplayTestHarness
    {
        public static async Task<IReadOnlyList<string>> RunSampleAsync(RuleReplaySample sample)
        {
            var errors = new List<string>();
            var registry = RuleRegistry.CreateDefaultRules();
            var matched = new List<DetectionEvent>();
            foreach (var record in sample.Records)
            {
                foreach (var rule in registry)
                {
                    var result = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
                    if (result.Matched) matched.AddRange(result.Events);
                }
            }
            foreach (var id in sample.ExpectedMatches)
            {
                if (!matched.Any(e => string.Equals(e.RuleId, id, StringComparison.OrdinalIgnoreCase))) errors.Add($"{sample.Name}: expected {id} to match.");
            }
            foreach (var id in sample.ExpectedNonMatches)
            {
                if (matched.Any(e => string.Equals(e.RuleId, id, StringComparison.OrdinalIgnoreCase))) errors.Add($"{sample.Name}: expected {id} not to match.");
            }
            if (sample.ExpectedMinimumConfidence > 0 && matched.Count > 0 && matched.Max(e => e.ConfidenceScore) < sample.ExpectedMinimumConfidence)
                errors.Add($"{sample.Name}: confidence below {sample.ExpectedMinimumConfidence}.");
            return errors;
        }

        public static async Task<IReadOnlyList<string>> RunDirectoryAsync(string directory)
        {
            var errors = new List<string>();
            if (!Directory.Exists(directory)) return errors;
            foreach (var file in Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories))
            {
                var sample = JsonSerializer.Deserialize<RuleReplaySample>(await File.ReadAllTextAsync(file), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (sample == null) { errors.Add($"Could not parse {file}"); continue; }
                errors.AddRange(await RunSampleAsync(sample));
            }
            return errors;
        }
    }
}
