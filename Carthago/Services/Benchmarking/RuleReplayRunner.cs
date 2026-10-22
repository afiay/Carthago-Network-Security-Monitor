// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/RuleReplayRunner.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Models;

namespace Carthago.Services.Benchmarking
{
    public sealed class RuleReplayRunner
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public async Task<RuleReplaySampleResult> RunSampleAsync(
            RuleReplaySample sample,
            RuleReplayRunOptions? options = null,
            string? filePath = null,
            CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask.ConfigureAwait(false);

            if (sample == null) throw new ArgumentNullException(nameof(sample));
            options ??= new RuleReplayRunOptions();

            if (options.ResetRuntimeStateBeforeSample)
                RuleEngine.ResetRuntimeStateForReplay();

            var sw = Stopwatch.StartNew();
            var traces = new List<RuleEvaluationTrace>();
            var detections = new List<DetectionEvent>();
            var matched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var suppressed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var shadowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var failed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var noMatchCodesByRule = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var record in sample.Records ?? new List<TrafficRecord>())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var emittedEvents = RuleEngine.Evaluate(record, sample.Sensitivity ?? options.Sensitivity);
                detections.AddRange(emittedEvents);
                foreach (var evt in emittedEvents)
                {
                    if (!string.IsNullOrWhiteSpace(evt.RuleId))
                    {
                        emitted.Add(evt.RuleId);
                        matched.Add(evt.RuleId);
                    }
                }

                var trace = RuleEngine.LastEvaluationTrace;
                if (trace == null)
                    continue;

                traces.Add(trace);
                AddRange(matched, trace.MatchedRuleIds);
                AddRange(emitted, trace.EmittedRuleIds);
                AddRange(suppressed, trace.SuppressedRuleIds);
                AddRange(shadowed, trace.ShadowedRuleIds);
                AddRange(failed, trace.FailedRuleIds);
                foreach (var pair in trace.NoMatchReasonsByRuleId)
                {
                    if (!noMatchCodesByRule.TryGetValue(pair.Key, out var codes))
                    {
                        codes = new List<string>();
                        noMatchCodesByRule[pair.Key] = codes;
                    }

                    codes.AddRange(pair.Value.Select(static reason => reason.Code).Where(static code => !string.IsNullOrWhiteSpace(code)));
                }
            }

            sw.Stop();

            var expectedMatches = NormalizeRuleIds(sample.ExpectedMatches);
            var expectedEmitted = NormalizeRuleIds(sample.ExpectedEmittedMatches);
            var expectedNonMatches = NormalizeRuleIds(sample.ExpectedNonMatches);
            var expectedSuppressed = NormalizeRuleIds(sample.ExpectedSuppressedMatches);
            var expectedShadowed = NormalizeRuleIds(sample.ExpectedShadowedMatches);
            if (options.RequireExpectedMatchesToEmit)
            {
                foreach (var id in expectedMatches)
                    if (!expectedEmitted.Contains(id, StringComparer.OrdinalIgnoreCase))
                        expectedEmitted.Add(id);
            }

            var assertions = BuildAssertions(sample, expectedMatches, expectedEmitted, expectedNonMatches, expectedSuppressed, expectedShadowed);
            var observations = BuildObservations(detections, traces, noMatchCodesByRule);
            var observationByRule = observations.ToDictionary(static item => item.RuleId, StringComparer.OrdinalIgnoreCase);
            var actualMatched = matched.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            var actualEmitted = emitted.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            var actualSuppressed = suppressed.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            var actualShadowed = shadowed.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            var actualFailed = failed.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();

            var result = new RuleReplaySampleResult
            {
                Name = string.IsNullOrWhiteSpace(sample.Name) ? Path.GetFileNameWithoutExtension(filePath ?? "sample") : sample.Name,
                FilePath = filePath,
                Classification = sample.Classification ?? InferClassification(filePath),
                RecordCount = sample.Records?.Count ?? 0,
                TraceCount = traces.Count,
                DetectionCount = detections.Count,
                Duration = sw.Elapsed,
                Detections = detections,
                ExpectedMatchRuleIds = expectedMatches,
                ExpectedNonMatchRuleIds = expectedNonMatches,
                MatchedRuleIds = actualMatched,
                EmittedRuleIds = actualEmitted,
                SuppressedRuleIds = actualSuppressed,
                ShadowedRuleIds = actualShadowed,
                FailedRuleIds = actualFailed,
                RuleObservations = observations,
                NoMatchReasonCodesByRuleId = noMatchCodesByRule.ToDictionary(
                    static pair => pair.Key,
                    static pair => pair.Value.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(static value => value, StringComparer.OrdinalIgnoreCase).ToList(),
                    StringComparer.OrdinalIgnoreCase)
            };

            foreach (var expected in expectedMatches)
            {
                if (!matched.Contains(expected))
                {
                    result.MissingExpectedRuleIds.Add(expected);
                    result.Errors.Add($"{result.Name}: expected {expected} to match, but it did not match in any trace.");
                }
            }

            foreach (var expected in expectedEmitted)
            {
                if (!emitted.Contains(expected))
                    result.Errors.Add($"{result.Name}: expected {expected} to emit an alert, but it only matched in a non-emitting path or did not match.");
            }

            foreach (var expected in expectedSuppressed)
            {
                if (!suppressed.Contains(expected))
                    result.Errors.Add($"{result.Name}: expected {expected} to be suppressed by policy/tuning, but it was not suppressed.");
            }

            foreach (var expected in expectedShadowed)
            {
                if (!shadowed.Contains(expected))
                    result.Errors.Add($"{result.Name}: expected {expected} to be shadowed, but it was not shadowed.");
            }

            foreach (var forbidden in expectedNonMatches)
            {
                if (matched.Contains(forbidden))
                {
                    result.UnexpectedRuleIds.Add(forbidden);
                    if (options.TreatUnexpectedMatchesAsFailure)
                        result.Errors.Add($"{result.Name}: expected {forbidden} not to match, but it matched.");
                }
            }

            if (result.Classification == ReplaySampleClassification.Benign && options.TreatBenignEmissionsAsFailure && emitted.Count > 0)
            {
                foreach (var emittedRule in emitted)
                {
                    if (!expectedMatches.Contains(emittedRule, StringComparer.OrdinalIgnoreCase))
                    {
                        result.UnexpectedRuleIds.Add(emittedRule);
                        result.Errors.Add($"{result.Name}: benign replay emitted unexpected alert {emittedRule}.");
                    }
                }
            }

            if (options.MaximumUnexpectedMatchCount >= 0)
            {
                var unexpectedCount = result.UnexpectedRuleIds.Distinct(StringComparer.OrdinalIgnoreCase).Count();
                var maxAllowed = sample.MaximumUnexpectedMatches ?? options.MaximumUnexpectedMatchCount;
                if (unexpectedCount > maxAllowed)
                    result.Errors.Add($"{result.Name}: unexpected match count {unexpectedCount} exceeded allowed maximum {maxAllowed}.");
            }

            if (sample.ExpectedMinimumConfidence > 0)
            {
                var maximumConfidence = detections.Count == 0 ? 0.0 : detections.Max(static evt => evt.ConfidenceScore);
                if (maximumConfidence < sample.ExpectedMinimumConfidence)
                    result.Errors.Add($"{result.Name}: maximum confidence {maximumConfidence:F2} was below expected floor {sample.ExpectedMinimumConfidence:F2}.");
            }

            foreach (var assertion in assertions)
            {
                ValidateAssertion(result, assertion, observationByRule);
            }

            result.UnexpectedRuleIds = result.UnexpectedRuleIds
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                .ToList();
            result.MissingExpectedRuleIds = result.MissingExpectedRuleIds
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return result;
        }

        public async Task<RuleReplayDirectoryResult> RunDirectoryAsync(
            string directory,
            RuleReplayRunOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            options ??= new RuleReplayRunOptions();
            var result = new RuleReplayDirectoryResult
            {
                ReplayDirectory = Path.GetFullPath(directory)
            };

            if (!Directory.Exists(directory))
                return result;

            foreach (var file in EnumerateSampleFiles(directory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sample = await LoadSampleAsync(file, cancellationToken).ConfigureAwait(false);
                var sampleResult = await RunSampleAsync(sample, options, file, cancellationToken).ConfigureAwait(false);
                result.Samples.Add(sampleResult);
            }

            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var sample in result.Samples)
            {
                AddRange(covered, sample.MatchedRuleIds);
                AddRange(covered, sample.EmittedRuleIds);
                AddRange(covered, sample.SuppressedRuleIds);
                AddRange(covered, sample.ShadowedRuleIds);
                AddRange(covered, sample.ExpectedMatchRuleIds);
                AddRange(covered, sample.ExpectedNonMatchRuleIds);
                AddRange(covered, sample.MissingExpectedRuleIds);
                AddRange(covered, sample.UnexpectedRuleIds);
                AddRange(covered, sample.RuleObservations.Select(static observation => observation.RuleId));
            }

            result.Summary.SampleCount = result.Samples.Count;
            result.Summary.PassedSampleCount = result.Samples.Count(static sample => sample.Passed);
            result.Summary.FailedSampleCount = result.Samples.Count - result.Summary.PassedSampleCount;
            result.Summary.BenignSampleCount = result.Samples.Count(static sample => sample.Classification == ReplaySampleClassification.Benign);
            result.Summary.MaliciousSampleCount = result.Samples.Count(static sample => sample.Classification == ReplaySampleClassification.Malicious);
            result.Summary.TotalDetections = result.Samples.Sum(static sample => sample.DetectionCount);
            result.Summary.TotalUnexpectedMatches = result.Samples.Sum(static sample => sample.UnexpectedRuleIds.Count);
            result.Summary.TotalMissingExpectedMatches = result.Samples.Sum(static sample => sample.MissingExpectedRuleIds.Count);
            result.Summary.NoisyRules = result.Samples
                .Where(static sample => sample.Classification == ReplaySampleClassification.Benign)
                .SelectMany(static sample => sample.UnexpectedRuleIds.Concat(sample.EmittedRuleIds))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                .ToList();
            result.Summary.RulesWithNoReplayCoverage = RuleCatalog.All
                .Select(static descriptor => descriptor.RuleId)
                .Where(ruleId => !covered.Contains(ruleId))
                .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return result;
        }

        public static async Task<RuleReplaySample> LoadSampleAsync(string file, CancellationToken cancellationToken = default)
        {
            await using var stream = File.OpenRead(file);
            var sample = await JsonSerializer.DeserializeAsync<RuleReplaySample>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
            if (sample == null)
                throw new InvalidOperationException("Could not parse replay sample: " + file);

            if (string.IsNullOrWhiteSpace(sample.Name))
                sample.Name = Path.GetFileNameWithoutExtension(file);
            sample.Classification ??= InferClassification(file);
            return sample;
        }

        private static IEnumerable<string> EnumerateSampleFiles(string directory)
            => Directory.Exists(directory)
                ? Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories).OrderBy(static file => file, StringComparer.OrdinalIgnoreCase)
                : Array.Empty<string>();

        private static ReplaySampleClassification InferClassification(string? filePath)
        {
            if (!string.IsNullOrWhiteSpace(filePath) && filePath.IndexOf("benign", StringComparison.OrdinalIgnoreCase) >= 0)
                return ReplaySampleClassification.Benign;
            return ReplaySampleClassification.Malicious;
        }

        private static List<RuleReplaySampleAssertion> BuildAssertions(
            RuleReplaySample sample,
            List<string> expectedMatches,
            List<string> expectedEmitted,
            List<string> expectedNonMatches,
            List<string> expectedSuppressed,
            List<string> expectedShadowed)
        {
            var assertions = new Dictionary<string, RuleReplaySampleAssertion>(StringComparer.OrdinalIgnoreCase);
            RuleReplaySampleAssertion Get(string ruleId)
            {
                if (!assertions.TryGetValue(ruleId, out var assertion))
                {
                    assertion = new RuleReplaySampleAssertion { RuleId = ruleId };
                    assertions[ruleId] = assertion;
                }

                return assertion;
            }

            foreach (var id in expectedMatches) Get(id).MustMatch = true;
            foreach (var id in expectedEmitted) Get(id).MustEmit = true;
            foreach (var id in expectedNonMatches) Get(id).MustNotMatch = true;
            foreach (var id in expectedSuppressed) Get(id).MustSuppress = true;
            foreach (var id in expectedShadowed) Get(id).MustShadow = true;

            foreach (var explicitAssertion in sample.Assertions ?? new List<RuleReplaySampleAssertion>())
            {
                if (string.IsNullOrWhiteSpace(explicitAssertion.RuleId))
                    continue;

                var target = Get(explicitAssertion.RuleId.Trim().ToUpperInvariant());
                target.MustMatch |= explicitAssertion.MustMatch;
                target.MustEmit |= explicitAssertion.MustEmit;
                target.MustNotMatch |= explicitAssertion.MustNotMatch;
                target.MustSuppress |= explicitAssertion.MustSuppress;
                target.MustShadow |= explicitAssertion.MustShadow;
                target.MinimumConfidence = Math.Max(target.MinimumConfidence, explicitAssertion.MinimumConfidence);
                target.MinimumSeverity = MoreSevere(target.MinimumSeverity, explicitAssertion.MinimumSeverity);
                target.RequiredEvidenceKeys.AddRange(explicitAssertion.RequiredEvidenceKeys ?? new List<string>());
                target.RequiredNoMatchReasonCodes.AddRange(explicitAssertion.RequiredNoMatchReasonCodes ?? new List<string>());
            }

            return assertions.Values.ToList();
        }

        private static void ValidateAssertion(
            RuleReplaySampleResult result,
            RuleReplaySampleAssertion assertion,
            IReadOnlyDictionary<string, RuleReplayRuleObservation> observations)
        {
            if (string.IsNullOrWhiteSpace(assertion.RuleId))
                return;

            observations.TryGetValue(assertion.RuleId, out var observation);
            if (assertion.MustMatch && (observation == null || observation.MatchedCount <= 0))
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: MustMatch.");
            if (assertion.MustEmit && (observation == null || observation.EmittedCount <= 0))
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: MustEmit.");
            if (assertion.MustSuppress && (observation == null || observation.SuppressedCount <= 0))
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: MustSuppress.");
            if (assertion.MustShadow && (observation == null || observation.ShadowedCount <= 0))
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: MustShadow.");
            if (assertion.MustNotMatch && observation != null && observation.MatchedCount > 0)
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: MustNotMatch.");
            if (assertion.MinimumConfidence > 0 && (observation == null || observation.MaximumConfidence < assertion.MinimumConfidence))
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: confidence {observation?.MaximumConfidence ?? 0:F2} below {assertion.MinimumConfidence:F2}.");
            if (assertion.MinimumSeverity.HasValue && (observation?.MaximumSeverity == null || observation.MaximumSeverity.Value < assertion.MinimumSeverity.Value))
                result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: severity below {assertion.MinimumSeverity.Value}.");

            foreach (var key in assertion.RequiredEvidenceKeys ?? new List<string>())
            {
                if (observation == null || !observation.EvidenceKeys.Contains(key, StringComparer.OrdinalIgnoreCase))
                    result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: missing evidence key {key}.");
            }

            foreach (var code in assertion.RequiredNoMatchReasonCodes ?? new List<string>())
            {
                if (observation == null || !observation.NoMatchReasonCodes.Contains(code, StringComparer.OrdinalIgnoreCase))
                    result.Errors.Add($"{result.Name}: assertion failed for {assertion.RuleId}: missing no-match reason code {code}.");
            }
        }

        private static List<RuleReplayRuleObservation> BuildObservations(
            IReadOnlyList<DetectionEvent> detections,
            IReadOnlyList<RuleEvaluationTrace> traces,
            IReadOnlyDictionary<string, List<string>> noMatchCodesByRule)
        {
            var observations = new Dictionary<string, RuleReplayRuleObservation>(StringComparer.OrdinalIgnoreCase);
            RuleReplayRuleObservation Get(string ruleId)
            {
                if (!observations.TryGetValue(ruleId, out var observation))
                {
                    observation = new RuleReplayRuleObservation { RuleId = ruleId };
                    observations[ruleId] = observation;
                }

                return observation;
            }

            foreach (var trace in traces)
            {
                foreach (var id in trace.MatchedRuleIds) Get(id).MatchedCount++;
                foreach (var id in trace.EmittedRuleIds) Get(id).EmittedCount++;
                foreach (var id in trace.SuppressedRuleIds) Get(id).SuppressedCount++;
                foreach (var id in trace.ShadowedRuleIds) Get(id).ShadowedCount++;
                foreach (var id in trace.FailedRuleIds) Get(id).FailedCount++;
            }

            foreach (var eventGroup in detections.Where(static evt => !string.IsNullOrWhiteSpace(evt.RuleId)).GroupBy(static evt => evt.RuleId, StringComparer.OrdinalIgnoreCase))
            {
                var observation = Get(eventGroup.Key);
                var confidenceValues = eventGroup.Select(static evt => evt.ConfidenceScore).Where(static value => value > 0).ToList();
                if (confidenceValues.Count > 0)
                {
                    observation.MaximumConfidence = Math.Max(observation.MaximumConfidence, confidenceValues.Max());
                    observation.AverageConfidence = confidenceValues.Average();
                }

                observation.MaximumSeverity = eventGroup.Select(static evt => (SeverityLevel?)evt.Severity).OrderByDescending(static severity => severity).FirstOrDefault();
                foreach (var evidenceKey in eventGroup.SelectMany(ExtractEvidenceKeys))
                    observation.EvidenceKeys.Add(evidenceKey);
            }

            foreach (var pair in noMatchCodesByRule)
            {
                var observation = Get(pair.Key);
                observation.NoMatchReasonCount += pair.Value.Count;
                observation.NoMatchReasonCodes.AddRange(pair.Value);
            }

            foreach (var observation in observations.Values)
            {
                observation.EvidenceKeys = observation.EvidenceKeys
                    .Where(static key => !string.IsNullOrWhiteSpace(key))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static key => key, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                observation.NoMatchReasonCodes = observation.NoMatchReasonCodes
                    .Where(static code => !string.IsNullOrWhiteSpace(code))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static code => code, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            return observations.Values.OrderBy(static item => item.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static IEnumerable<string> ExtractEvidenceKeys(DetectionEvent evt)
        {
            if (evt.StructuredEvidence?.Items != null)
            {
                foreach (var item in evt.StructuredEvidence.Items)
                    if (!string.IsNullOrWhiteSpace(item.Key))
                        yield return item.Key;
            }

            if (string.IsNullOrWhiteSpace(evt.Evidence))
                yield break;

            foreach (var part in evt.Evidence.Split(new[] { ';', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var index = part.IndexOf('=');
                if (index > 0)
                    yield return part.Substring(0, index);
            }
        }

        private static SeverityLevel? MoreSevere(SeverityLevel? a, SeverityLevel? b)
        {
            if (!a.HasValue) return b;
            if (!b.HasValue) return a;
            return a.Value >= b.Value ? a : b;
        }

        private static List<string> NormalizeRuleIds(IEnumerable<string>? values)
            => values?
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim().ToUpperInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                .ToList()
               ?? new List<string>();

        private static void AddRange(HashSet<string> target, IEnumerable<string>? values)
        {
            if (values == null) return;
            foreach (var value in values)
                if (!string.IsNullOrWhiteSpace(value))
                    target.Add(value.Trim().ToUpperInvariant());
        }
    }
}
