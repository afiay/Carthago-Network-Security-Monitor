// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkRunner.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Carthago.Services;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;
using Carthago.Services.Baseline;

namespace Carthago.Services.Benchmarking
{
    public sealed class TuningBenchmarkRunner
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        // RuleEngine replay resets additional process-level detector state, so
        // two benchmark runs inside one process must not overlap.
        private static readonly SemaphoreSlim ReplayGate = new(1, 1);

        public async Task<TuningBenchmarkReport> RunAsync(TuningBenchmarkOptions options, CancellationToken cancellationToken = default)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            await ReplayGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            var baselineDirectory = Path.Combine(Path.GetTempPath(), "carthago-replay-baseline-" + Guid.NewGuid().ToString("N"));
            try
            {
                // Never clear or append to the live baseline journal in ProgramData.
                // The scope flows through awaits and is restored on success/failure.
                using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = baselineDirectory })))
                    return await RunIsolatedAsync(options, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    if (Directory.Exists(baselineDirectory))
                        Directory.Delete(baselineDirectory, recursive: true);
                }
                catch (IOException) { /* Safe to leave an isolated temporary baseline on disk. */ }
                catch (UnauthorizedAccessException) { /* Do not mask the benchmark failure. */ }
                finally { ReplayGate.Release(); }
            }
        }

        private async Task<TuningBenchmarkReport> RunIsolatedAsync(TuningBenchmarkOptions options, CancellationToken cancellationToken)
        {
            var rules = RuleRegistry.CreateDefaultRules()
                .OrderBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var rulesById = rules.ToDictionary(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase);
            var report = new TuningBenchmarkReport
            {
                Name = options.Name,
                GeneratedAtUtc = DateTime.UtcNow,
                ReplayDirectory = Path.GetFullPath(options.ReplayDirectory)
            };

            var defaultProfileName = RuleTuningCatalog.DefaultProfileName;
            var ruleCoverage = RuleCatalog.All.ToDictionary(
                static descriptor => descriptor.RuleId,
                static descriptor => new CoverageAccumulator(descriptor.RuleId),
                StringComparer.OrdinalIgnoreCase);
            var profileAccumulators = options.Profiles
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(RuleTuningCatalog.NormalizeProfileName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    static profile => profile,
                    static profile => new ProfileAccumulator(profile),
                    StringComparer.OrdinalIgnoreCase);

            var recommendShadow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var recommendAlert = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var noisyRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var confidenceDistribution = CreateConfidenceBuckets();

            foreach (var file in EnumerateSampleFiles(options.ReplayDirectory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sample = await LoadSampleAsync(file, cancellationToken).ConfigureAwait(false);
                var classification = sample.Classification ?? InferClassification(file);
                var approvedAssets = new ApprovedAssetRegistry(sample.EnvironmentTuning);

                RuleEngine.ResetRuntimeStateForReplay();

                var matches = new List<ReplayMatch>();
                var expectedMatchIds = NormalizeRuleIds(sample.ExpectedMatches);
                var expectedDiagnostics = expectedMatchIds.ToDictionary(
                    static id => id,
                    static id => new TuningBenchmarkExpectedRuleDiagnostic { RuleId = id, Outcome = "RuleUnavailable" },
                    StringComparer.OrdinalIgnoreCase);
                var evaluatedExpected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var matchedExpected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var failedExpected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var record in sample.Records)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    foreach (var rule in rules)
                    {
                        var telemetry = RuleTelemetryValidator.Validate(rule, record);
                        var isExpected = expectedDiagnostics.TryGetValue(rule.Descriptor.RuleId, out var diagnostic);
                        if (isExpected && diagnostic != null)
                        {
                            if (diagnostic.Outcome == "RuleUnavailable") diagnostic.Outcome = "MissingTelemetry";
                            diagnostic.MissingRequiredTelemetry.AddRange(telemetry.MissingRequiredTelemetry);
                        }
                        if (!telemetry.CanRunSafely)
                            continue;

                        var result = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow)).ConfigureAwait(false);
                        if (isExpected && diagnostic != null)
                        {
                            evaluatedExpected.Add(rule.Descriptor.RuleId);
                            if (result.Matched && result.Events.Count > 0)
                                matchedExpected.Add(rule.Descriptor.RuleId);
                            if (result.Failed)
                            {
                                failedExpected.Add(rule.Descriptor.RuleId);
                                diagnostic.NoMatchReasons.Add(result.FailureMessage ?? "Rule evaluation failed.");
                            }
                            diagnostic.NoMatchReasons.AddRange(result.NoMatchReasons.Select(static reason =>
                                $"{reason.Category}/{reason.Code}: {reason.Message}"));
                        }
                        if (!result.Matched || result.Events.Count == 0)
                            continue;

                        foreach (var evt in result.Events)
                        {
                            PrepareReplayEvent(evt, rule.Descriptor, rule.Intelligence, record);
                            matches.Add(new ReplayMatch(rule.Descriptor, record, evt));
                            IncrementConfidenceBucket(confidenceDistribution, evt.ConfidenceScore);
                        }
                    }
                }

                var actualMatchIds = matches.Select(static match => match.Descriptor.RuleId)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                foreach (var diagnostic in expectedDiagnostics.Values)
                {
                    if (matchedExpected.Contains(diagnostic.RuleId)) diagnostic.Outcome = "Matched";
                    else if (evaluatedExpected.Contains(diagnostic.RuleId))
                        diagnostic.Outcome = failedExpected.Contains(diagnostic.RuleId) ? "EvaluationFailed" : "NoMatch";
                    diagnostic.MissingRequiredTelemetry = diagnostic.MissingRequiredTelemetry
                        .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(static value => value, StringComparer.OrdinalIgnoreCase).ToList();
                    diagnostic.NoMatchReasons = diagnostic.NoMatchReasons
                        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                }
                var expectedNonMatchIds = NormalizeRuleIds(sample.ExpectedNonMatches);
                var missingExpected = expectedMatchIds.Where(id => !actualMatchIds.Contains(id, StringComparer.OrdinalIgnoreCase)).ToList();
                var unexpected = expectedNonMatchIds.Where(id => actualMatchIds.Contains(id, StringComparer.OrdinalIgnoreCase)).ToList();
                var maxConfidence = matches.Count == 0 ? 0.0 : matches.Max(static match => match.Event.ConfidenceScore);
                var avgConfidence = matches.Count == 0 ? 0.0 : matches.Average(static match => match.Event.ConfidenceScore);

                var sampleResult = new TuningBenchmarkSampleResult
                {
                    Name = sample.Name,
                    FilePath = file,
                    Classification = classification,
                    ExpectedMatches = expectedMatchIds,
                    ExpectedNonMatches = expectedNonMatchIds,
                    ActualMatches = actualMatchIds,
                    ExpectedRuleDiagnostics = expectedDiagnostics.Values.OrderBy(static item => item.RuleId, StringComparer.OrdinalIgnoreCase).ToList(),
                    MissingExpectedMatches = missingExpected,
                    UnexpectedMatches = unexpected,
                    MaximumConfidence = maxConfidence,
                    AverageConfidence = avgConfidence
                };

                if (classification == ReplaySampleClassification.Benign)
                    report.Summary.BenignSampleCount++;
                else
                    report.Summary.MaliciousSampleCount++;

                if (missingExpected.Count > 0)
                    sampleResult.Errors.AddRange(missingExpected.Select(static id => $"Expected match {id} was not triggered."));
                if (unexpected.Count > 0)
                    sampleResult.Errors.AddRange(unexpected.Select(static id => $"Expected non-match {id} triggered unexpectedly."));
                if (sample.ExpectedMinimumConfidence > 0 && maxConfidence < sample.ExpectedMinimumConfidence)
                    sampleResult.Errors.Add($"Maximum confidence {maxConfidence:F2} was below the expected floor {sample.ExpectedMinimumConfidence:F2}.");

                // Benign fixtures can deliberately exercise a raw rule match while
                // policy correctly keeps it in Shadow. Those matches must not inflate
                // the metric named "true-positive pass rate".
                if (classification == ReplaySampleClassification.Malicious)
                {
                    report.Summary.ExpectedMatchCount += expectedMatchIds.Count;
                    report.Summary.MatchedExpectedCount += expectedMatchIds.Count(
                        id => actualMatchIds.Contains(id, StringComparer.OrdinalIgnoreCase));
                }

                foreach (var ruleId in actualMatchIds)
                {
                    if (!ruleCoverage.TryGetValue(ruleId, out var coverage))
                        continue;

                    var highestConfidence = matches.Where(match => string.Equals(match.Descriptor.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
                        .Select(static match => match.Event.ConfidenceScore)
                        .DefaultIfEmpty(0.0)
                        .Max();

                    if (classification == ReplaySampleClassification.Benign)
                    {
                        coverage.BenignCoverageCount++;
                        coverage.BenignReplayFailures++;
                        noisyRules.Add(ruleId);
                        recommendShadow.Add(ruleId);
                    }
                    else
                    {
                        coverage.ReplayCoverageCount++;
                    }

                    coverage.NoteConfidence(highestConfidence);
                }

                if (classification == ReplaySampleClassification.Malicious)
                {
                    foreach (var expectedRuleId in expectedMatchIds)
                    {
                        if (!actualMatchIds.Contains(expectedRuleId, StringComparer.OrdinalIgnoreCase))
                            ruleCoverage[expectedRuleId].MaliciousReplayFailures++;
                    }
                }

                foreach (var profile in profileAccumulators.Values)
                {
                    var profileSample = new TuningBenchmarkProfileSampleSummary
                    {
                        ProfileName = profile.ProfileName
                    };

                    foreach (var match in matches)
                    {
                        // Mirror live RuleEngine baseline eligibility: a replay
                        // cannot page from a fresh isolated baseline simply because
                        // a broad profile defaults to Alert.
                        var readiness = BaselineStore.Current.Readiness;
                        var decision = RuleTuningCatalog.Resolve(
                            profile.ProfileName,
                            match.Descriptor,
                            match.Event,
                            match.Record,
                            approvedAssets,
                            baselineLearningMode: sample.BaselineLearningMode || BaselineStore.Current.IsLearningMode,
                            effectiveConfidenceScore: match.Event.ConfidenceScore,
                            baselineReady: readiness.IsReady);
                        // Apply the same independent precision checks used by live
                        // capture. Alert is the unconstrained input here because
                        // each replay profile already supplies its own policy mode.
                        var precision = RulePrecisionRuntimeEvaluator.Evaluate(
                            match.Descriptor, match.Event, match.Record, RuleMode.Alert, profile.ProfileName, approvedAssets);
                        var evaluatedMode = RulePrecisionCatalog.MostRestrictive(
                            decision.EffectiveMode, precision.EffectiveMode);

                        var precisionMode = RulePrecisionCatalog.GetProfile(match.Descriptor).DefaultMode;
                        var existingTrace = profileSample.RuleDecisions.FirstOrDefault(item =>
                            string.Equals(item.RuleId, match.Descriptor.RuleId, StringComparison.OrdinalIgnoreCase));
                        if (existingTrace == null || existingTrace.Confidence < match.Event.ConfidenceScore)
                        {
                            if (existingTrace != null)
                                profileSample.RuleDecisions.Remove(existingTrace);
                            profileSample.RuleDecisions.Add(new TuningBenchmarkRuleDecision
                            {
                                RuleId = match.Descriptor.RuleId,
                                Tier = decision.Tier.ToString(),
                                DefaultMode = decision.DefaultMode.ToString(),
                                PrecisionMode = precisionMode.ToString(),
                                EffectiveMode = evaluatedMode.ToString(),
                                Confidence = match.Event.ConfidenceScore,
                                ConfidenceFloor = decision.ConfidenceFloor,
                                Reasons = decision.Reasons.Select(static reason => reason.ToString()).ToList(),
                                ReasonDetails = decision.ReasonDetails.ToList(),
                                RuntimePrecisionReasons = precision.Reasons.ToList()
                            });
                        }

                        switch (evaluatedMode)
                        {
                            case RuleMode.Alert:
                                profileSample.AlertRuleIds.Add(match.Descriptor.RuleId);
                                profile.AlertCount++;
                                profile.AlertRuleIds.Add(match.Descriptor.RuleId);
                                if (match.Event.Severity == SeverityLevel.Critical)
                                    profileSample.CriticalAlertCount++;
                                break;
                            case RuleMode.Shadow:
                                profileSample.ShadowRuleIds.Add(match.Descriptor.RuleId);
                                profile.ShadowCount++;
                                break;
                            default:
                                profileSample.SuppressedRuleIds.Add(match.Descriptor.RuleId);
                                profile.SuppressedCount++;
                                break;
                        }
                    }

                    profileSample.AlertRuleIds = Deduplicate(profileSample.AlertRuleIds);
                    profileSample.ShadowRuleIds = Deduplicate(profileSample.ShadowRuleIds);
                    profileSample.SuppressedRuleIds = Deduplicate(profileSample.SuppressedRuleIds);
                    profileSample.CriticalAlertCount = matches
                        .Where(match => profileSample.AlertRuleIds.Contains(match.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase) && match.Event.Severity == SeverityLevel.Critical)
                        .Select(static match => match.Descriptor.RuleId)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Count();

                    sampleResult.Profiles[profile.ProfileName] = profileSample;

                    if (classification == ReplaySampleClassification.Benign)
                    {
                        profile.BenignAlertCount += profileSample.AlertRuleIds.Count;
                        profile.BenignCriticalAlertCount += profileSample.CriticalAlertCount;
                    }
                    else
                    {
                        profile.MaliciousExpectedMatchCount += expectedMatchIds.Count;
                        profile.MaliciousAlertMatchCount += expectedMatchIds.Count(id => profileSample.AlertRuleIds.Contains(id, StringComparer.OrdinalIgnoreCase));
                    }
                }

                var defaultProfileSample = sampleResult.Profiles[defaultProfileName];
                if (classification == ReplaySampleClassification.Benign)
                {
                    report.Summary.BenignFalsePositiveCount += defaultProfileSample.AlertRuleIds.Count;
                    report.Summary.BenignCriticalAlertCount += defaultProfileSample.CriticalAlertCount;
                    foreach (var ruleId in defaultProfileSample.AlertRuleIds)
                    {
                        ruleCoverage[ruleId].DefaultProfileBenignAlertCount++;
                        noisyRules.Add(ruleId);
                        recommendShadow.Add(ruleId);
                    }
                }
                else
                {
                    foreach (var ruleId in defaultProfileSample.AlertRuleIds)
                        ruleCoverage[ruleId].DefaultProfileMaliciousAlertCount++;

                    foreach (var expectedRuleId in expectedMatchIds)
                    {
                        if (!defaultProfileSample.AlertRuleIds.Contains(expectedRuleId, StringComparer.OrdinalIgnoreCase)
                            && rulesById.TryGetValue(expectedRuleId, out var rule)
                            && matches.Any(match =>
                                string.Equals(match.Descriptor.RuleId, expectedRuleId, StringComparison.OrdinalIgnoreCase)
                                // Advisory recommendations must not bypass a rule-specific
                                // precision floor. A raw Shadow match is not an alert.
                                && match.Event.ConfidenceScore >= Math.Max(
                                    0.75, RulePrecisionCatalog.GetProfile(rule.Descriptor).MinimumConfidence / 100.0)))
                        {
                            recommendAlert.Add(rule.Descriptor.RuleId);
                        }
                    }
                }

                report.SampleResults.Add(sampleResult);
            }

            foreach (var profile in profileAccumulators.Values)
            {
                if (profile.MaliciousExpectedMatchCount > 0)
                {
                    profile.TruePositivePassRate = (double)profile.MaliciousAlertMatchCount / profile.MaliciousExpectedMatchCount;
                }

                report.ProfileResults[profile.ProfileName] = new TuningBenchmarkProfileSummary
                {
                    ProfileName = profile.ProfileName,
                    AlertCount = profile.AlertCount,
                    ShadowCount = profile.ShadowCount,
                    SuppressedCount = profile.SuppressedCount,
                    BenignAlertCount = profile.BenignAlertCount,
                    BenignCriticalAlertCount = profile.BenignCriticalAlertCount,
                    MaliciousExpectedMatchCount = profile.MaliciousExpectedMatchCount,
                    MaliciousAlertMatchCount = profile.MaliciousAlertMatchCount,
                    TruePositivePassRate = profile.TruePositivePassRate,
                    AlertRuleIds = profile.AlertRuleIds.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList()
                };
            }

            report.RuleCoverage = ruleCoverage.Values
                .OrderBy(static coverage => coverage.RuleId, StringComparer.OrdinalIgnoreCase)
                .Select(static coverage => coverage.ToModel())
                .ToList();

            report.Summary.ReplaySampleCount = report.SampleResults.Count;
            report.Summary.SampleLevelQuality = DetectionQualityMetrics.FromReplaySamples(report.SampleResults, defaultProfileName);
            foreach (var profileName in profileAccumulators.Keys)
                report.Summary.SampleLevelQualityByProfile[profileName] =
                    DetectionQualityMetrics.FromReplaySamples(report.SampleResults, profileName);
            report.Summary.TruePositivePassRate = report.Summary.ExpectedMatchCount == 0
                ? 0.0
                : (double)report.Summary.MatchedExpectedCount / report.Summary.ExpectedMatchCount;
            report.Summary.NoisyRules = noisyRules.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            report.Summary.RulesRecommendedForShadow = recommendShadow.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            report.Summary.RulesRecommendedForAlert = recommendAlert.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            report.Summary.RulesWithoutReplayCoverage = report.RuleCoverage
                .Where(static coverage => coverage.ReplayCoverageCount == 0)
                .Select(static coverage => coverage.RuleId)
                .ToList();
            report.Summary.RulesWithoutBenignCoverage = report.RuleCoverage
                .Where(static coverage => coverage.BenignCoverageCount == 0)
                .Select(static coverage => coverage.RuleId)
                .ToList();
            report.Summary.ConfidenceDistribution = confidenceDistribution;

            // Each gap is an expected malicious (sample, rule, profile) with
            // no alert; Shadow matches are not counted as alert true positives.
            report.RecallGaps = TuningBenchmarkRecallGapAnalyzer.Analyze(report);
            report.DetectionFunnelByProfile = TuningBenchmarkDetectionFunnelAnalyzer.Analyze(report);
            report.RuleEvidenceCoverage = TuningBenchmarkRuleEvidenceAnalyzer.Analyze(report);
            report.RuleHardeningAudit = TuningBenchmarkRuleHardeningAudit.Analyze(report);
            RuleEngine.ResetRuntimeStateForReplay();
            return report;
        }

        private static async Task<RuleReplaySample> LoadSampleAsync(string filePath, CancellationToken cancellationToken)
        {
            await using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var sample = await JsonSerializer.DeserializeAsync<RuleReplaySample>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
            if (sample == null)
                throw new InvalidOperationException($"Could not deserialize replay sample at {filePath}.");

            if (string.IsNullOrWhiteSpace(sample.Name))
                sample.Name = Path.GetFileNameWithoutExtension(filePath);

            // Replay fixtures cannot assign the internal capture-trust flag
            // HttpBasicDefaultCredentialObserved through JSON. It must come
            // from the actual HTTP parser, just as it does in live capture.
            // Raw requests are synthetic local test inputs only; overwrite
            // headers with redacted parser output before any rule evaluates.
            foreach (var (recordIndex, request) in sample.RawHttpRequestsByRecordIndex)
            {
                if (recordIndex < 0 || recordIndex >= sample.Records.Count
                    || string.IsNullOrWhiteSpace(request) || request.Length > 16_384
                    || request.Any(static c => c > 127))
                    throw new InvalidDataException(
                        $"Replay '{sample.Name}' has an invalid synthetic HTTP request at record {recordIndex}.");

                if (!HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed)
                    || string.IsNullOrWhiteSpace(parsed.Method)
                    || string.IsNullOrWhiteSpace(parsed.Host)
                    || string.IsNullOrWhiteSpace(parsed.Path))
                    throw new InvalidDataException(
                        $"Replay '{sample.Name}' contains an incomplete or invalid HTTP request at record {recordIndex}.");

                var record = sample.Records[recordIndex];
                if (!string.Equals(record.HttpMethod, parsed.Method, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(record.HttpHost, parsed.Host, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(record.HttpUri, parsed.Path, StringComparison.Ordinal))
                    throw new InvalidDataException(
                        $"Replay '{sample.Name}' HTTP parser disagrees with the declared method/host/path at record {recordIndex}.");

                record.HttpRequestHeaders = parsed.JoinedHeaderLines;
                record.HttpUserAgent = parsed.UserAgent ?? record.HttpUserAgent;
                record.HttpBasicDefaultCredentialObserved = parsed.ObservedDefaultBasicCredential;
            }

            foreach (var (index, hex) in sample.RawOtTcpPayloadsByRecordIndex)
            {
                if (index < 0 || index >= sample.Records.Count || string.IsNullOrEmpty(hex)
                    || hex.Length < 16 || hex.Length > 1024 || (hex.Length % 2) != 0
                    || hex.Any(static ch => !Uri.IsHexDigit(ch)))
                    throw new InvalidDataException("Invalid OT replay payload at index " + index);
                var record = sample.Records[index];
                if (!record.IsTcp || record.IsUdp || record.IsQuic || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                    || record.SourcePort is null || record.DestinationPort is null
                    || record.HttpMethod != null || record.HttpUri != null || record.TlsVersion != null
                    || sample.RawHttpRequestsByRecordIndex.ContainsKey(index))
                    throw new InvalidDataException("Contradictory OT replay metadata at index " + index);
                if (!OtProtocolLight.TryIdentifyTcp(Convert.FromHexString(hex), record.SourcePort,
                        record.DestinationPort, out var parsed))
                    throw new InvalidDataException("OT parser rejected replay payload at index " + index);
                if (record.ApplicationProtocol != null &&
                    !string.Equals(record.ApplicationProtocol, parsed, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("OT replay protocol conflict at index " + index);
                record.ApplicationProtocol = parsed;
            }
            return sample;
        }

        private static IEnumerable<string> EnumerateSampleFiles(string replayDirectory)
        {
            if (!Directory.Exists(replayDirectory))
                return Array.Empty<string>();

            return Directory.EnumerateFiles(replayDirectory, "*.json", SearchOption.AllDirectories)
                .OrderBy(static path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static ReplaySampleClassification InferClassification(string filePath)
            => filePath.Contains($"{Path.DirectorySeparatorChar}benign{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
                ? ReplaySampleClassification.Benign
                : ReplaySampleClassification.Malicious;

        private static void PrepareReplayEvent(DetectionEvent evt, RuleDescriptor descriptor, RuleIntelligence intelligence, TrafficRecord record)
        {
            evt.RuleId = string.IsNullOrWhiteSpace(evt.RuleId) ? descriptor.RuleId : evt.RuleId;
            evt.RuleName = string.IsNullOrWhiteSpace(evt.RuleName) ? descriptor.Name : evt.RuleName;
            evt.TimestampUtc = evt.TimestampUtc == default ? DateTime.UtcNow : evt.TimestampUtc;
            evt.SourceIp ??= record.Source;
            evt.DestinationIp ??= record.Destination;
            evt.DestinationPort ??= record.DestinationPort;
            evt.Protocol ??= record.Protocol;
            evt.Summary = string.IsNullOrWhiteSpace(evt.Summary) ? descriptor.Description : evt.Summary;
            evt.RuleMaturityAtDetection ??= intelligence.Maturity.ToString();
            evt.RuleRevisionAtDetection = evt.RuleRevisionAtDetection <= 0 ? intelligence.Revision : evt.RuleRevisionAtDetection;
            EvidenceBuilder.EnsureStructuredEvidence(evt);
            if (evt.ConfidenceScore <= 0)
                ConfidenceBuilder.ApplyDefault(evt, descriptor, intelligence);
        }

        private static List<string> NormalizeRuleIds(IEnumerable<string>? values)
            => values?
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim().ToUpperInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                .ToList()
               ?? new List<string>();

        private static List<string> Deduplicate(IEnumerable<string> values)
            => values.Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                .ToList();

        private static Dictionary<string, int> CreateConfidenceBuckets()
            => new(StringComparer.OrdinalIgnoreCase)
            {
                ["0.00-0.24"] = 0,
                ["0.25-0.49"] = 0,
                ["0.50-0.74"] = 0,
                ["0.75-1.00"] = 0
            };

        private static void IncrementConfidenceBucket(IDictionary<string, int> buckets, double confidence)
        {
            var key = confidence switch
            {
                < 0.25 => "0.00-0.24",
                < 0.50 => "0.25-0.49",
                < 0.75 => "0.50-0.74",
                _ => "0.75-1.00"
            };

            buckets[key] = buckets.TryGetValue(key, out var current) ? current + 1 : 1;
        }

        private sealed record ReplayMatch(RuleDescriptor Descriptor, TrafficRecord Record, DetectionEvent Event);

        private sealed class ProfileAccumulator
        {
            public ProfileAccumulator(string profileName) => ProfileName = profileName;
            public string ProfileName { get; }
            public int AlertCount { get; set; }
            public int ShadowCount { get; set; }
            public int SuppressedCount { get; set; }
            public int BenignAlertCount { get; set; }
            public int BenignCriticalAlertCount { get; set; }
            public int MaliciousExpectedMatchCount { get; set; }
            public int MaliciousAlertMatchCount { get; set; }
            public double TruePositivePassRate { get; set; }
            public HashSet<string> AlertRuleIds { get; } = new(StringComparer.OrdinalIgnoreCase);
        }

        private sealed class CoverageAccumulator
        {
            private double _confidenceSum;
            private int _confidenceCount;

            public CoverageAccumulator(string ruleId) => RuleId = ruleId;
            public string RuleId { get; }
            public int ReplayCoverageCount { get; set; }
            public int BenignCoverageCount { get; set; }
            public int BenignReplayFailures { get; set; }
            public int MaliciousReplayFailures { get; set; }
            public int DefaultProfileBenignAlertCount { get; set; }
            public int DefaultProfileMaliciousAlertCount { get; set; }

            public void NoteConfidence(double confidence)
            {
                if (confidence <= 0)
                    return;

                _confidenceSum += confidence;
                _confidenceCount++;
            }

            public TuningBenchmarkRuleCoverage ToModel() => new()
            {
                RuleId = RuleId,
                ReplayCoverageCount = ReplayCoverageCount,
                BenignCoverageCount = BenignCoverageCount,
                BenignReplayFailures = BenignReplayFailures,
                MaliciousReplayFailures = MaliciousReplayFailures,
                DefaultProfileBenignAlertCount = DefaultProfileBenignAlertCount,
                DefaultProfileMaliciousAlertCount = DefaultProfileMaliciousAlertCount,
                AverageConfidence = _confidenceCount <= 0 ? 0.0 : _confidenceSum / _confidenceCount
            };
        }
    }
}
