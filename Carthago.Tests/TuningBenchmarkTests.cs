using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests
{
    public sealed class TuningBenchmarkTests
    {
        [Fact]
        public async Task Benchmark_Runs_Without_External_Services_And_Writes_Report()
        {
            var tempOutput = CreateTempDirectory();
            var runner = new TuningBenchmarkRunner();
            var store = new TuningBenchmarkReportStore();

            var report = await runner.RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory(),
                OutputDirectory = tempOutput
            });

            await store.SaveAsync(report, tempOutput);

            Assert.NotNull(report);
            Assert.True(report.SampleResults.Count >= 16);
            var quality = Assert.IsType<DetectionQualityMetrics>(report.Summary.SampleLevelQuality);
            Assert.Equal(report.SampleResults.Count(sample =>
                    sample.Classification != ReplaySampleClassification.UnsupportedMalicious),
                quality.TruePositives + quality.FalsePositives + quality.FalseNegatives + quality.TrueNegatives);
            Assert.Equal(6, report.Summary.UnsupportedMaliciousSampleCount);
            Assert.Equal(6, report.Summary.UnsupportedRuleCount);
            Assert.True(File.Exists(store.GetJsonPath(tempOutput)));
            Assert.True(File.Exists(store.GetMarkdownPath(tempOutput)));
            Assert.True(File.Exists(store.GetHardeningAuditPath(tempOutput)));
            Assert.Equal(Carthago.Engine.Rules.Catalog.RuleCatalog.All.Count, report.RuleHardeningAudit.Count);
            Assert.Equal(0, report.RuleHardeningAudit.Count(entry => entry.ContractIssues.Count > 0));
            var auditMarkdown = await File.ReadAllTextAsync(store.GetHardeningAuditPath(tempOutput));
            Assert.Contains($"Registered rules reviewed: {Carthago.Engine.Rules.Catalog.RuleCatalog.All.Count}", auditMarkdown);
            Assert.Contains("## All registered rules", auditMarkdown);
            var markdown = await File.ReadAllTextAsync(store.GetMarkdownPath(tempOutput));
            Assert.Contains("Precision:", markdown);
            Assert.Contains("Recall:", markdown);
            Assert.Contains("F1:", markdown);
            Assert.Contains("## Alert-Level Recall Gaps", markdown);
            Assert.Contains("## Explicit Rule Evidence Coverage", markdown);
            Assert.Contains("## Unsupported Trusted-Producer Coverage", markdown);
            var loaded = await store.LoadAsync(tempOutput);
            Assert.NotNull(loaded);
            Assert.Equal(report.RuleEvidenceCoverage.Count, loaded!.RuleEvidenceCoverage.Count);
            Assert.Equal(report.RuleHardeningAudit.Count, loaded.RuleHardeningAudit.Count);
            Assert.Equal(report.SampleResults.Sum(sample => sample.ExpectedNonMatches.Count),
                loaded.SampleResults.Sum(sample => sample.ExpectedNonMatches.Count));
            var expectedAlertGaps = report.SampleResults
                .Where(sample => sample.Classification == ReplaySampleClassification.Malicious)
                .Sum(sample => sample.Profiles.Values.Sum(profile =>
                    sample.ExpectedMatches.Count(ruleId =>
                        !profile.AlertRuleIds.Contains(ruleId, StringComparer.OrdinalIgnoreCase))));
            Assert.Equal(expectedAlertGaps, report.RecallGaps.Count);
            Assert.All(report.RecallGaps, gap =>
                Assert.False(string.IsNullOrWhiteSpace(gap.Cause)));
        }

        [Fact]
        public async Task Benchmark_Rule_Evidence_Coverage_Reconciles_With_Labeled_Replays()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });
            var coverage = report.RuleEvidenceCoverage;

            Assert.True(coverage.Count >= report.RuleCoverage.Count);
            Assert.All(report.RuleCoverage, rule =>
                Assert.Contains(coverage, entry => string.Equals(
                    entry.RuleId, rule.RuleId, StringComparison.OrdinalIgnoreCase)));
            Assert.Equal(report.Summary.ExpectedMatchCount, coverage.Sum(rule => rule.PositiveCases));
            Assert.Equal(report.Summary.MatchedExpectedCount, coverage.Sum(rule => rule.PositiveRecognized));
            // Reconcile every current miss with the report; do not silently
            // treat obsolete replay expectations as successful detections.
            Assert.Equal(report.Summary.ExpectedMatchCount - report.Summary.MatchedExpectedCount,
                coverage.Sum(rule => rule.PositiveMissed));
            Assert.Equal(report.SampleResults.Sum(sample => sample.ExpectedNonMatches.Count),
                coverage.Sum(rule => rule.ExplicitNegativeCases));
            Assert.Equal(report.SampleResults.Sum(sample => sample.UnexpectedMatches.Count),
                coverage.Sum(rule => rule.ExplicitNegativeFailed));
            Assert.Equal(report.SampleResults
                    .Where(sample => sample.Classification == ReplaySampleClassification.Benign)
                    .Sum(sample => sample.ActualMatches.Count),
                coverage.Sum(rule => rule.BenignRawMatches));

            // The existence of a matched rule alone never creates a labeled
            // negative control; specifically check R118/R163 metadata.
            foreach (var ruleId in new[] { "R102", "R118", "R163" })
            {
                var entry = Assert.Single(coverage, rule => rule.RuleId == ruleId);
                Assert.True(entry.PositiveCases > 0);
            }
        }

        [Fact]
        public async Task Benchmark_Replays_Never_Clear_The_Active_Baseline_Journal()
        {
            var root = CreateTempDirectory();
            var activeDirectory = Path.Combine(root, "active-baseline");
            var active = new BaselineStore(new BaselineOptions { DirectoryPath = activeDirectory });
            await active.ObserveAsync(new BaselineObservation(
                "dns.domain", "10.200.1.40", "production.example.test",
                DateTime.UtcNow.AddMinutes(-1), "existing live observation"));

            var journalPath = Path.Combine(activeDirectory, "baseline-journal.jsonl");
            var originalJournal = await File.ReadAllTextAsync(journalPath);

            var replayDirectory = Path.Combine(root, "replay");
            Directory.CreateDirectory(replayDirectory);
            File.Copy(Path.Combine(GetReplayDirectory(), "benign", "normal-dns-cdn.json"),
                Path.Combine(replayDirectory, "normal-dns-cdn.json"));

            // Emulate a caller with an active baseline in the same async flow.
            // Nested replay scope must supersede it and restore it afterward.
            using (BaselineStore.UseScoped(active))
            {
                var report = await new TuningBenchmarkRunner().RunAsync(
                    new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });
                Assert.Single(report.SampleResults);
                Assert.Same(active, BaselineStore.Current);
            }

            Assert.Equal(originalJournal, await File.ReadAllTextAsync(journalPath));
        }

        [Fact]
        public async Task Benign_Samples_Do_Not_Generate_Critical_Alert_Spam()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            var benignCritical = report.SampleResults
                .Where(sample => sample.Classification == ReplaySampleClassification.Benign)
                .Select(sample => new { sample.Name, Profile = sample.Profiles["SmallBusiness"] })
                .Where(item => item.Profile.CriticalAlertCount > 0)
                .Select(item => $"{item.Name} (critical={item.Profile.CriticalAlertCount}, alert-rules={string.Join(",", item.Profile.AlertRuleIds)})")
                .ToArray();
            Assert.True(report.Summary.BenignCriticalAlertCount <= 1,
                $"Expected benign critical alert spam to stay near zero, but saw {report.Summary.BenignCriticalAlertCount}. " +
                $"Affected labeled samples: {string.Join("; ", benignCritical)}.");
            Assert.True(report.ProfileResults["HomeLab"].BenignCriticalAlertCount <= report.ProfileResults["Research"].BenignCriticalAlertCount);
        }

        [Fact]
        public async Task R163_Paired_Metadata_Replays_Distinguish_Recognition_From_Alert_Eligibility()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            var authorized = report.SampleResults.Single(sample => sample.Name == "r163-paired-authorized-agent");
            var suspicious = report.SampleResults.Single(sample => sample.Name == "r163-paired-suspicious-direct-probe");
            var candidate = report.SampleResults.Single(sample => sample.Name == "r163-paired-correlated-ssrf-candidate");

            Assert.Equal(ReplaySampleClassification.Benign, authorized.Classification);
            Assert.DoesNotContain("R163", authorized.ActualMatches);

            foreach (var sample in new[] { suspicious, candidate })
            {
                Assert.Equal(ReplaySampleClassification.Malicious, sample.Classification);
                Assert.Contains("R163", sample.ActualMatches);
                Assert.Contains(sample.ExpectedRuleDiagnostics,
                    diagnostic => diagnostic.RuleId == "R163" && diagnostic.Outcome == "Matched");

                foreach (var profile in sample.Profiles.Values)
                {
                    var decision = Assert.Single(profile.RuleDecisions,
                        item => item.RuleId == "R163");
                    // An inbound fetch and subsequent metadata request are not,
                    // by themselves, a verified causal trace. Do not automatically
                    // promote either fixture to an alert or lower the 84% floor.
                    Assert.Equal("Shadow", decision.EffectiveMode);
                    Assert.True(decision.Confidence < 0.84,
                        $"{sample.Name} [{profile.ProfileName}] confidence {decision.Confidence} unexpectedly reached the 84% floor.");
                    Assert.DoesNotContain("R163", profile.AlertRuleIds);
                }
            }
        }

        [Fact]
        public async Task Benign_Replays_Have_No_Critical_Alerts_In_Any_Profile()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            var violations = report.SampleResults
                .Where(sample => sample.Classification == ReplaySampleClassification.Benign)
                .SelectMany(sample => sample.Profiles
                    .Where(profile => profile.Value.CriticalAlertCount > 0)
                    .Select(profile => $"{sample.Name} [{profile.Key}]: critical={profile.Value.CriticalAlertCount}, alerted={string.Join(",", profile.Value.AlertRuleIds)}"))
                .ToArray();

            Assert.True(violations.Length == 0,
                "Benign replay produced critical alerts: " + string.Join("; ", violations));

            // The current curated benign replay suite has zero alert-level
            // false positives across all profiles. Preserve that baseline as
            // recall tuning evolves; a Shadow match is not counted as an alert.
            var benignAlerts = report.SampleResults
                .Where(sample => sample.Classification == ReplaySampleClassification.Benign)
                .SelectMany(sample => sample.Profiles.SelectMany(profile =>
                    profile.Value.AlertRuleIds.Select(ruleId =>
                        $"{sample.Name} [{profile.Key}]: {ruleId}")))
                .ToArray();
            Assert.Empty(benignAlerts);
        }

        [Fact]
        public async Task Malicious_Samples_Trigger_Expected_HighConfidence_Rules_And_Profiles_Differ()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            var dnsTunnel = report.SampleResults.Single(sample => sample.Name == "dns-tunnel-high-confidence");
            var oauth = report.SampleResults.Single(sample => sample.Name == "oauth-device-code-phishing");
            var modbus = report.SampleResults.Single(sample => sample.Name == "modbus-write-function");

            Assert.Contains("R102", dnsTunnel.ActualMatches);
            Assert.True(dnsTunnel.MaximumConfidence >= 0.75, $"Expected high confidence for dns-tunnel-high-confidence, got {dnsTunnel.MaximumConfidence:F2}.");
            // A device-code initiation alone does not establish phishing and
            // the required trusted IdP producer is not connected. Keep the
            // coverage gap explicit without counting it as supported recall.
            Assert.Equal(ReplaySampleClassification.UnsupportedMalicious, oauth.Classification);
            Assert.DoesNotContain("R275", oauth.ActualMatches);
            Assert.Contains("R275", oauth.UnsupportedRuleIds);
            Assert.Empty(oauth.MissingExpectedMatches);
            Assert.Equal("TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE",
                oauth.UnsupportedReasonCodesByRuleId["R275"]);
            Assert.True(report.ProfileResults["Enterprise"].AlertCount >= report.ProfileResults["HomeLab"].AlertCount);
            // MBAP/PDU bytes are now decoded by the same OT parser used by
            // capture. Raw R240 recognition must succeed; environment profile
            // authorization and confidence still control alert eligibility.
            Assert.Contains("R240", modbus.ActualMatches);
            Assert.DoesNotContain("R240", modbus.MissingExpectedMatches);
            Assert.True(modbus.MaximumConfidence >= 0.65);
            Assert.DoesNotContain("R240", modbus.Profiles["HomeLab"].AlertRuleIds);
        }

        [Fact]
        public async Task Unsupported_Producer_Gaps_Are_Separated_From_Supported_Detector_Recall()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            var unsupported = report.SampleResults
                .Where(sample => sample.Classification == ReplaySampleClassification.UnsupportedMalicious)
                .ToArray();
            Assert.Equal(6, unsupported.Length);
            Assert.Equal(new[] { "R275", "R295", "R343", "R437", "R508", "R516" },
                unsupported.SelectMany(sample => sample.UnsupportedRuleIds)
                    .OrderBy(id => id, StringComparer.OrdinalIgnoreCase).ToArray());
            Assert.All(unsupported, sample =>
            {
                Assert.Empty(sample.ExpectedMatches);
                Assert.Empty(sample.MissingExpectedMatches);
                Assert.Empty(sample.Errors);
                Assert.All(sample.UnsupportedRuleIds, ruleId =>
                    Assert.DoesNotContain(sample.ActualMatches,
                        actual => string.Equals(actual, ruleId, StringComparison.OrdinalIgnoreCase)));
            });

            var jenkins = report.SampleResults.Single(sample => sample.Name == "devops-jenkins-crumb");
            var bacnet = report.SampleResults.Single(sample => sample.Name == "bacnet-write-property");
            Assert.Equal(ReplaySampleClassification.Malicious, jenkins.Classification);
            Assert.Equal(ReplaySampleClassification.Malicious, bacnet.Classification);
            Assert.Contains("R356", jenkins.ActualMatches);
            Assert.Contains("R485", bacnet.ActualMatches);
            Assert.Empty(jenkins.MissingExpectedMatches);
            Assert.Empty(bacnet.MissingExpectedMatches);
        }

        [Fact]
        public async Task Benchmark_Report_Lists_Tuning_Gaps()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            Assert.NotEmpty(report.Summary.RulesWithoutReplayCoverage);
            Assert.NotEmpty(report.Summary.RulesWithoutBenignCoverage);
            Assert.NotEmpty(report.Summary.ConfidenceDistribution);
        }

        [Fact]
        public async Task Benchmark_Compares_Alert_Quality_For_Every_Profile()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            Assert.Equal(report.ProfileResults.Keys.OrderBy(name => name),
                report.Summary.SampleLevelQualityByProfile.Keys.OrderBy(name => name));
            var scoredSampleCount = report.SampleResults.Count(sample =>
                sample.Classification != ReplaySampleClassification.UnsupportedMalicious);
            foreach (var quality in report.Summary.SampleLevelQualityByProfile.Values)
            {
                Assert.Equal(scoredSampleCount,
                    quality.TruePositives + quality.FalsePositives + quality.FalseNegatives + quality.TrueNegatives);
            }
            Assert.Equal(report.Summary.SampleLevelQuality,
                report.Summary.SampleLevelQualityByProfile["SmallBusiness"]);
        }

        [Fact]
        public async Task Benchmark_Separates_Cold_And_Calibrated_Deployment_States()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            var cold = report.DeploymentStates[TuningBenchmarkDeploymentStates.ColdUnconfigured];
            var calibrated = report.DeploymentStates[TuningBenchmarkDeploymentStates.CalibratedConfigured];

            Assert.False(cold.SimulatedBaselineReady);
            Assert.True(cold.SimulatedBaselineLearningMode);
            Assert.True(calibrated.SimulatedBaselineReady);
            Assert.False(calibrated.SimulatedBaselineLearningMode);
            Assert.Equal("None", cold.EnvironmentConfigurationSource);
            Assert.Equal("Fixture-declared EnvironmentTuning", calibrated.EnvironmentConfigurationSource);
            Assert.Equal(report.ProfileResults.Keys.OrderBy(static name => name),
                cold.ProfileResults.Keys.OrderBy(static name => name));

            var scoredSampleCount = report.SampleResults.Count(sample =>
                sample.Classification != ReplaySampleClassification.UnsupportedMalicious);
            foreach (var profileName in cold.ProfileResults.Keys)
            {
                var coldFunnel = cold.DetectionFunnelByProfile[profileName];
                var calibratedFunnel = calibrated.DetectionFunnelByProfile[profileName];
                Assert.Equal(report.Summary.ExpectedMatchCount, coldFunnel.ExpectedMaliciousRules);
                Assert.Equal(report.Summary.ExpectedMatchCount, calibratedFunnel.ExpectedMaliciousRules);
                Assert.Equal(1.0, coldFunnel.DetectorRecognitionRate);
                Assert.Equal(1.0, calibratedFunnel.DetectorRecognitionRate);

                var coldQuality = cold.SampleLevelQualityByProfile[profileName];
                var calibratedQuality = calibrated.SampleLevelQualityByProfile[profileName];
                Assert.NotNull(coldQuality.Recall);
                Assert.NotNull(calibratedQuality.Recall);
                Assert.Equal(scoredSampleCount, coldQuality.TruePositives + coldQuality.FalsePositives
                    + coldQuality.FalseNegatives + coldQuality.TrueNegatives);
                Assert.Equal(scoredSampleCount, calibratedQuality.TruePositives + calibratedQuality.FalsePositives
                    + calibratedQuality.FalseNegatives + calibratedQuality.TrueNegatives);
            }

            // Baseline readiness alone should release the high-confidence R102
            // replay while preserving the authored 80% precision floor.
            var dns = report.SampleResults.Single(sample =>
                sample.Name == "r102-distinct-txt-burst-candidate");
            Assert.DoesNotContain("R102",
                TuningBenchmarkDeploymentStates.ProfilesFor(
                    dns, TuningBenchmarkDeploymentStates.ColdUnconfigured)["SmallBusiness"].AlertRuleIds);
            Assert.Contains("R102",
                TuningBenchmarkDeploymentStates.ProfilesFor(
                    dns, TuningBenchmarkDeploymentStates.CalibratedConfigured)["SmallBusiness"].AlertRuleIds);

            // R356 has fixture-declared CI/CD inventory. Calibrated Research
            // should no longer be blocked by a false "unconfigured" precision gate.
            var jenkins = report.SampleResults.Single(sample => sample.Name == "devops-jenkins-crumb");
            var calibratedResearch = TuningBenchmarkDeploymentStates.ProfilesFor(
                jenkins, TuningBenchmarkDeploymentStates.CalibratedConfigured)["Research"];
            var trace = Assert.Single(calibratedResearch.RuleDecisions, decision => decision.RuleId == "R356");
            Assert.DoesNotContain(trace.RuntimePrecisionReasons,
                reason => reason.Contains("environment-scoped rule lacks", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task Benchmark_Detection_Funnel_Accounts_For_Every_Expected_Malicious_Rule()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            Assert.Equal(report.ProfileResults.Keys.OrderBy(name => name),
                report.DetectionFunnelByProfile.Keys.OrderBy(name => name));

            foreach (var profile in report.ProfileResults.Keys)
            {
                var funnel = report.DetectionFunnelByProfile[profile];
                var accumulated = report.ProfileResults[profile];
                Assert.Equal(report.Summary.ExpectedMatchCount, funnel.ExpectedMaliciousRules);
                Assert.Equal(report.Summary.MatchedExpectedCount, funnel.RecognizedByDetector);
                Assert.Equal(funnel.ExpectedMaliciousRules,
                    funnel.RecognizedByDetector + funnel.DetectorMisses);
                Assert.Equal(accumulated.MaliciousExpectedMatchCount, funnel.ExpectedMaliciousRules);
                Assert.Equal(accumulated.MaliciousAlertMatchCount, funnel.SimulatedAlerted);
                Assert.Equal(accumulated.BenignAlertCount, funnel.BenignSimulatedAlerts);

                // Every detector-recognized, expected malicious rule must
                // have exactly one accounting outcome in the replay.
                Assert.Equal(funnel.RecognizedByDetector,
                    funnel.SimulatedAlerted + funnel.PolicyShadowed +
                    funnel.PolicyDisabled + funnel.MissingPolicyDecisions +
                    funnel.EligibleButNotAlerted);
                Assert.Equal(0, funnel.MissingPolicyDecisions);
                Assert.Equal(0, funnel.EligibleButNotAlerted);
                Assert.Equal(0, funnel.AlertDecisionMismatches);
                Assert.Equal(0, funnel.BenignSimulatedAlerts);
            }

            var dns = report.SampleResults.Single(sample => sample.Name == "r102-distinct-txt-burst-candidate");
            var research = report.DetectionFunnelByProfile["Research"];
            Assert.Contains("R102", dns.ActualMatches);
            Assert.DoesNotContain("R102", dns.Profiles["Research"].AlertRuleIds);
            Assert.True(research.RecognizedByDetector > research.SimulatedAlerted,
                "A correctly shadowed raw detection must not count as an emitted alert.");
        }

        [Fact]
        public async Task Benchmark_Explains_Shadowed_Expected_Rules_Without_Changing_Their_Mode()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            var dns = report.SampleResults.Single(sample => sample.Name == "dns-tunnel-high-confidence");
            var decision = Assert.Single(dns.Profiles["SmallBusiness"].RuleDecisions,
                item => item.RuleId == "R102");

            Assert.Equal("Shadow", decision.EffectiveMode);
            Assert.Equal("BaselineRequired", decision.Tier);
            Assert.Contains("R102", dns.Profiles["SmallBusiness"].ShadowRuleIds);
            Assert.NotEmpty(decision.Reasons);
            Assert.InRange(decision.Confidence, 0, 1);
            Assert.NotEmpty(decision.RuntimePrecisionReasons);
        }

        [Fact]
        public async Task Benchmark_Explains_Why_Expected_Rules_Did_Not_Match()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            var powerShell = report.SampleResults.Single(sample => sample.Name == "ad-psremoting-encoded-command");
            var diagnostic = Assert.Single(powerShell.ExpectedRuleDiagnostics);
            Assert.Equal("R343", diagnostic.RuleId);
            Assert.Equal("NoMatch", diagnostic.Outcome);
            Assert.Contains(diagnostic.NoMatchReasons,
                reason => reason.Contains("WINRM_COMMAND_AUDIT_UNAVAILABLE", StringComparison.Ordinal));

            var oauth = report.SampleResults.Single(sample => sample.Name == "oauth-device-code-phishing");
            Assert.Contains(oauth.ExpectedRuleDiagnostics,
                item => item.RuleId == "R275"
                    && (item.Outcome is "NoMatch" or "MissingTelemetry")
                    && (item.MissingRequiredTelemetry.Count > 0 || item.NoMatchReasons.Any(reason =>
                        reason.Contains("TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE", StringComparison.Ordinal))));
        }

        [Fact]
        public async Task Incomplete_PowerShell_Replay_Reports_Missing_Telemetry()
        {
            var folder = CreateTempDirectory();
            var json = """
                {"name":"missing-process","records":[{"source":"10.0.0.70","destination":"10.0.0.20","protocol":"TCP","destinationPort":5985,"info":"WinRM Invoke-Command -EncodedCommand SQBFAFgA"}],"expectedMatches":["R343"]}
                """;
            await File.WriteAllTextAsync(Path.Combine(folder, "missing-process.json"), json);

            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions { ReplayDirectory = folder });
            var sample = Assert.Single(report.SampleResults);
            var diagnostic = Assert.Single(sample.ExpectedRuleDiagnostics);
            Assert.Equal("R343", diagnostic.RuleId);
            Assert.Equal("MissingTelemetry", diagnostic.Outcome);
            Assert.Contains("precision.Process", diagnostic.MissingRequiredTelemetry);
        }

        [Fact]
        public async Task Evidence_Rich_Replays_Match_Their_Specific_Rules()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            // Supported malicious replays must be recognized by their intended
            // detector. R356 and R485 are parser-backed here; no free-text
            // operation claim is allowed to substitute for parser provenance.
            foreach (var name in new[]
            {
                "modbus-write-function",
                "ssrf-imds",
                "devops-jenkins-crumb",
                "bacnet-write-property"
            })
            {
                var sample = report.SampleResults.Single(item => item.Name == name);
                Assert.Equal(ReplaySampleClassification.Malicious, sample.Classification);
                Assert.True(sample.ExpectedMatches.All(rule => sample.ActualMatches.Contains(rule)),
                    $"{name}: missing {string.Join(", ", sample.MissingExpectedMatches)}; " +
                    string.Join("; ", sample.ExpectedRuleDiagnostics.Select(item =>
                        $"{item.RuleId}={item.Outcome} ({string.Join(", ", item.MissingRequiredTelemetry)}; {string.Join(", ", item.NoMatchReasons)})")));
            }

            // Producer-limited malicious replays are explicit architecture
            // coverage gaps. They must fail closed with the stable reason code,
            // and must not be counted as supported detector false negatives.
            foreach (var unavailable in new[] {
                (Sample: "oauth-device-code-phishing", Rule: "R275", Reason: "TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE"),
                (Sample: "kubernetes-pod-exec", Rule: "R295", Reason: "K8S_POD_EXEC_AUDIT_UNAVAILABLE"),
                (Sample: "ad-psremoting-encoded-command", Rule: "R343", Reason: "WINRM_COMMAND_AUDIT_UNAVAILABLE"),
                (Sample: "redis-config-set", Rule: "R437", Reason: "REDIS_RESP_CONFIG_SET_UNAVAILABLE"),
                (Sample: "rclone-exfil", Rule: "R508", Reason: "RCLONE_PROCESS_USERAGENT_AND_EGRESS_PROVENANCE_UNAVAILABLE"),
                (Sample: "cloudflared-tunnel", Rule: "R516", Reason: "CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE")
            })
            {
                var sample = report.SampleResults.Single(item => item.Name == unavailable.Sample);
                Assert.Equal(ReplaySampleClassification.UnsupportedMalicious, sample.Classification);
                Assert.Empty(sample.ExpectedMatches);
                Assert.Empty(sample.MissingExpectedMatches);
                Assert.Contains(unavailable.Rule, sample.UnsupportedRuleIds);
                Assert.DoesNotContain(unavailable.Rule, sample.ActualMatches);
                Assert.Equal(unavailable.Reason, sample.UnsupportedReasonCodesByRuleId[unavailable.Rule]);
                Assert.Contains(sample.ExpectedRuleDiagnostics,
                    diagnostic => diagnostic.RuleId == unavailable.Rule
                        && diagnostic.Outcome != "Matched"
                        && diagnostic.NoMatchReasons.Any(reason =>
                            reason.Contains(unavailable.Reason, StringComparison.Ordinal)));
            }
        }

        [Fact]
        public async Task True_Positive_Pass_Rate_Only_Counts_Malicious_Expected_Matches()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            var malicious = report.SampleResults
                .Where(sample => sample.Classification == ReplaySampleClassification.Malicious)
                .ToArray();
            Assert.Equal(malicious.Sum(sample => sample.ExpectedMatches.Count),
                report.Summary.ExpectedMatchCount);
            Assert.Equal(malicious.Sum(sample => sample.ExpectedMatches.Count(
                    id => sample.ActualMatches.Contains(id, StringComparer.OrdinalIgnoreCase))),
                report.Summary.MatchedExpectedCount);
        }

        private static string GetReplayDirectory()
            => Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");

        private static string CreateTempDirectory()
        {
            var path = Path.Combine(Path.GetTempPath(), "carthago-benchmark-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return path;
        }
    }
}
