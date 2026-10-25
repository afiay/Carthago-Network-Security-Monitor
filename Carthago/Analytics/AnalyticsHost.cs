// SPDX-License-Identifier: MIT
// File: Analytics/AnalyticsHost.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Carthago.Analytics.Models;
using Carthago.Analytics.Services;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Analytics
{
    public sealed class AnalyticsHost : IDisposable
    {
        private readonly LocalStore _store;
        private readonly IncidentFeedbackStore _feedbackStore;
        private readonly FeatureExtractor _featureExtractor;
        private readonly BaselineEngine _baselineEngine;
        private readonly MlFeatureWindowBuilder _mlWindowBuilder;
        private readonly MlAnomalyScoringEngine _mlAnomalyScoringEngine;
        private readonly IncidentTimelineBuilder _timelineBuilder;
        private readonly IncidentCorrelationEngine _correlationEngine;
        private readonly RiskScoringEngine _riskScoringEngine;
        private readonly RecommendedActionEngine _recommendedActionEngine;
        private readonly LlmSummarizer _llm;
        private readonly Channel<AnalyticsEnvelope> _channel;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _pump;
        private readonly object _cacheGate = new();
        private readonly Dictionary<string, Incident> _incidentCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly LinkedList<AnomalySignal> _anomalyCache = new();
        private readonly HashSet<string> _summariesInFlight = new(StringComparer.OrdinalIgnoreCase);
        private readonly TimeSpan _baselinePersistInterval = TimeSpan.FromSeconds(30);
        private readonly bool _enableMlAnomalyScoring;
        private DateTime _lastBaselinePersistUtc = DateTime.MinValue;

        public event Action<Incident>? IncidentCreated;
        public event Action<Incident>? IncidentUpdated;
        public event Action<AnomalySignal>? AnomalyObserved;
        public event Action<BaselineStatus>? BaselineStatusChanged;
        public event Action<string, string>? AnalysisProgress;
        public event Action<string, string>? SummaryReady;
        public event Action? StateReset;

        public DateTime? LastAnalysisUtc { get; private set; }

        public AnalyticsHost(
            TimeSpan window,
            LocalStore store,
            GraphBuilder? graph = null,
            UserBehaviorEngine? uba = null,
            GnnScoringClient? gnn = null,
            LlmSummarizer? llm = null,
            IncidentFeedbackStore? feedbackStore = null,
            FeatureExtractor? featureExtractor = null,
            BaselineEngine? baselineEngine = null,
            MlFeatureWindowBuilder? mlFeatureWindowBuilder = null,
            MlAnomalyScoringEngine? mlAnomalyScoringEngine = null,
            IncidentTimelineBuilder? timelineBuilder = null,
            IncidentCorrelationEngine? correlationEngine = null,
            RiskScoringEngine? riskScoringEngine = null,
            RecommendedActionEngine? recommendedActionEngine = null,
            bool enableMlAnomalyScoring = true)
        {
            _store = store ?? new LocalStore();
            _feedbackStore = feedbackStore ?? new IncidentFeedbackStore();
            _featureExtractor = featureExtractor ?? new FeatureExtractor();
            _llm = llm ?? new LlmSummarizer(LlmSummarizer.Backend.None);
            _enableMlAnomalyScoring = enableMlAnomalyScoring;
            _feedbackStore.CleanupExpiredSuppressions();

            var persistedIncidents = _store.LoadIncidents(250);
            var persistedAnomalies = _store.LoadAnomalies(600);
            var persistedBaselines = _store.LoadBaselineSnapshots();

            _baselineEngine = baselineEngine
                ?? new BaselineEngine(window <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : window, persistedBaselines);
            _mlWindowBuilder = mlFeatureWindowBuilder ?? new MlFeatureWindowBuilder(window <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : window);
            _mlAnomalyScoringEngine = mlAnomalyScoringEngine ?? new MlAnomalyScoringEngine();
            _timelineBuilder = timelineBuilder ?? new IncidentTimelineBuilder();
            _correlationEngine = correlationEngine
                ?? new IncidentCorrelationEngine(TimeSpan.FromMinutes(15), persistedIncidents, _timelineBuilder);
            _riskScoringEngine = riskScoringEngine ?? new RiskScoringEngine();
            _recommendedActionEngine = recommendedActionEngine ?? new RecommendedActionEngine();

            foreach (var incident in persistedIncidents)
                _incidentCache[incident.Id] = incident;

            foreach (var anomaly in persistedAnomalies.OrderBy(a => a.UpdatedUtc))
                _anomalyCache.AddLast(anomaly);

            foreach (var incident in _incidentCache.Values.ToList())
                ApplyFeedbackState(incident);

            _channel = Channel.CreateBounded<AnalyticsEnvelope>(new BoundedChannelOptions(8192)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait
            });

            _llm.Progress += (id, state) => AnalysisProgress?.Invoke(id, state);
            _pump = Task.Run(ProcessLoopAsync);
        }

        public void OnTrafficRecord(TrafficRecord record)
            => OnTrafficRecord(record, null);

        public void OnTrafficRecord(TrafficRecord record, string? demoTag)
        {
            if (record == null)
                return;

            _ = EnqueueAnalyticsAsync(new AnalyticsEnvelope(record, null, null, demoTag));
        }

        public void OnDetection(DetectionEvent evt)
            => OnDetection(evt, null);

        public void OnDetection(DetectionEvent evt, string? demoTag)
        {
            if (evt == null)
                return;

            var enqueueTask = EnqueueAnalyticsAsync(new AnalyticsEnvelope(null, evt, null, demoTag));
            if (!enqueueTask.IsCompletedSuccessfully)
            {
                _ = enqueueTask.ContinueWith(t =>
                {
                    if (t.Exception != null)
                    {
                        RuleEngineHealthState.ReportSinkQueueBackpressure("analytics enqueue failed: " + t.Exception.GetBaseException().Message);
                        RuleEngineMetrics.Increment(evt.RuleId, RuleMetricNames.DetectionOutboxPendingTotal);
                    }
                }, TaskScheduler.Default);
            }
        }

        public void OnAnomaly(AnomalySignal anomaly, string? demoTag = null)
        {
            if (anomaly == null)
                return;

            _ = EnqueueAnalyticsAsync(new AnalyticsEnvelope(null, null, anomaly, demoTag));
        }

        private async Task EnqueueAnalyticsAsync(AnalyticsEnvelope envelope)
        {
            try
            {
                await _channel.Writer.WriteAsync(envelope, _cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Shutdown path; DetectionEvents remain in the mandatory journal.
            }
            catch (Exception ex)
            {
                if (envelope.DetectionEvent != null)
                {
                    RuleEngineHealthState.ReportSinkQueueBackpressure("analytics enqueue failed: " + ex.Message);
                    RuleEngineMetrics.Increment(envelope.DetectionEvent.RuleId, RuleMetricNames.DetectionOutboxPendingTotal);
                }
                // DetectionEvents are already durable in the local journal; analytics enqueue failure must not crash callers.
            }
        }

        public IReadOnlyList<Incident> GetRecentIncidents(int limit = 200)
        {
            lock (_cacheGate)
            {
                return _incidentCache.Values
                    .OrderBy(i => i.IsSuppressed)
                    .ThenByDescending(i => i.RiskScore)
                    .ThenByDescending(i => i.UpdatedUtc)
                    .Take(Math.Max(1, limit))
                    .Select(CloneIncident)
                    .ToArray();
            }
        }

        public IReadOnlyList<AnomalySignal> GetRecentAnomalies(int limit = 500)
        {
            lock (_cacheGate)
            {
                return _anomalyCache
                    .TakeLast(Math.Max(1, limit))
                    .Reverse()
                    .Select(CloneAnomaly)
                    .ToArray();
            }
        }

        public BaselineStatus GetBaselineStatus() => _baselineEngine.GetStatus();

        public void UpdateIncidentStatus(string incidentId, string status)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return;

            Incident? incident = null;
            lock (_cacheGate)
            {
                if (_incidentCache.TryGetValue(incidentId, out incident))
                {
                    var previousStatus = incident.Status;
                    incident.Status = NormalizeStatus(status);
                    incident.UpdatedUtc = DateTime.UtcNow;
                    _timelineBuilder.AddStatusChange(incident, previousStatus, incident.Status);
                }
            }

            if (incident == null)
                return;

            _correlationEngine.UpdateStatus(incidentId, incident.Status);
            _store.SaveIncident(incident);
            IncidentUpdated?.Invoke(CloneIncident(incident));
        }

        public void UpdateIncidentPresentation(string incidentId, string title, string category)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return;

            Incident? incident = null;
            lock (_cacheGate)
            {
                if (_incidentCache.TryGetValue(incidentId, out incident))
                {
                    if (!string.IsNullOrWhiteSpace(title))
                        incident.Title = title;
                    if (!string.IsNullOrWhiteSpace(category))
                        incident.Category = category;
                    incident.UpdatedUtc = DateTime.UtcNow;
                    _incidentCache[incidentId] = CloneIncident(incident);
                }
            }

            if (incident == null)
                return;

            _store.SaveIncident(incident);
            IncidentUpdated?.Invoke(CloneIncident(incident));
        }

        public int ClearDemoData(bool includeFeedback = true)
        {
            int removedIncidents;
            int removedAnomalies;
            int removedFeedback = 0;

            lock (_cacheGate)
            {
                removedIncidents = _incidentCache
                    .Where(kv => HasDemoTag(kv.Value.Tags))
                    .Select(kv => kv.Key)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray()
                    .Length;

                foreach (var incidentId in _incidentCache
                             .Where(kv => HasDemoTag(kv.Value.Tags))
                             .Select(kv => kv.Key)
                             .Distinct(StringComparer.OrdinalIgnoreCase)
                             .ToArray())
                {
                    _incidentCache.Remove(incidentId);
                    _summariesInFlight.Remove(incidentId);
                }

                removedAnomalies = _anomalyCache.Count(anomaly => HasDemoTag(anomaly.Tags));
                var remainingAnomalies = _anomalyCache
                    .Where(anomaly => !HasDemoTag(anomaly.Tags))
                    .Select(CloneAnomaly)
                    .ToArray();

                _anomalyCache.Clear();
                foreach (var anomaly in remainingAnomalies)
                    _anomalyCache.AddLast(anomaly);
            }

            _store.DeleteIncidents(incident => HasDemoTag(incident.Tags));
            _store.DeleteAnomalies(anomaly => HasDemoTag(anomaly.Tags));
            if (includeFeedback)
            {
                var existingFeedback = _feedbackStore.GetAll();
                removedFeedback = existingFeedback.Count(entry => HasDemoTag(entry.Tags));
                _feedbackStore.DeleteFeedback(entry => HasDemoTag(entry.Tags));
            }

            StateReset?.Invoke();
            PublishBaselineStatus();
            return removedIncidents + removedAnomalies + removedFeedback;
        }

        public void MarkIncidentConfirmedSuspicious(string incidentId, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "ConfirmedSuspicious", analystNote);

        public void MarkIncidentExpected(string incidentId, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "ExpectedBehavior", analystNote);

        public void MarkIncidentFalsePositive(string incidentId, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "FalsePositive", analystNote);

        public void SuppressSimilar(string incidentId, TimeSpan duration, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "SuppressSimilar", analystNote, DateTime.UtcNow.Add(duration <= TimeSpan.Zero ? TimeSpan.FromDays(7) : duration));

        public void TrustDestinationForHost(string incidentId, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "TrustDestinationForHost", analystNote);

        public void TrustPortForHost(string incidentId, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "TrustPortForHost", analystNote);

        public void TrustProcessForHost(string incidentId, string? analystNote = null)
            => ApplyFeedbackAndRefresh(incidentId, "TrustProcessForHost", analystNote);

        public void AddIncidentNote(string incidentId, string? analystNote)
            => ApplyFeedbackAndRefresh(incidentId, "AddNote", analystNote);

        public void Dispose()
        {
            try { _channel.Writer.TryComplete(); } catch { }
            try { _cts.Cancel(); } catch { }
            try { _pump.Wait(TimeSpan.FromSeconds(5)); } catch { }
            try { PersistBaselines(force: true); } catch { }
        }

        private async Task ProcessLoopAsync()
        {
            try
            {
                while (await _channel.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
                {
                    while (_channel.Reader.TryRead(out var envelope))
                    {
                        try
                        {
                            if (envelope.TrafficRecord != null)
                                ProcessTraffic(envelope.TrafficRecord, envelope.DemoTag);

                            if (envelope.AnomalySignal != null)
                                ProcessInjectedAnomaly(envelope.AnomalySignal, envelope.DemoTag);

                            if (envelope.DetectionEvent != null)
                                ProcessDetection(envelope.DetectionEvent, envelope.DemoTag);

                            LastAnalysisUtc = DateTime.UtcNow;
                            PersistBaselines();
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"[AnalyticsHost] Processing failed: {ex.Message}");
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }

        private void ProcessTraffic(TrafficRecord record, string? demoTag)
        {
            var feature = _featureExtractor.FromTrafficRecord(record);
            var anomalies = _baselineEngine.ObserveTraffic(feature);
            PublishAnomalies(anomalies, demoTag);
            ObserveMlTraffic(feature, demoTag);
            PublishBaselineStatus();
        }

        private void ProcessDetection(DetectionEvent evt, string? demoTag = null)
        {
            var feature = _featureExtractor.FromDetectionEvent(evt);
            var baselineAnomalies = _baselineEngine.ObserveDetection(evt, feature);
            PublishAnomalies(baselineAnomalies, demoTag);
            ObserveMlDetection(evt, feature, demoTag);

            var correlation = _correlationEngine.Correlate(evt);
            FinalizeIncident(correlation, summarize: correlation.IsNew || evt.Severity >= SeverityLevel.High, demoTag);
            PublishBaselineStatus();
        }

        private void ProcessInjectedAnomaly(AnomalySignal anomaly, string? demoTag)
        {
            PublishAnomalies(new[] { anomaly }, demoTag);
            ObserveMlAnomaly(anomaly, demoTag);
            PublishBaselineStatus();
        }

        private void ObserveMlTraffic(FlowFeature feature, string? demoTag)
        {
            if (!_enableMlAnomalyScoring)
                return;

            PublishMlSignals(_mlWindowBuilder.ObserveTraffic(feature), demoTag);
        }

        private void ObserveMlDetection(DetectionEvent evt, FlowFeature feature, string? demoTag)
        {
            if (!_enableMlAnomalyScoring)
                return;

            PublishMlSignals(_mlWindowBuilder.ObserveDetection(evt, feature), demoTag);
        }

        private void ObserveMlAnomaly(AnomalySignal anomaly, string? demoTag)
        {
            if (!_enableMlAnomalyScoring)
                return;

            PublishMlSignals(_mlWindowBuilder.ObserveAnomaly(anomaly), demoTag);
        }

        private void PublishMlSignals(IReadOnlyList<MlFeatureWindow> windows, string? demoTag)
        {
            if (!_enableMlAnomalyScoring || windows == null || windows.Count == 0)
                return;

            foreach (var window in windows)
            {
                var score = _mlAnomalyScoringEngine.Evaluate(window);
                if (score == null || !score.IsAnomalous || score.Score < 55)
                    continue;

                var signal = CreateMlAnomalySignal(score);
                if (signal != null)
                    PublishAnomalies(new[] { signal }, demoTag);
            }
        }

        private void PublishAnomalies(IReadOnlyList<AnomalySignal> anomalies, string? demoTag = null)
        {
            if (anomalies == null || anomalies.Count == 0)
                return;

            foreach (var anomaly in anomalies)
            {
                ApplyDemoTag(anomaly.Tags, demoTag);
                _store.SaveAnomaly(anomaly);
                lock (_cacheGate)
                {
                    _anomalyCache.AddLast(CloneAnomaly(anomaly));
                    while (_anomalyCache.Count > 1000)
                        _anomalyCache.RemoveFirst();
                }

                AnomalyObserved?.Invoke(CloneAnomaly(anomaly));

                var correlation = _correlationEngine.Correlate(anomaly);
                FinalizeIncident(correlation, summarize: correlation.IsNew || anomaly.Score >= 0.85, demoTag);
            }
        }

        private void FinalizeIncident(CorrelationResult result, bool summarize, string? demoTag = null)
        {
            var incident = result.Incident;
            var previousRiskScore = incident.RiskScore == 0 ? (int?)null : incident.RiskScore;
            var previousSeverity = string.IsNullOrWhiteSpace(incident.Severity) ? null : incident.Severity;
            ApplyDemoTag(incident.Tags, demoTag);
            if (result.IsNew && !string.IsNullOrWhiteSpace(demoTag))
            {
                _timelineBuilder.AddDemoStep(
                    incident,
                    "Demo scenario started",
                    "The developer demo injected a simulated compromised-laptop sequence into the analytics pipeline.",
                    incident.FirstSeenUtc == default ? incident.CreatedUtc : incident.FirstSeenUtc,
                    DemoScenarioService.DemoTag,
                    demoTag);
            }
            ApplyFeedbackState(incident);
            _timelineBuilder.AddRiskChange(incident, previousRiskScore, previousSeverity, incident.FeedbackAppliedReasons.FirstOrDefault() ?? incident.RiskReasons.FirstOrDefault());
            incident.RecommendedActions = _recommendedActionEngine.GetActions(incident).ToList();
            _timelineBuilder.AddRecommendedActions(incident, incident.RecommendedActions);
            incident.UpdatedUtc = DateTime.UtcNow;

            lock (_cacheGate)
            {
                _incidentCache[incident.Id] = CloneIncident(incident);
            }

            _store.SaveIncident(incident);

            if (result.IsNew)
                IncidentCreated?.Invoke(CloneIncident(incident));
            else
                IncidentUpdated?.Invoke(CloneIncident(incident));

            if (summarize)
                QueueSummary(incident);
        }

        private void QueueSummary(Incident incident)
        {
            if (incident == null || string.IsNullOrWhiteSpace(incident.Id))
                return;

            lock (_cacheGate)
            {
                if (!_incidentCache.TryGetValue(incident.Id, out var live))
                    return;

                if (!_summariesInFlight.Add(incident.Id))
                    return;

                live.IsAnalyzing = true;
                _incidentCache[incident.Id] = live;
                _store.SaveIncident(live);
            }

            AnalysisProgress?.Invoke(incident.Id, "queued");
            var snapshot = CloneIncident(incident);

            _ = Task.Run(async () =>
            {
                try
                {
                    var summary = await _llm.TrySummarizeAsync(snapshot, ct: _cts.Token).ConfigureAwait(false);
                    Incident? updated = null;
                    lock (_cacheGate)
                    {
                        if (_incidentCache.TryGetValue(snapshot.Id, out updated))
                        {
                            updated.Summary = summary;
                            updated.IsAnalyzing = false;
                            updated.UpdatedUtc = DateTime.UtcNow;
                            _timelineBuilder.AddSummary(updated, summary);
                            _incidentCache[snapshot.Id] = updated;
                        }

                        _summariesInFlight.Remove(snapshot.Id);
                    }

                    if (updated != null)
                    {
                        _store.UpdateIncidentSummary(updated.Id, summary);
                        SummaryReady?.Invoke(updated.Id, summary);
                        IncidentUpdated?.Invoke(CloneIncident(updated));
                    }
                }
                catch (OperationCanceledException)
                {
                    lock (_cacheGate)
                        _summariesInFlight.Remove(snapshot.Id);
                }
                catch (Exception ex)
                {
                    Incident? updated = null;
                    lock (_cacheGate)
                    {
                        _summariesInFlight.Remove(snapshot.Id);
                        if (_incidentCache.TryGetValue(snapshot.Id, out updated))
                        {
                            updated.IsAnalyzing = false;
                            updated.UpdatedUtc = DateTime.UtcNow;
                            _timelineBuilder.AddSummary(updated, BuildFallbackTimelineSummary(updated));
                            _incidentCache[snapshot.Id] = updated;
                        }
                    }

                    if (updated != null)
                        _store.SaveIncident(updated);
                    AnalysisProgress?.Invoke(snapshot.Id, "failed: " + ex.Message);
                }
            }, _cts.Token);
        }

        private void PersistBaselines(bool force = false)
        {
            var now = DateTime.UtcNow;
            if (!force && now - _lastBaselinePersistUtc < _baselinePersistInterval)
                return;

            if (_store.SaveBaselineSnapshots(_baselineEngine.GetSnapshots()))
                _lastBaselinePersistUtc = now;
        }

        private void PublishBaselineStatus()
            => BaselineStatusChanged?.Invoke(_baselineEngine.GetStatus());

        private void ApplyFeedbackAndRefresh(string incidentId, string? feedbackType, string? analystNote = null, DateTime? suppressUntilUtc = null)
        {
            if (string.IsNullOrWhiteSpace(incidentId) || string.IsNullOrWhiteSpace(feedbackType))
                return;

            Incident? snapshot = null;
            lock (_cacheGate)
            {
                if (_incidentCache.TryGetValue(incidentId, out var incident))
                    snapshot = CloneIncident(incident);
            }

            if (snapshot == null)
                return;

            var feedback = BuildFeedback(snapshot, feedbackType, analystNote, suppressUntilUtc);
            _feedbackStore.SaveFeedback(feedback);
            ReevaluateIncidents(feedback);
        }

        private void ReevaluateIncidents(IncidentFeedback? newestFeedback = null)
        {
            List<Incident> refreshed;
            lock (_cacheGate)
            {
                refreshed = _incidentCache.Values
                    .Select(CloneIncident)
                    .ToList();
            }

            foreach (var incident in refreshed)
            {
                var previousRiskScore = incident.RiskScore == 0 ? (int?)null : incident.RiskScore;
                var previousSeverity = string.IsNullOrWhiteSpace(incident.Severity) ? null : incident.Severity;
                ApplyFeedbackState(incident);

                if (newestFeedback != null
                    && string.Equals(newestFeedback.IncidentId, incident.Id, StringComparison.OrdinalIgnoreCase))
                {
                    _timelineBuilder.AddFeedback(incident, newestFeedback, incident.FeedbackAppliedReasons);
                }

                _timelineBuilder.AddRiskChange(incident, previousRiskScore, previousSeverity, incident.FeedbackAppliedReasons.FirstOrDefault() ?? incident.RiskReasons.FirstOrDefault());
            }

            lock (_cacheGate)
            {
                foreach (var incident in refreshed)
                    _incidentCache[incident.Id] = CloneIncident(incident);
            }

            foreach (var incident in refreshed)
            {
                _store.SaveIncident(incident);
                IncidentUpdated?.Invoke(CloneIncident(incident));
            }
        }

        private void ApplyFeedbackState(Incident incident)
        {
            var matchingFeedback = _feedbackStore.GetMatchingFeedback(incident);
            var latestExactFeedback = _feedbackStore.GetLatestExactFeedback(incident.Id);
            var displayFeedback = latestExactFeedback ?? GetLatestDisplayFeedback(matchingFeedback);

            incident.AnalystFeedbackType = displayFeedback?.FeedbackType;
            incident.LastFeedbackUtc = displayFeedback?.CreatedUtc;
            incident.AnalystNote = latestExactFeedback?.AnalystNote ?? incident.AnalystNote;
            if (string.IsNullOrWhiteSpace(incident.AnalystNote))
            {
                incident.AnalystNote = matchingFeedback
                    .Where(entry => !string.IsNullOrWhiteSpace(entry.AnalystNote))
                    .OrderByDescending(entry => entry.CreatedUtc)
                    .Select(entry => entry.AnalystNote)
                    .FirstOrDefault();
            }

            _riskScoringEngine.Score(incident, matchingFeedback);

            foreach (var feedback in matchingFeedback
                         .Where(entry => !string.Equals(entry.FeedbackType, "AddNote", StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(entry => entry.CreatedUtc)
                         .Take(3))
            {
                _timelineBuilder.AddFeedback(incident, feedback, incident.FeedbackAppliedReasons);
            }

            if (latestExactFeedback != null
                && string.Equals(latestExactFeedback.FeedbackType, "AddNote", StringComparison.OrdinalIgnoreCase))
            {
                _timelineBuilder.AddFeedback(incident, latestExactFeedback, new[] { latestExactFeedback.AnalystNote ?? "The analyst added a local note to the incident." });
            }
        }

        private static IncidentFeedback BuildFeedback(Incident incident, string feedbackType, string? analystNote, DateTime? suppressUntilUtc)
        {
            var processName = IncidentFeedbackStore.GetIncidentProcessName(incident);
            var destinationPort = IncidentFeedbackStore.GetIncidentPort(incident);

            return new IncidentFeedback
            {
                IncidentId = incident.Id,
                FeedbackType = feedbackType,
                CreatedUtc = DateTime.UtcNow,
                SourceIp = incident.PrimarySourceIp,
                DestinationIp = incident.PrimaryDestinationIp,
                DestinationHost = incident.PrimaryDestinationHost,
                DestinationPort = destinationPort,
                ProcessName = processName,
                Category = incident.Category,
                AnalystNote = string.IsNullOrWhiteSpace(analystNote) ? null : analystNote.Trim(),
                SuppressUntilUtc = suppressUntilUtc,
                Tags = incident.Tags.ToArray()
            };
        }

        private static IncidentFeedback? GetLatestDisplayFeedback(IReadOnlyList<IncidentFeedback> feedback)
        {
            return feedback
                .Where(entry => !string.Equals(entry.FeedbackType, "AddNote", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(entry => entry.CreatedUtc)
                .FirstOrDefault();
        }

        private static string BuildFallbackTimelineSummary(Incident incident)
        {
            var orderedItems = incident.TimelineItems
                .OrderBy(item => item.TimestampUtc)
                .ToArray();

            if (orderedItems.Length == 0)
            {
                var actor = string.IsNullOrWhiteSpace(incident.PrimarySourceIp) ? "the affected host" : incident.PrimarySourceIp;
                return $"The incident for {actor} remains correlated and under investigation.";
            }

            var highlights = orderedItems
                .Select(item => item.Title)
                .Where(title => !string.IsNullOrWhiteSpace(title))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(3)
                .ToArray();

            var first = highlights.ElementAtOrDefault(0) ?? "initial suspicious activity";
            var second = highlights.ElementAtOrDefault(1);
            var third = highlights.ElementAtOrDefault(2);
            var risk = incident.RiskScore > 0 ? $"Risk is currently {incident.RiskScore}/100." : string.Empty;

            return second == null
                ? $"The incident began with {first}. {risk}".Trim()
                : third == null
                    ? $"The incident began with {first}, followed by {second}. {risk}".Trim()
                    : $"The incident began with {first}, followed by {second}, and later {third}. {risk}".Trim();
        }

        private static Incident CloneIncident(Incident incident)
        {
            return new Incident
            {
                Id = incident.Id,
                Title = incident.Title,
                Severity = incident.Severity,
                RiskScore = incident.RiskScore,
                FirstSeenUtc = incident.FirstSeenUtc,
                CreatedUtc = incident.CreatedUtc,
                UpdatedUtc = incident.UpdatedUtc,
                LastSeenUtc = incident.LastSeenUtc,
                PrimarySourceIp = incident.PrimarySourceIp,
                PrimaryDestinationIp = incident.PrimaryDestinationIp,
                PrimaryDestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                Status = incident.Status,
                Summary = incident.Summary,
                IsAnalyzing = incident.IsAnalyzing,
                OccurrenceCount = incident.OccurrenceCount,
                CorrelationKey = incident.CorrelationKey,
                RelatedEvents = incident.RelatedEvents.ToList(),
                RelatedAnomalies = incident.RelatedAnomalies.Select(CloneAnomaly).ToList(),
                Evidence = incident.Evidence.ToList(),
                RecommendedActions = incident.RecommendedActions.ToList(),
                Tags = incident.Tags.ToList(),
                RiskReasons = incident.RiskReasons.ToList(),
                TimelineItems = incident.TimelineItems
                    .Select(item => new IncidentTimelineItem
                    {
                        Id = item.Id,
                        TimestampUtc = item.TimestampUtc,
                        Type = item.Type,
                        Title = item.Title,
                        Description = item.Description,
                        Severity = item.Severity,
                        RiskScoreAfter = item.RiskScoreAfter,
                        SourceIp = item.SourceIp,
                        DestinationIp = item.DestinationIp,
                        DestinationHost = item.DestinationHost,
                        Category = item.Category,
                        Tags = item.Tags.ToArray(),
                        Details = item.Details.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase)
                    })
                    .ToList(),
                AnalystFeedbackType = incident.AnalystFeedbackType,
                AnalystNote = incident.AnalystNote,
                FeedbackAppliedReasons = incident.FeedbackAppliedReasons.ToList(),
                SuppressedUntilUtc = incident.SuppressedUntilUtc,
                IsSuppressed = incident.IsSuppressed,
                LastFeedbackUtc = incident.LastFeedbackUtc
            };
        }

        private static AnomalySignal CloneAnomaly(AnomalySignal anomaly)
        {
            return new AnomalySignal
            {
                Id = anomaly.Id,
                CreatedUtc = anomaly.CreatedUtc,
                UpdatedUtc = anomaly.UpdatedUtc,
                SourceIp = anomaly.SourceIp,
                DestinationIp = anomaly.DestinationIp,
                DestinationHost = anomaly.DestinationHost,
                DestinationPort = anomaly.DestinationPort,
                Protocol = anomaly.Protocol,
                Category = anomaly.Category,
                Title = anomaly.Title,
                Description = anomaly.Description,
                Score = anomaly.Score,
                Severity = anomaly.Severity,
                Reasons = anomaly.Reasons.ToList(),
                RelatedRuleIds = anomaly.RelatedRuleIds.ToList(),
                Tags = anomaly.Tags.ToList(),
                Features = anomaly.Features.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase)
            };
        }

        private static string NormalizeStatus(string? status)
        {
            if (string.Equals(status, "Resolved", StringComparison.OrdinalIgnoreCase))
                return "Resolved";
            if (string.Equals(status, "Acknowledged", StringComparison.OrdinalIgnoreCase))
                return "Acknowledged";
            return "New";
        }

        private static void ApplyDemoTag(ICollection<string> tags, string? demoTag)
        {
            if (string.IsNullOrWhiteSpace(demoTag))
                return;

            EnsureTag(tags, DemoScenarioService.DemoTag);
            EnsureTag(tags, demoTag);
        }

        private static bool HasDemoTag(IEnumerable<string> tags)
            => tags.Any(tag => string.Equals(tag, DemoScenarioService.DemoTag, StringComparison.OrdinalIgnoreCase)
                            || tag.StartsWith("demo:", StringComparison.OrdinalIgnoreCase));

        private static void EnsureTag(ICollection<string> tags, string tag)
        {
            if (string.IsNullOrWhiteSpace(tag))
                return;

            if (tags.Any(existing => string.Equals(existing, tag, StringComparison.OrdinalIgnoreCase)))
                return;

            tags.Add(tag);
        }

        private static AnomalySignal? CreateMlAnomalySignal(MlAnomalyScore score)
        {
            if (score == null || string.IsNullOrWhiteSpace(score.SourceIp))
                return null;

            var id = $"ml:{score.SourceIp}:{score.WindowStartUtc:yyyyMMddHHmm}";
            var featurePairs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["MlScore"] = score.Score.ToString("0.0"),
                ["MlConfidence"] = score.Confidence.ToString("0.00"),
                ["MlModelName"] = score.ModelName,
                ["MlModelVersion"] = score.ModelVersion,
                ["WindowStartUtc"] = score.WindowStartUtc.ToString("o"),
                ["WindowEndUtc"] = score.WindowEndUtc.ToString("o")
            };

            foreach (var contribution in score.FeatureContributions
                         .OrderByDescending(kv => kv.Value)
                         .Take(3))
            {
                featurePairs[$"MlFeature:{contribution.Key}"] = contribution.Value.ToString("0.0");
            }

            return new AnomalySignal
            {
                Id = id,
                CreatedUtc = score.WindowEndUtc == default ? score.ScoredAtUtc : score.WindowEndUtc,
                UpdatedUtc = score.WindowEndUtc == default ? score.ScoredAtUtc : score.WindowEndUtc,
                SourceIp = score.SourceIp,
                Category = "MlBehaviorAnomaly",
                Title = $"ML-assisted behavior anomaly for {score.SourceIp}",
                Description = "ML.NET detected unusual behavior compared with recent host activity windows.",
                Score = Math.Clamp(score.Score / 100.0, 0, 1),
                Severity = score.Score >= 80 ? "high" : "medium",
                Reasons = score.Reasons
                    .Where(reason => !string.IsNullOrWhiteSpace(reason))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .ToList(),
                Tags = new List<string> { "ml", "behavior", "anomaly", "host-baseline", "ml-assisted" },
                Features = featurePairs
            };
        }

        private readonly record struct AnalyticsEnvelope(
            TrafficRecord? TrafficRecord,
            DetectionEvent? DetectionEvent,
            AnomalySignal? AnomalySignal,
            string? DemoTag);
    }
}
