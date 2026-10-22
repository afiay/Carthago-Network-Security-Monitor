// SPDX-License-Identifier: MIT
// File: Sinks/SinkHost.cs
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Services;

using Carthago.Analytics;
using Carthago.Analytics.Services;

namespace Carthago.Sinks
{
    /// <summary>
    /// Subscribes to capture, fans detections to analytics + configured sinks, and surfaces UI events.
    /// </summary>
    public sealed class SinkHost : IDisposable
    {
        private readonly Func<AppPreferences> _getPrefs;
        private readonly object _gate = new();

        private SinkManager? _manager;
        private TrafficCaptureService? _capture;

        private AnalyticsHost? _analytics;
        private LocalStore? _store;
        private LlmSummarizer? _llm;

         public SinkHost(Func<AppPreferences> getPrefs, TrafficCaptureService capture)
         {
             _getPrefs = getPrefs ?? throw new ArgumentNullException(nameof(getPrefs));
             _capture = capture ?? throw new ArgumentNullException(nameof(capture));

             _capture.TrafficRecordReceived += OnTrafficRecord;
             // TrafficCaptureService.DetectionEventRaised is Action<DetectionEvent>
             _capture.DetectionEventRaised += OnDetection;

             BuildAll();
        }

        // Exposed for IncidentsPage
        public AnalyticsHost Analytics => _analytics ?? throw new InvalidOperationException("Analytics not initialized.");

        // UI hooks (kept as simple tuples for the page)
        public event Action<string, DetectionEvent, DateTime>? SinkEmitted;
        public event Action<string, DetectionEvent, Exception, DateTime>? SinkFailed;

        public void Reload()
        {
            lock (_gate)
            {
                TeardownManagerLocked();
                BuildManagerLocked();
            }
        }

        public void Dispose()
        {
             lock (_gate)
             {
                 try { if (_capture != null) _capture.TrafficRecordReceived -= OnTrafficRecord; } catch { }
                 try { if (_capture != null) _capture.DetectionEventRaised -= OnDetection; } catch { }

                TeardownManagerLocked();

                try { _analytics?.Dispose(); } catch { }
                try { _store?.Dispose(); } catch { }
                try { _llm?.Dispose(); } catch { }
                _analytics = null;
                _store = null;
                _llm = null;
                _capture = null;
            }
        }

        // ---------------- internals ----------------

        private void BuildAll()
        {
            lock (_gate)
            {
                _store ??= new LocalStore();

                _llm ??= BuildSummarizer();

                if (_analytics == null)
                {
                    _analytics = new AnalyticsHost(
                        window: TimeSpan.FromSeconds(30),
                        store: _store,
                        llm: _llm);

                    _analytics.IncidentCreated += inc =>
                        System.Diagnostics.Debug.WriteLine($"[INCIDENT] {inc.Title} sev={inc.Severity}");
                }

                BuildManagerLocked();
            }
        }

        private void BuildManagerLocked()
        {
            var prefs = _getPrefs();
            var sinks = BuildSinks(prefs);
            if (sinks.Count == 0)
                WriteDiagnostic("No sinks are enabled with valid configuration. Detection delivery to external sinks is idle.");

            _manager = new SinkManager(sinks.ToArray());

            // Bridge manager events to simple tuples for the UI
            _manager.SinkEmitted += Manager_SinkEmitted;
            _manager.SinkFailed += Manager_SinkFailed;
        }

        private void TeardownManagerLocked()
        {
            if (_manager != null)
            {
                try { _manager.SinkEmitted -= Manager_SinkEmitted; } catch { }
                try { _manager.SinkFailed -= Manager_SinkFailed; } catch { }
                try { _manager.Dispose(); } catch { }
                _manager = null;
            }
        }

        // TrafficCaptureService callback (Action<DetectionEvent>)
        private void OnTrafficRecord(TrafficRecord record)
        {
            try { _analytics?.OnTrafficRecord(record); } catch { /* best-effort */ }
        }

        private async void OnDetection(DetectionEvent e)
        {
            // 1) analytics is downstream of the mandatory journal and is not the source of truth.
            try { _analytics?.OnDetection(e); } catch { /* best-effort */ }

            // 2) sinks via manager. Await the enqueue so backpressure/failure is observed;
            // never mark the local journal status as failed because of an external sink issue.
            var mgr = _manager;
            if (mgr == null) return;

            try
            {
                await mgr.EnqueueAsync(e).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                e.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed;
                e.LastSinkError = ex.Message;
                e.LastSinkAttemptUtc = DateTime.UtcNow;
                e.SinkFailureCount++;
                RuleEngineHealthState.ReportSinkQueueBackpressure(ex.Message);
                RuleEngineMetrics.Increment(e.RuleId, RuleMetricNames.RuleSinkFailedTotal);

                try
                {
                    await DetectionOutbox.Current.AppendPendingAsync(e, "SinkManager", ex.Message).ConfigureAwait(false);
                }
                catch { /* local journal is still authoritative */ }
            }
        }

        // Convert manager EventHandler<T> to simple tuple events
        private void Manager_SinkEmitted(object? sender, SinkEmitEventArgs e)
        {
            if (e.Event is not null)
                SinkEmitted?.Invoke(e.SinkName, e.Event, e.Utc);
        }

        private void Manager_SinkFailed(object? sender, SinkErrorEventArgs e)
        {
            if (e.Event is not null)
                SinkFailed?.Invoke(e.SinkName, e.Event, e.Exception, e.Utc);
        }

        private List<IDetectionSink> BuildSinks(AppPreferences prefs)
        {
            var sinks = new List<IDetectionSink>();

            AddSinkIfEnabled(
                sinks,
                "FileJsonl",
                prefs.EnableFileSink,
                () => new FileJsonlSink(
                    directory: string.IsNullOrWhiteSpace(prefs.FileSinkDirectory) ? null : prefs.FileSinkDirectory,
                    maxSizeMB: prefs.FileSinkMaxSizeMB > 0 ? prefs.FileSinkMaxSizeMB : 100,
                    rollDaily: prefs.FileSinkRollDaily,
                    compressOnRotate: prefs.FileSinkCompressOnRotate));

            AddSinkIfEnabled(
                sinks,
                "OTLP",
                prefs.EnableOtlp,
                () => ValidateAbsoluteUri(prefs.OtlpEndpoint, "OTLP endpoint is missing or invalid."),
                () => new OtlpSink(prefs.OtlpEndpoint!));

            AddSinkIfEnabled(
                sinks,
                "AzureLogs",
                prefs.EnableAzure,
                () =>
                {
                    if (!ValidateAbsoluteUri(prefs.AzureDceUri, "Azure DCE URI is missing or invalid.", out var reason))
                        return reason;
                    if (string.IsNullOrWhiteSpace(prefs.AzureDcrId))
                        return "Azure DCR immutable ID is required.";
                    if (string.IsNullOrWhiteSpace(prefs.AzureStream))
                        return "Azure stream name is required.";
                    return null;
                },
                () => new AzureLogsSink(prefs.AzureDceUri!, prefs.AzureDcrId!, prefs.AzureStream!));

            AddSinkIfEnabled(
                sinks,
                "CEF",
                prefs.EnableCef,
                () =>
                {
                    if (string.IsNullOrWhiteSpace(prefs.CefHost))
                        return "CEF host is required.";
                    if (prefs.CefPort is <= 0 or > 65535)
                        return "CEF port must be between 1 and 65535.";
                    return null;
                },
                () => new CefSyslogSink(prefs.CefHost!, prefs.CefPort, prefs.CefTls));

            AddSinkIfEnabled(
                sinks,
                "SplunkHEC",
                prefs.EnableSplunkHec,
                () =>
                {
                    if (!ValidateAbsoluteUri(prefs.SplunkBaseUrl, "Splunk base URL is missing or invalid.", out var reason))
                        return reason;
                    if (string.IsNullOrWhiteSpace(prefs.SplunkToken))
                        return "Splunk token is required.";
                    return null;
                },
                () => new SplunkHecSink(
                    prefs.SplunkBaseUrl!,
                    prefs.SplunkToken!,
                    prefs.SplunkSource,
                    prefs.SplunkSourcetype,
                    prefs.SplunkIndex,
                    prefs.SplunkHost));

            AddSinkIfEnabled(
                sinks,
                "Elastic",
                prefs.EnableElastic,
                () =>
                {
                    if (!ValidateAbsoluteUri(prefs.ElasticBaseUrl, "Elastic base URL is missing or invalid.", out var reason))
                        return reason;
                    if (string.IsNullOrWhiteSpace(prefs.ElasticIndex))
                        return "Elastic index is required.";
                    return null;
                },
                () => new ElasticSink(prefs.ElasticBaseUrl!, prefs.ElasticIndex!, prefs.ElasticApiKey));

            AddSinkIfEnabled(
                sinks,
                "Kafka",
                prefs.EnableKafka,
                () =>
                {
                    if (string.IsNullOrWhiteSpace(prefs.KafkaBootstrap))
                        return "Kafka bootstrap servers are required.";
                    if (string.IsNullOrWhiteSpace(prefs.KafkaTopic))
                        return "Kafka topic is required.";

                    var hasUser = !string.IsNullOrWhiteSpace(prefs.KafkaSaslUser);
                    var hasPass = !string.IsNullOrWhiteSpace(prefs.KafkaSaslPass);
                    if (hasUser != hasPass)
                        return "Kafka SASL username and password must be provided together.";

                    return null;
                },
                () => new KafkaSink(
                    prefs.KafkaBootstrap!,
                    prefs.KafkaTopic!,
                    prefs.KafkaSaslUser,
                    prefs.KafkaSaslPass));

            AddSinkIfEnabled(
                sinks,
                "Webhook",
                prefs.EnableWebhook,
                () => ValidateAbsoluteUri(prefs.WebhookUrl, "Webhook URL is missing or invalid."),
                () => new WebhookSink(prefs.WebhookUrl!));

            return sinks;
        }

        private void AddSinkIfEnabled(
            ICollection<IDetectionSink> sinks,
            string sinkName,
            bool enabled,
            Func<IDetectionSink> factory)
        {
            AddSinkIfEnabled(sinks, sinkName, enabled, static () => null, factory);
        }

        private void AddSinkIfEnabled(
            ICollection<IDetectionSink> sinks,
            string sinkName,
            bool enabled,
            Func<string?> validate,
            Func<IDetectionSink> factory)
        {
            if (!enabled)
                return;

            var reason = validate();
            if (!string.IsNullOrWhiteSpace(reason))
            {
                WriteDiagnostic($"{sinkName} sink skipped: {reason}");
                return;
            }

            try
            {
                sinks.Add(factory());
            }
            catch (Exception ex)
            {
                WriteDiagnostic($"{sinkName} sink failed to initialize: {ex.Message}");
            }
        }

        private static string? ValidateAbsoluteUri(string? value, string message)
            => ValidateAbsoluteUri(value, message, out var reason) ? null : reason;

        private static bool ValidateAbsoluteUri(string? value, string message, out string? reason)
        {
            if (string.IsNullOrWhiteSpace(value) || !Uri.TryCreate(value, UriKind.Absolute, out _))
            {
                reason = message;
                return false;
            }

            reason = null;
            return true;
        }

        private static void WriteDiagnostic(string message)
        {
            Console.Error.WriteLine($"[SinkHost] {message}");
        }

        private static LlmSummarizer BuildSummarizer()
        {
            var enabled = string.Equals(
                Environment.GetEnvironmentVariable("CARTHAGO_ENABLE_OLLAMA"),
                "true",
                StringComparison.OrdinalIgnoreCase);

            if (!enabled)
                return new LlmSummarizer(LlmSummarizer.Backend.None);

            var baseUrl = Environment.GetEnvironmentVariable("CARTHAGO_OLLAMA_URL");
            var model = Environment.GetEnvironmentVariable("CARTHAGO_OLLAMA_MODEL");

            return new LlmSummarizer(
                backend: LlmSummarizer.Backend.Ollama,
                baseUrl: string.IsNullOrWhiteSpace(baseUrl) ? "http://127.0.0.1:11434" : baseUrl,
                model: string.IsNullOrWhiteSpace(model) ? "qwen2.5:7b" : model,
                timeout: TimeSpan.FromSeconds(20));
        }
    }
}
