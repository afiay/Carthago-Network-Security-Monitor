// File: Telemetry/OtelMetrics.cs
// SPDX-License-Identifier: MIT
#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Reflection;
using System.Runtime.CompilerServices; // MethodImpl / AggressiveInlining
using Carthago.Services;               // PreferencesService
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;

namespace Carthago.Telemetry
{
    /// <summary>
    /// Central OTLP metrics singleton. Instruments are always usable; exporter toggles from Preferences.
    /// </summary>
    public static class OtelMetrics
    {
        private const string METER_NAME = "Carthago";
        private static readonly object _gate = new();

        private static readonly Meter s_meter =
            new(METER_NAME, Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0");

        private static readonly Counter<long> s_packetsCaptured = s_meter.CreateCounter<long>("packets_captured");
        private static readonly Counter<long> s_packetsDropped = s_meter.CreateCounter<long>("packets_dropped");
        private static readonly Counter<long> s_parseFailures = s_meter.CreateCounter<long>("parse_failures");
        private static readonly UpDownCounter<long> s_queueDepth = s_meter.CreateUpDownCounter<long>("queue_depth");
        private static readonly Histogram<long> s_sinkBatchSize = s_meter.CreateHistogram<long>("sink_batch_size");
        private static readonly Histogram<double> s_sinkLatencyMs = s_meter.CreateHistogram<double>("sink_latency_ms");
        private static readonly Counter<long> s_ruleHits = s_meter.CreateCounter<long>("rule_hits");

        private static Func<double?>? s_cacheHitRatioProvider;
        private static readonly ObservableGauge<double> s_cacheHitGauge =
            s_meter.CreateObservableGauge("enrichment_cache_hit_ratio", () =>
            {
                double? v = s_cacheHitRatioProvider?.Invoke();
                return new[] { new Measurement<double>(v is null ? double.NaN : v.Value) };
            });

        private static MeterProvider? _provider;
        private static bool _started;

        /// <summary>Initialize metrics pipeline (idempotent).</summary>
        public static void EnsureStarted()
        {
            if (_started) return;
            lock (_gate)
            {
                if (_started) return;
                _started = true;
                BuildOrTearDownProviderFromPreferences();
            }
        }

        /// <summary>Alias kept for the Integrations page.</summary>
        public static void ReconfigureFromPreferences() => ReloadFromPreferences();

        /// <summary>Re-read preferences and rebuild exporter.</summary>
        public static void ReloadFromPreferences()
        {
            lock (_gate)
            {
                BuildOrTearDownProviderFromPreferences();
            }
        }

        private static void BuildOrTearDownProviderFromPreferences()
        {
            try { _provider?.Dispose(); } catch { }
            _provider = null;

            var p = PreferencesService.Current;
            bool enable = p.EnableOtlp;
            string? endpoint = p.OtlpEndpoint;

            if (!enable || string.IsNullOrWhiteSpace(endpoint))
                return;

            if (!Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out var uri))
                return;

            var rb = ResourceBuilder.CreateDefault()
                .AddService(
                    serviceName: "Carthago",
                    serviceVersion: Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0",
                    serviceInstanceId: Environment.MachineName)
                .AddAttributes(new[]
                {
                    new KeyValuePair<string, object>("os.type", Environment.OSVersion.Platform.ToString()),
                    new KeyValuePair<string, object>("process.pid", Environment.ProcessId),
                });

            var builder = Sdk.CreateMeterProviderBuilder()
                             .SetResourceBuilder(rb)
                             .AddMeter(METER_NAME);

            // http/https => OTLP/HTTP; otherwise gRPC
            var protocol = (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ||
                            uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                           ? OtlpExportProtocol.HttpProtobuf
                           : OtlpExportProtocol.Grpc;

            builder.AddOtlpExporter(o =>
            {
                o.Protocol = protocol;
                o.Endpoint = uri;
            });

            _provider = builder.Build();
        }

        // ===== Public API (no TagList dependency) =====

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CountPacketCaptured() => s_packetsCaptured.Add(1);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CountPacketDropped() => s_packetsDropped.Add(1);

        /// <param name="where">Small-cardinality label (e.g., "OnPacketArrival").</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CountParseFailure(string where)
        {
            s_parseFailures.Add(1, new KeyValuePair<string, object?>("where",
                string.IsNullOrWhiteSpace(where) ? "unknown" : where));
        }

        /// <summary>Adjust bounded UI queue depth (positive or negative deltas).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void AdjustQueueDepth(int delta) => s_queueDepth.Add(delta);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ObserveSinkBatchSize(int batchSize)
        {
            if (batchSize > 0) s_sinkBatchSize.Record(batchSize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ObserveSinkLatency(TimeSpan elapsed)
        {
            if (elapsed.Ticks > 0) s_sinkLatencyMs.Record(elapsed.TotalMilliseconds);
        }

        /// <param name="rule">Stable rule id/name; keep cardinality low.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CountRuleHit(string? rule)
        {
            s_ruleHits.Add(1, new KeyValuePair<string, object?>("rule",
                string.IsNullOrWhiteSpace(rule) ? "unknown" : rule));
        }

        /// <summary>Provide a callback returning a 0..1 cache hit ratio (or null if unknown).</summary>
        public static void SetCacheHitRatioProvider(Func<double?> provider)
        {
            s_cacheHitRatioProvider = provider;
        }

        /// <summary>Alias kept for the Integrations page.</summary>
        public static void EmitTestMetric() => SendTestMetric();

        /// <summary>Utility to emit a one-off test metric.</summary>
        public static void SendTestMetric()
        {
            EnsureStarted();
            s_meter.CreateCounter<long>("test_metric").Add(1);
        }
    }
}
