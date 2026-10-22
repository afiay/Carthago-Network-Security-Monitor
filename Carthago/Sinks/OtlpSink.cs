// SPDX-License-Identifier: MIT
// File: Sinks/OtlpSink.cs
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;

namespace Carthago.Sinks
{
    public sealed class OtlpSink : IDetectionSink
    {
        private readonly ILogger _logger;
        private readonly ILoggerFactory _lf;

        public OtlpSink(string otlpLogsEndpoint)
        {
            _lf = LoggerFactory.Create(builder =>
            {
                builder.AddOpenTelemetry(o =>
                {
                    o.IncludeFormattedMessage = true;
                    o.ParseStateValues = true;
                    o.IncludeScopes = false;
                    o.AddOtlpExporter(exp =>
                    {
                        exp.Endpoint = new Uri(otlpLogsEndpoint); // e.g., http://localhost:4318/v1/logs
                    });
                });
            });
            _logger = _lf.CreateLogger("Carthago.Detections");
        }

        public Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            // Structured log
            _logger.LogInformation("detection {@evt}", evt);
            // If your backend prefers raw JSON, use: _logger.LogInformation("{json}", JsonSerializer.Serialize(evt));
            return Task.CompletedTask;
        }

        public void Dispose() => _lf?.Dispose();
    }
}
