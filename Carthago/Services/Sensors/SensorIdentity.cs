// SPDX-License-Identifier: MIT
// File: Services/Sensors/SensorIdentity.cs
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Services.Sensors
{
    public sealed class SensorIdentity
    {
        public string TenantId { get; set; } = "local";
        public string SiteId { get; set; } = "default";
        public string SensorId { get; set; } = Environment.MachineName.ToLowerInvariant();
        public string? CaptureInterface { get; set; }
        public string SensorVersion { get; set; } = typeof(SensorIdentity).Assembly.GetName().Version?.ToString() ?? "local";
        public double? SensorClockSkewMs { get; set; }

        public static SensorIdentity LocalDefault() => new() { SensorId = $"local-{Dns.GetHostName().ToLowerInvariant()}" };

        public void ApplyTo(DetectionEvent evt)
        {
            evt.TenantId ??= TenantId;
            evt.SiteId ??= SiteId;
            evt.SensorId ??= SensorId;
            evt.CaptureInterface ??= CaptureInterface;
            evt.SensorVersion ??= SensorVersion;
            evt.SensorClockSkewMs ??= SensorClockSkewMs;
            evt.IngestionTimestampUtc ??= DateTime.UtcNow;
        }
    }
}
