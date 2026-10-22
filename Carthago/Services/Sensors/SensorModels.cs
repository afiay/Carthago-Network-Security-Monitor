// SPDX-License-Identifier: MIT
// File: Services/Sensors/SensorModels.cs
using System;
using Carthago.Models;

namespace Carthago.Services.Sensors
{
    public sealed class SensorHeartbeat
    {
        public string SensorId { get; set; } = string.Empty;
        public string SiteId { get; set; } = "default";
        public string TenantId { get; set; } = "local";
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public double? ClockSkewMs { get; set; }
        public string Status { get; set; } = "Online";
    }

    public sealed class SensorHealth
    {
        public string SensorId { get; set; } = string.Empty;
        public DateTime LastHeartbeatUtc { get; set; }
        public string Status { get; set; } = "Unknown";
        public double? ClockSkewMs { get; set; }
    }

    public sealed class SensorIngestionEnvelope
    {
        public SensorIdentity Sensor { get; set; } = SensorIdentity.LocalDefault();
        public DetectionEvent Event { get; set; } = new();
        public DateTime IngestionTimestampUtc { get; set; } = DateTime.UtcNow;
    }
}
