// SPDX-License-Identifier: MIT
// File: Services/Sensors/SensorRegistry.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Carthago.Services;

namespace Carthago.Services.Sensors
{
    public sealed class SensorRegistry
    {
        private readonly string _directory;
        private readonly JsonSerializerOptions _json = new() { Converters = { new JsonStringEnumConverter() } };

        public SensorRegistry(string? directory = null)
        {
            _directory = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Carthago", "sensors");
        }

        public async Task RecordHeartbeatAsync(SensorHeartbeat heartbeat)
        {
            Directory.CreateDirectory(_directory);
            var path = Path.Combine(_directory, $"heartbeats-{DateTime.UtcNow:yyyy-MM-dd}.jsonl");
            await File.AppendAllTextAsync(path, JsonSerializer.Serialize(heartbeat, _json) + Environment.NewLine).ConfigureAwait(false);
            if (heartbeat.ClockSkewMs.HasValue)
                RuleEngineHealthState.ReportClockSkew(DateTime.UtcNow.AddMilliseconds(-heartbeat.ClockSkewMs.Value), DateTime.UtcNow);
        }

        public async Task<IReadOnlyList<SensorHealth>> ReadHealthAsync()
        {
            if (!Directory.Exists(_directory)) return Array.Empty<SensorHealth>();
            var latest = new Dictionary<string, SensorHealth>(StringComparer.OrdinalIgnoreCase);
            foreach (var file in Directory.EnumerateFiles(_directory, "heartbeats-*.jsonl"))
            {
                foreach (var line in await File.ReadAllLinesAsync(file).ConfigureAwait(false))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var hb = JsonSerializer.Deserialize<SensorHeartbeat>(line, _json);
                        if (hb == null) continue;
                        latest[hb.SensorId] = new SensorHealth { SensorId = hb.SensorId, LastHeartbeatUtc = hb.TimestampUtc, Status = hb.Status, ClockSkewMs = hb.ClockSkewMs };
                    }
                    catch { }
                }
            }
            return latest.Values.OrderBy(h => h.SensorId).ToList();
        }
    }
}
