// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // Per-detector bounded observation state. A packet ID can contribute
    // exactly once to both the distinct-artifact count and byte volume.
    internal sealed class NetworkBatch201205Window
    {
        private sealed class Slot
        {
            internal readonly Dictionary<Guid, (DateTime At, string Artifact, long Bytes)> Events = new();
            internal DateTime Latest = DateTime.MinValue;
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);
        internal bool Observe(TrafficRecord record, string key, string artifact, DateTime at,
            TimeSpan window, long bytes, out int distinct, out long totalBytes)
        {
            distinct = 0; totalBytes = 0;
            if (record.Id == Guid.Empty || string.IsNullOrWhiteSpace(key)
                || string.IsNullOrWhiteSpace(artifact)) return false;
            lock (_gate)
            {
                foreach (var old in _slots.Where(x => at - x.Value.Latest > TimeSpan.FromHours(2))
                    .Select(x => x.Key).ToArray()) _slots.Remove(old);
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 1024)
                        _slots.Remove(_slots.OrderBy(x => x.Value.Latest).First().Key);
                    _slots[key] = slot = new Slot();
                }
                if (at < slot.Latest || slot.Events.ContainsKey(record.Id)) return false;
                foreach (var old in slot.Events.Where(x => at - x.Value.At > window)
                    .Select(x => x.Key).ToArray()) slot.Events.Remove(old);
                if (slot.Events.Count >= 256)
                    slot.Events.Remove(slot.Events.OrderBy(x => x.Value.At).First().Key);
                slot.Events.Add(record.Id, (at, artifact, Math.Max(0, bytes)));
                slot.Latest = at;
                distinct = slot.Events.Values.Select(x => x.Artifact)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count();
                totalBytes = slot.Events.Values.Sum(x => x.Bytes);
                return true;
            }
        }
    }
}
