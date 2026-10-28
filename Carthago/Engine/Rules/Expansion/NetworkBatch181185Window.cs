// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // Instance-owned, bounded DNS event windows. Duplicate IDs and out-of-order
    // records never inflate a threshold. No shared static burst counters.
    internal sealed class NetworkBatch181185Window
    {
        private sealed class Slot
        {
            internal readonly Dictionary<Guid, (DateTime At, string Value)> Events = new();
            internal DateTime Latest = DateTime.MinValue;
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);
        internal int Observe(TrafficRecord r, string key, string value, DateTime at, TimeSpan window, bool distinct)
        {
            if (r.Id == Guid.Empty || string.IsNullOrWhiteSpace(r.Source)
                || string.IsNullOrWhiteSpace(r.Destination)) return 0;
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
                if (at < slot.Latest || slot.Events.ContainsKey(r.Id)) return 0;
                foreach (var old in slot.Events.Where(x => at - x.Value.At > window)
                    .Select(x => x.Key).ToArray()) slot.Events.Remove(old);
                if (slot.Events.Count >= 256)
                    slot.Events.Remove(slot.Events.OrderBy(x => x.Value.At).First().Key);
                slot.Events.Add(r.Id, (at, value));
                slot.Latest = at;
                return distinct
                    ? slot.Events.Values.Select(x => x.Value).Distinct(StringComparer.OrdinalIgnoreCase).Count()
                    : slot.Events.Count;
            }
        }
    }
}
