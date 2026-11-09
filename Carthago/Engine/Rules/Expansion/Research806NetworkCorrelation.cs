// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Bounded, per-rule state; no shared alert correlation.
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Engine.Rules.Expansion
{
    internal sealed class Research806DifferentPeerWindow
    {
        private sealed class State
        {
            internal string FirstPeer = string.Empty;
            internal Guid InitialId;
            internal DateTime First;
            internal DateTime Last;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, State> _states = new(StringComparer.Ordinal);

        internal bool Observe(string key, string peer, Guid id, DateTime at, bool first)
        {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(peer)
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc) return false;
            lock (_gate)
            {
                if (!_states.TryGetValue(key, out var state))
                {
                    if (!first) return false;
                    if (_states.Count >= 512)
                    {
                        foreach (var stale in _states.Where(x => at >= x.Value.Last
                            && at - x.Value.Last > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray()) _states.Remove(stale);
                        if (_states.Count >= 512) return false;
                    }
                    _states[key] = new State
                    {
                        FirstPeer = peer, InitialId = id, First = at, Last = at
                    };
                    return false;
                }

                if (at <= state.Last || id == state.InitialId) return false;
                if (first)
                {
                    state.FirstPeer = peer; state.InitialId = id;
                    state.First = state.Last = at;
                    return false;
                }
                _states.Remove(key);
                return at - state.First <= TimeSpan.FromSeconds(60)
                    && !string.Equals(state.FirstPeer, peer, StringComparison.Ordinal);
            }
        }
    }

    internal sealed class Research806AlternatingSizeWindow
    {
        private sealed class State
        {
            internal DateTime First;
            internal DateTime Last;
            internal bool LastLarge;
            internal int Count;
            internal readonly HashSet<Guid> Ids = new();
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, State> _states = new(StringComparer.Ordinal);

        internal bool Observe(string key, Guid id, int size, DateTime at)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty
                || at.Kind != DateTimeKind.Utc) return false;
            var small = size is >= 128 and <= 320;
            var large = size is >= 1000 and <= 4096;
            if (!small && !large) return false;

            lock (_gate)
            {
                if (!_states.TryGetValue(key, out var state))
                {
                    if (_states.Count >= 512)
                    {
                        foreach (var stale in _states.Where(x => at >= x.Value.Last
                            && at - x.Value.Last > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray()) _states.Remove(stale);
                        if (_states.Count >= 512) return false;
                    }
                    state = new State { First = at, Last = at, LastLarge = large, Count = 1 };
                    state.Ids.Add(id);
                    _states[key] = state;
                    return false;
                }
                if (at <= state.Last || state.Ids.Contains(id)) return false;
                var spacing = at - state.Last;
                if (at - state.First > TimeSpan.FromSeconds(90)
                    || spacing < TimeSpan.FromSeconds(2)
                    || spacing > TimeSpan.FromSeconds(20)
                    || state.LastLarge == large)
                {
                    state.First = at; state.Last = at; state.LastLarge = large;
                    state.Count = 1; state.Ids.Clear(); state.Ids.Add(id);
                    return false;
                }
                if (state.Ids.Count >= 8) return false;
                state.Last = at; state.LastLarge = large;
                state.Ids.Add(id); state.Count++;
                if (state.Count != 4) return false;
                _states.Remove(key);
                return true;
            }
        }
    }
}
