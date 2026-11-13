// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;

namespace Carthago.Services.Flow
{
    /// <summary>Session-owned, bounded latency observations. No network or wall-clock dependency.</summary>
    internal sealed class LatencyTrackerState
    {
        internal const int MaxFlows = 16384;
        private sealed class T
        {
            public DateTime? Syn;
            public DateTime? SynAck;
            public DateTime? FirstDataClient;
            public DateTime? FirstDataServer;
        }
        private readonly object _gate = new();
        private readonly Dictionary<FlowKey,T> _t = new();
        private readonly Queue<FlowKey> _order = new();
        internal int ActiveFlowCount { get { lock (_gate) return _t.Count; } }

        private T GetOrAdd(FlowKey fk)
        {
            if (_t.TryGetValue(fk,out var existing)) return existing;
            if (_t.Count >= MaxFlows) _t.Remove(_order.Dequeue());
            var state = new T();
            _t.Add(fk,state);
            _order.Enqueue(fk);
            return state;
        }
        internal void NoteSyn(FlowKey fk, DateTime ts)
        { lock (_gate) GetOrAdd(fk).Syn = ts; }
        internal void NoteSynAck(FlowKey fk, DateTime ts)
        { lock (_gate) GetOrAdd(fk).SynAck = ts; }
        internal void NoteFirstDataClient(FlowKey fk, DateTime ts)
        { lock (_gate) GetOrAdd(fk).FirstDataClient ??= ts; }
        internal void NoteFirstDataServer(FlowKey fk, DateTime ts)
        { lock (_gate) GetOrAdd(fk).FirstDataServer ??= ts; }

        internal (string ja4l,string ja4ls) GetLatencyFingerprints(FlowKey clientFk)
        {
            lock (_gate)
            {
                if (!_t.TryGetValue(clientFk,out var s)) return (string.Empty,string.Empty);
                double rtt = -1, ttfb = -1;
                if (s.Syn.HasValue && s.SynAck.HasValue) rtt = (s.SynAck.Value - s.Syn.Value).TotalMilliseconds;
                if (s.SynAck.HasValue && s.FirstDataServer.HasValue) ttfb = (s.FirstDataServer.Value - s.SynAck.Value).TotalMilliseconds;
                static string Bin(double x) =>
                    x < 0 ? "na" :
                    x < 1 ? "0-1" :
                    x < 5 ? "1-5" :
                    x < 10 ? "5-10" :
                    x < 20 ? "10-20" :
                    x < 50 ? "20-50" :
                    x < 100 ? "50-100" :
                    x < 200 ? "100-200" : "200+";
                var client = $"rtt:{Bin(rtt)};ttfb:{Bin(ttfb)}";
                return (client,client);
            }
        }
        internal void Clear()
        {
            lock (_gate) { _t.Clear(); _order.Clear(); }
        }
    }

    /// <summary>Legacy process-wide latency facade; retained for existing callers.</summary>
    public static class LatencyTracker
    {
        internal static LatencyTrackerState Shared { get; } = new();
        public static void NoteSyn(FlowKey fk,DateTime ts) => Shared.NoteSyn(fk,ts);
        public static void NoteSynAck(FlowKey fk,DateTime ts) => Shared.NoteSynAck(fk,ts);
        public static void NoteFirstDataClient(FlowKey fk,DateTime ts) => Shared.NoteFirstDataClient(fk,ts);
        public static void NoteFirstDataServer(FlowKey fk,DateTime ts) => Shared.NoteFirstDataServer(fk,ts);
        public static (string ja4l,string ja4ls) GetLatencyFingerprints(FlowKey clientFk) => Shared.GetLatencyFingerprints(clientFk);
    }
}
