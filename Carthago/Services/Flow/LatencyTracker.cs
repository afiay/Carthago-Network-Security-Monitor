// SPDX-License-Identifier: MIT
// File: Services/Flow/LatencyTracker.cs

using System;
using System.Collections.Concurrent;

namespace Carthago.Services.Flow
{
    /// <summary>Tracks SYN/SYN-ACK/first-data times and returns compact latency bins (JA4L/JA4LS-like).</summary>
    public static class LatencyTracker
    {
        private sealed class T
        {
            public DateTime? Syn;
            public DateTime? SynAck;
            public DateTime? FirstDataClient;
            public DateTime? FirstDataServer;
        }

        private static readonly ConcurrentDictionary<FlowKey, T> _t = new();

        public static void NoteSyn(FlowKey fk, DateTime ts)
        {
            var s = _t.GetOrAdd(fk, _ => new T());
            s.Syn = ts;
        }

        public static void NoteSynAck(FlowKey fk, DateTime ts)
        {
            var s = _t.GetOrAdd(fk, _ => new T());
            s.SynAck = ts;
        }

        public static void NoteFirstDataClient(FlowKey fk, DateTime ts)
        {
            var s = _t.GetOrAdd(fk, _ => new T());
            s.FirstDataClient ??= ts;
        }

        public static void NoteFirstDataServer(FlowKey fk, DateTime ts)
        {
            var s = _t.GetOrAdd(fk, _ => new T());
            s.FirstDataServer ??= ts;
        }

        public static (string ja4l, string ja4ls) GetLatencyFingerprints(FlowKey clientFk)
        {
            if (!_t.TryGetValue(clientFk, out var s)) return (string.Empty, string.Empty);

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
            var server = client;
            return (client, server);
        }
    }
}
