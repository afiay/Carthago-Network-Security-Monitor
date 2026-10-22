// SPDX-License-Identifier: MIT
// File: Services/Etw/TcpIpEtwListener.cs
//
// Realtime ETW listener for Microsoft-Windows-TCPIP provider.
// Targets SYN / SYN-ACK timings (JA4T/JA4TS seeds) + latency (JA4L/JA4LS).
//
// NuGet: Microsoft.Diagnostics.Tracing.TraceEvent

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.Flow;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace Carthago.Services.Etw
{
    public sealed class TcpIpEtwListener : IDisposable
    {
        private readonly string _sessionName = $"Carthago-TCPIP-{Environment.ProcessId}";
        private TraceEventSession? _session;
        private Task? _pump;
        private CancellationTokenSource? _cts;

        public bool IsRunning => _pump != null && !_pump.IsCompleted;

        public void Start(CancellationToken externalCancel = default)
        {
            if (IsRunning) return;

            _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancel);

            try
            {
                _session = new TraceEventSession(_sessionName) { StopOnDispose = true };
                _session.EnableProvider("Microsoft-Windows-TCPIP", TraceEventLevel.Informational, ulong.MaxValue);

                _pump = Task.Run(() =>
                {
                    var src = _session.Source;
                    src.Dynamic.All += OnEvent;
                    try { src.Process(); }
                    catch (ObjectDisposedException) { /* disposed */ }
                }, _cts.Token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[TcpIpEtw] Failed to start session: {ex.Message}");
                Stop();
            }
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { /* ignore */ }
            try { _session?.Dispose(); } catch { /* ignore */ }
            try { _pump?.Wait(500); } catch { /* ignore */ }
            _pump = null;
            _session = null;
            _cts?.Dispose();
            _cts = null;
        }

        private void OnEvent(TraceEvent ev)
        {
            if (!string.Equals(ev.ProviderName, "Microsoft-Windows-TCPIP", StringComparison.OrdinalIgnoreCase))
                return;

            var name = ev.EventName?.ToLowerInvariant() ?? string.Empty;

            var src = FirstString(ev, "saddr", "src", "SourceAddress", "LocalAddress", "localAddr");
            var dst = FirstString(ev, "daddr", "dst", "DestinationAddress", "RemoteAddress", "remoteAddr");
            var sport = FirstU16(ev, "sport", "srcPort", "SourcePort", "LocalPort");
            var dport = FirstU16(ev, "dport", "dstPort", "DestinationPort", "RemotePort");

            // Extract TCP flags when surfaced; else infer from name/opcode
            var flags = FirstInt(ev, "flags", "tcpFlags", "TcpFlags");
            bool syn = (flags & 0x02) != 0;
            bool ack = (flags & 0x10) != 0;
            bool rst = (flags & 0x04) != 0;

            if (!syn && !ack)
            {
                if (name.Contains("synack") || (name.Contains("accept") && name.Contains("syn")))
                {
                    syn = true; ack = true;
                }
                else if (name.Contains("syn"))
                {
                    syn = true; ack = false;
                }
                if (name.Contains("rst")) rst = true;
            }

            var now = DateTime.UtcNow;

            if (!string.IsNullOrWhiteSpace(src) &&
                !string.IsNullOrWhiteSpace(dst) &&
                sport.HasValue && dport.HasValue)
            {
                var fk = new FlowKey(src!, sport!.Value, dst!, dport!.Value, "TCP");

                if (syn && !ack)
                {
                    // Client SYN observed
                    LatencyTracker.NoteSyn(fk, now);
                    // Hook JA4T builder here if implemented (e.g., FromTcpSyn)
                }
                else if (syn && ack)
                {
                    // Server SYN-ACK observed
                    LatencyTracker.NoteSynAck(fk.Reverse(), now);
                    // Hook JA4TS builder here if implemented (e.g., FromTcpSynAck)
                }
                else if (rst)
                {
                    // Optional: LatencyTracker.NoteRst(fk, now);
                }
            }
        }

        // -------------------------
        // Robust payload helpers
        // -------------------------
        private static bool TryGetPayload(TraceEvent ev, out object? value, params string[] candidates)
        {
            value = null;
            var names = ev.PayloadNames ?? Array.Empty<string>();
            foreach (var cand in candidates)
            {
                var match = names.FirstOrDefault(n => string.Equals(n, cand, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    try { value = ev.PayloadByName(match); return true; }
                    catch { /* ignore and continue */ }
                }
            }
            return false;
        }

        private static string? FirstString(TraceEvent ev, params string[] names)
        {
            if (TryGetPayload(ev, out var obj, names) && obj != null)
                return obj.ToString();
            return null;
        }

        private static ushort? FirstU16(TraceEvent ev, params string[] names)
        {
            if (!TryGetPayload(ev, out var obj, names) || obj == null) return null;

            try
            {
                return obj switch
                {
                    ushort u16 => u16,
                    short i16 when i16 >= 0 => (ushort)i16,
                    int i32 when i32 >= 0 && i32 <= ushort.MaxValue => (ushort)i32,
                    uint u32 when u32 <= ushort.MaxValue => (ushort)u32,
                    long i64 when i64 >= 0 && i64 <= ushort.MaxValue => (ushort)i64,
                    string s when ushort.TryParse(s, out var p) => p,
                    _ => (ushort?)null
                };
            }
            catch { return null; }
        }

        private static int FirstInt(TraceEvent ev, params string[] names)
        {
            if (!TryGetPayload(ev, out var obj, names) || obj == null) return 0;

            try
            {
                return obj switch
                {
                    int i => i,
                    uint u when u <= int.MaxValue => (int)u,
                    long l when l >= int.MinValue && l <= int.MaxValue => (int)l,
                    string s when int.TryParse(s, out var p) => p,
                    _ => 0
                };
            }
            catch { return 0; }
        }

        public void Dispose() => Stop();
    }
}
