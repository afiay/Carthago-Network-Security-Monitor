// SPDX-License-Identifier: MIT
// File: Services/Etw/MsQuicEtwListener.cs
//
// Realtime ETW listener for Microsoft-Windows-MsQuic provider.
// Pulls: connection start/stop, version, (SNI/ALPN if surfaced), optional local/remote 5-tuple.
// Emits lightweight TrafficRecord rows into the same bounded channel pipeline.
//
// NuGet: Microsoft.Diagnostics.Tracing.TraceEvent

using System;
using System.Buffers.Binary;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Services.Flow;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace Carthago.Services.Etw
{
    public sealed class MsQuicEtwListener : IDisposable
    {
        private readonly string _sessionName = $"Carthago-MsQuic-{Environment.ProcessId}";
        private TraceEventSession? _session;
        private Task? _pump;
        private CancellationTokenSource? _cts;
        private ChannelWriter<TrafficRecord>? _writer;

        public bool IsRunning => _pump != null && !_pump.IsCompleted;

        public void Start(ChannelWriter<TrafficRecord> writer, CancellationToken externalCancel = default)
        {
            if (IsRunning) return;

            _writer = writer ?? throw new ArgumentNullException(nameof(writer));
            _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancel);

            try
            {
                _session = new TraceEventSession(_sessionName) { StopOnDispose = true };
                _session.EnableProvider("Microsoft-Windows-MsQuic", TraceEventLevel.Informational, ulong.MaxValue);

                _pump = Task.Run(() =>
                {
                    var src = _session.Source;
                    src.Dynamic.All += OnEvent;
                    try { src.Process(); }
                    catch (ObjectDisposedException) { /* session disposed */ }
                }, _cts.Token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[MsQuicEtw] Failed to start session: {ex.Message}");
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
            if (!string.Equals(ev.ProviderName, "Microsoft-Windows-MsQuic", StringComparison.OrdinalIgnoreCase))
                return;

            var name = ev.EventName?.ToLowerInvariant() ?? string.Empty;
            var now = DateTime.UtcNow;

            // Optional 5-tuple (depends on event)
            var srcIp = FirstString(ev, "LocalAddress", "localAddr", "LocalIP", "SourceAddress", "src", "saddr");
            var dstIp = FirstString(ev, "RemoteAddress", "remoteAddr", "RemoteIP", "DestinationAddress", "dst", "daddr");
            var srcPort = FirstU16(ev, "LocalPort", "srcPort", "sport", "SourcePort");
            var dstPort = FirstU16(ev, "RemotePort", "dstPort", "dport", "DestinationPort");

            var version = FirstString(ev, "QuicVersion", "Version", "version", "HandshakeTlsVersion");
            var alpn = FirstString(ev, "ALPN", "alpn");
            var sni = FirstString(ev, "SNI", "ServerName", "server_name");

            // MsQuic often surfaces CIDs (original/destination). Hash to non-PII tag.
            var cidHash = HashCid(
                FirstBytes(ev, "ConnectionID", "CID", "DestCID", "SourceCID", "ConnectionId", "dcid", "scid"),
                FirstString(ev, "ConnectionID", "CID", "DestCID", "SourceCID", "ConnectionId", "dcid", "scid")
            );

            string? evtType = name.Contains("start") ? "Start"
                             : name.Contains("stop") ? "Stop"
                             : name.Contains("handshake") && name.Contains("complete") ? "HandshakeComplete"
                             : name.Contains("handshake") ? "Handshake"
                             : name.Contains("connected") ? "Connected"
                             : name.Contains("stats") ? "Stats"
                             : ev.Opcode == TraceEventOpcode.Start ? "Start"
                             : ev.Opcode == TraceEventOpcode.Stop ? "Stop"
                             : null;

            // Emit a minimal record
            var rec = new TrafficRecord
            {
                Timestamp = now.ToString("HH:mm:ss"),
                Protocol = "UDP",
                ApplicationProtocol = "QUIC",
                IsQuic = true,

                Source = srcIp,
                Destination = dstIp,
                SourcePort = srcPort,
                DestinationPort = dstPort,

                QuicVersion = string.IsNullOrWhiteSpace(version) ? null : version,
                QuicAlpn = string.IsNullOrWhiteSpace(alpn) ? null : alpn,
                Sni = string.IsNullOrWhiteSpace(sni) ? null : sni,
                QuicConnectionIdHash = cidHash,

                Info = evtType != null ? $"[MsQuic {evtType} v={version ?? "-"} alpn={alpn ?? "-"} sni={sni ?? "-"}]" : "[MsQuic]",
            };

            if (rec.DestinationPort.HasValue)
                rec.ApplicationService = PortServiceResolver.GetServiceName(rec.DestinationPort.Value, "UDP");

            _ = _writer?.TryWrite(rec);
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

        private static byte[]? FirstBytes(TraceEvent ev, params string[] names)
        {
            if (!TryGetPayload(ev, out var obj, names) || obj == null) return null;

            try
            {
                switch (obj)
                {
                    case byte[] b when b.Length > 0:
                        return b;
                    case string s when !string.IsNullOrWhiteSpace(s):
                        var hex = new string(s.Where(Uri.IsHexDigit).ToArray());
                        if (hex.Length >= 2 && hex.Length % 2 == 0)
                        {
                            var arr = new byte[hex.Length / 2];
                            for (int i = 0; i < arr.Length; i++)
                                arr[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                            return arr;
                        }
                        // fallback: ASCII bytes
                        return Encoding.ASCII.GetBytes(s);
                }
            }
            catch { /* ignore */ }
            return null;
        }

        private static string? HashCid(byte[]? cidBytes, string? cidFallback)
        {
            try
            {
                byte[]? data = cidBytes ?? (cidFallback != null ? Encoding.ASCII.GetBytes(cidFallback) : null);
                if (data == null || data.Length == 0) return null;

                using var sha = SHA256.Create();
                var h = sha.ComputeHash(data);

                // Short non-PII tag: first 8 bytes big-endian
                Span<byte> first = h.AsSpan(0, 8);
                ulong v = BinaryPrimitives.ReadUInt64BigEndian(first);
                return v.ToString("X16");
            }
            catch { return null; }
        }

        public void Dispose() => Stop();
    }
}
