// File: Capture/EtwCapture.cs
// SPDX-License-Identifier: MIT

using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Carthago.Models;
using Microsoft.Diagnostics.Tracing.Parsers;          // ✅ for KernelTraceEventParser
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;    // ✅ for TcpIpTraceData / UdpIpTraceData
using Microsoft.Diagnostics.Tracing.Session;

namespace Carthago.Capture
{
    /// <summary>
    /// ETW-based capture source (kernel TCP/UDP events). Works without Npcap.
    /// Emits TrafficRecord items into the shared bounded channel.
    /// </summary>
    public sealed class EtwCapture : ICaptureSource, IDisposable
    {
        private TraceEventSession? _session;
        private readonly Channel<TrafficRecord> _channel;
        private readonly CancellationTokenSource _cts = new();

        public string Name => "ETW Kernel Capture";
        public bool IsRunning { get; private set; }

        public EtwCapture(Channel<TrafficRecord> channel)
        {
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
        }

        public Task StartAsync()
        {
            if (IsRunning) return Task.CompletedTask;
            IsRunning = true;

            return Task.Run(() =>
            {
                try
                {
                    using var session = new TraceEventSession("CarthagoETW");
                    _session = session;

                    // ✅ Use the parser in Microsoft.Diagnostics.Tracing.Parsers (no ".Kernel" here)
                    session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                    // TCP events
                    session.Source.Kernel.TcpIpRecv += data =>
                    {
                        var rec = new TrafficRecord
                        {
                            Timestamp = DateTime.UtcNow.ToString("o"),
                            Protocol = "TCP",
                            Source = data.saddr.ToString(),
                            Destination = data.daddr.ToString(),
                            SourcePort = data.sport,
                            DestinationPort = data.dport
                        };
                        _channel.Writer.TryWrite(rec);
                    };

                    session.Source.Kernel.TcpIpSend += data =>
                    {
                        var rec = new TrafficRecord
                        {
                            Timestamp = DateTime.UtcNow.ToString("o"),
                            Protocol = "TCP",
                            Source = data.saddr.ToString(),
                            Destination = data.daddr.ToString(),
                            SourcePort = data.sport,
                            DestinationPort = data.dport
                        };
                        _channel.Writer.TryWrite(rec);
                    };

                    // UDP events
                    session.Source.Kernel.UdpIpRecv += data =>
                    {
                        var rec = new TrafficRecord
                        {
                            Timestamp = DateTime.UtcNow.ToString("o"),
                            Protocol = "UDP",
                            Source = data.saddr.ToString(),
                            Destination = data.daddr.ToString(),
                            SourcePort = data.sport,
                            DestinationPort = data.dport
                        };
                        _channel.Writer.TryWrite(rec);
                    };

                    session.Source.Kernel.UdpIpSend += data =>
                    {
                        var rec = new TrafficRecord
                        {
                            Timestamp = DateTime.UtcNow.ToString("o"),
                            Protocol = "UDP",
                            Source = data.saddr.ToString(),
                            Destination = data.daddr.ToString(),
                            SourcePort = data.sport,
                            DestinationPort = data.dport
                        };
                        _channel.Writer.TryWrite(rec);
                    };

                    // Blocks until disposed
                    session.Source.Process();
                }
                catch (OperationCanceledException)
                {
                    // normal shutdown
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ETW] StartAsync error: {ex}");
                }
                finally
                {
                    IsRunning = false;
                }
            }, _cts.Token);
        }

        public Task StopAsync()
        {
            try
            {
                if (!IsRunning) return Task.CompletedTask;

                _cts.Cancel();
                _session?.Dispose(); // breaks Source.Process()
                _session = null;
                IsRunning = false;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ETW] StopAsync error: {ex}");
            }

            return Task.CompletedTask;
        }

        public void Dispose()
        {
            StopAsync();
            _cts.Dispose();
        }
    }
}
