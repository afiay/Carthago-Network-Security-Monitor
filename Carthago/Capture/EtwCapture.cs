
// File: Capture/EtwCapture.cs
// SPDX-License-Identifier: MIT

using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Carthago.Models;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace Carthago.Capture
{
    public sealed class EtwCapture : ICaptureSource
    {
        private const string SessionName = "CarthagoETW";

        private sealed class CaptureRun
        {
            public Task Completion { get; set; } =
                System.Threading.Tasks.Task.CompletedTask;

            public TraceEventSession? Session;
            public int StopRequested;
        }

        private readonly Channel<TrafficRecord> _channel;
        private readonly object _lifecycleLock = new();

        private CaptureRun? _run;
        private int _running;
        private int _disposed;

        private long _eventsObserved;
        private long _eventsPublished;
        private long _eventsDropped;
        private string? _lastError;

        public EtwCapture(Channel<TrafficRecord> channel)
        {
            _channel = channel ??
                throw new ArgumentNullException(nameof(channel));
        }

        public string Name => "ETW Kernel Capture";

        public bool IsRunning =>
            Volatile.Read(ref _running) != 0;

        public long EventsObserved =>
            Interlocked.Read(ref _eventsObserved);

        public long EventsPublished =>
            Interlocked.Read(ref _eventsPublished);

        public long EventsDropped =>
            Interlocked.Read(ref _eventsDropped);

        public string? LastError =>
            Volatile.Read(ref _lastError);

        // Raised from the background capture thread.
        public event Action<Exception>? CaptureFaulted;

        public Task StartAsync()
        {
            lock (_lifecycleLock)
            {
                if (_disposed != 0)
                    throw new ObjectDisposedException(
                        nameof(EtwCapture));

                if (_run is not null)
                {
                    if (Volatile.Read(
                            ref _run.StopRequested) != 0)
                        throw new InvalidOperationException(
                            "ETW capture is stopping; wait for " +
                            "StopAsync before restarting.");

                    return _run.Completion;
                }

                Volatile.Write(ref _lastError, null);

                var run = new CaptureRun();
                _run = run;

                run.Completion =
                    Task.Run(() => CaptureLoop(run));

                return run.Completion;
            }
        }

        private void CaptureLoop(CaptureRun run)
        {
            try
            {
                var session =
                    new TraceEventSession(SessionName);

                lock (_lifecycleLock)
                {
                    if (Volatile.Read(
                            ref run.StopRequested) != 0)
                    {
                        session.Dispose();
                        return;
                    }

                    run.Session = session;
                }

                session.Source.Kernel.TcpIpRecv += data =>
                    Publish(
                        "TCP",
                        data.saddr.ToString(),
                        data.daddr.ToString(),
                        data.sport,
                        data.dport);

                session.Source.Kernel.TcpIpSend += data =>
                    Publish(
                        "TCP",
                        data.saddr.ToString(),
                        data.daddr.ToString(),
                        data.sport,
                        data.dport);

                session.Source.Kernel.UdpIpRecv += data =>
                    Publish(
                        "UDP",
                        data.saddr.ToString(),
                        data.daddr.ToString(),
                        data.sport,
                        data.dport);

                session.Source.Kernel.UdpIpSend += data =>
                    Publish(
                        "UDP",
                        data.saddr.ToString(),
                        data.daddr.ToString(),
                        data.sport,
                        data.dport);

                if (Volatile.Read(
                        ref run.StopRequested) != 0)
                    return;

                session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP);

                if (Volatile.Read(
                        ref run.StopRequested) != 0)
                    return;

                Volatile.Write(ref _running, 1);

                // Blocks while the ETW session is active.
                session.Source.Process();

                if (Volatile.Read(
                        ref run.StopRequested) == 0)
                    throw new InvalidOperationException(
                        "ETW session ended without a stop request.");
            }
            catch (Exception ex)
            {
                if (Volatile.Read(
                        ref run.StopRequested) == 0)
                {
                    Volatile.Write(ref _lastError, ex.Message);

                    Console.Error.WriteLine(
                        $"[ETW] Capture failed: " +
                        $"{ex.GetType().Name}: {ex.Message}");

                    try
                    {
                        CaptureFaulted?.Invoke(ex);
                    }
                    catch (Exception observerError)
                    {
                        Console.Error.WriteLine(
                            $"[ETW] Fault observer failed: " +
                            observerError.Message);
                    }

                    throw;
                }
            }
            finally
            {
                Volatile.Write(ref _running, 0);

                var session =
                    Interlocked.Exchange(ref run.Session, null);

                if (session is not null)
                {
                    try
                    {
                        session.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine(
                            $"[ETW] Session cleanup failed: " +
                            ex.Message);
                    }
                }

                lock (_lifecycleLock)
                {
                    if (ReferenceEquals(_run, run))
                        _run = null;
                }
            }
        }

        private void Publish(
            string protocol,
            string source,
            string destination,
            int sourcePort,
            int destinationPort)
        {
            Interlocked.Increment(ref _eventsObserved);

            try
            {
                var record = new TrafficRecord
                {
                    Timestamp = DateTime.UtcNow.ToString("o"),
                    Protocol = protocol,
                    Source = source,
                    Destination = destination,
                    SourcePort = sourcePort,
                    DestinationPort = destinationPort,
                    IsTcp = protocol == "TCP",
                    IsUdp = protocol == "UDP"
                };

                if (_channel.Writer.TryWrite(record))
                {
                    Interlocked.Increment(
                        ref _eventsPublished);
                }
                else
                {
                    RecordDrop();
                }
            }
            catch (Exception ex)
            {
                RecordDrop();

                Console.Error.WriteLine(
                    $"[ETW] Failed to publish an event: " +
                    ex.Message);
            }
        }

        private void RecordDrop()
        {
            var dropped =
                Interlocked.Increment(ref _eventsDropped);

            // Avoid excessive logging under heavy traffic.
            if (dropped == 1 || dropped % 1000 == 0)
            {
                Console.Error.WriteLine(
                    $"[ETW] {dropped} event(s) dropped: " +
                    "consumer channel is full or closed.");
            }
        }

        public async Task StopAsync()
        {
            CaptureRun? run;

            lock (_lifecycleLock)
            {
                run = _run;

                if (run is null)
                    return;

                Volatile.Write(
                    ref run.StopRequested, 1);
            }

            var session =
                Interlocked.Exchange(ref run.Session, null);

            if (session is not null)
            {
                try
                {
                    session.Dispose();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        $"[ETW] Stop failed: {ex.Message}");
                }
            }

            await run.Completion.ConfigureAwait(false);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            try
            {
                StopAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"[ETW] Dispose encountered an error: " +
                    ex.Message);
            }
        }
    }
}
