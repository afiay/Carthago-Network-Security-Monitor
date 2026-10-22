// SPDX-License-Identifier: MIT
// File: Services/Cisco/CiscoSyslogListener.cs

using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services.Cisco
{
    /// <summary>
    /// Very small UDP syslog listener focused on Cisco devices.
    /// It listens on the given UDP port and raises MessageReceived for each line.
    /// </summary>
    public sealed class CiscoSyslogListener : IDisposable
    {
        private readonly int _port;
        private UdpClient? _client;
        private CancellationTokenSource? _cts;

        public event Action<CiscoSyslogEvent>? MessageReceived;

        public CiscoSyslogListener(int port)
        {
            _port = port;
        }

        public void Start()
        {
            if (_client != null)
                return; // already running

            _cts = new CancellationTokenSource();

            // Bind on all IPv4 addresses on the chosen port
            _client = new UdpClient(new IPEndPoint(IPAddress.Any, _port))
            {
                EnableBroadcast = true
            };

            _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
        }

        private async Task ReceiveLoopAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    UdpReceiveResult result = await _client!
                        .ReceiveAsync(ct)
                        .ConfigureAwait(false);

                    string raw;
                    try
                    {
                        raw = Encoding.UTF8.GetString(result.Buffer);
                    }
                    catch
                    {
                        raw = Encoding.ASCII.GetString(result.Buffer);
                    }

                    var evt = ParseSyslog(raw, result.RemoteEndPoint.Address.ToString());

                    MessageReceived?.Invoke(evt);
                }
            }
            catch (OperationCanceledException)
            {
                // normal on stop
            }
            catch (ObjectDisposedException)
            {
                // normal when client is disposed
            }
            catch
            {
                // swallow other errors; in production you'd probably log this
            }
        }

        private static CiscoSyslogEvent ParseSyslog(string raw, string host)
        {
            var evt = new CiscoSyslogEvent
            {
                Timestamp = DateTime.UtcNow,
                Host = host,
                Raw = raw
            };

            // Extremely small RFC3164/5424-style parser:
            // If message starts with <PRI>, derive facility/severity.
            string text = raw.Trim();
            if (text.StartsWith("<"))
            {
                int end = text.IndexOf('>');
                if (end > 1 && int.TryParse(text.AsSpan(1, end - 1), out int pri))
                {
                    int facility = pri / 8;
                    int severity = pri % 8;
                    evt.Facility = facility.ToString();
                    evt.Severity = severity.ToString();
                    text = text[(end + 1)..].TrimStart();
                }
            }

            // Cisco often has timestamp and %-style prefixes; we keep as-is for now.
            evt.Message = text;

            return evt;
        }

        public void Stop()
        {
            _cts?.Cancel();
            _cts = null;

            _client?.Dispose();
            _client = null;
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
