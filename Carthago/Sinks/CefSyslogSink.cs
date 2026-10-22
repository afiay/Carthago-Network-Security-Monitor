// SPDX-License-Identifier: MIT
// File: Sinks/CefSyslogSink.cs
using System;
using System.IO;              // <-- needed for Stream
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Sinks
{
    public sealed class CefSyslogSink : IDetectionSink
    {
        private readonly string _host;
        private readonly int _port;
        private readonly bool _useTls;
        private TcpClient? _client;
        private Stream? _stream;

        public CefSyslogSink(string host, int port, bool useTls = true)
        {
            _host = host;
            _port = port;
            _useTls = useTls;
        }

        public async Task EmitAsync(DetectionEvent e, CancellationToken ct = default)
        {
            await EnsureConnectedAsync(ct).ConfigureAwait(false);
            var msg = BuildCef(e) + "\n";
            var bytes = Encoding.UTF8.GetBytes(msg);
            await _stream!.WriteAsync(bytes.AsMemory(0, bytes.Length), ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }

        private async Task EnsureConnectedAsync(CancellationToken ct)
        {
            if (_client is { Connected: true } && _stream is not null) return;

            _client?.Dispose();
            _client = new TcpClient();
            await _client.ConnectAsync(_host, _port, ct).ConfigureAwait(false);

            var net = _client.GetStream();
            if (_useTls)
            {
                var tls = new SslStream(net, leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (_, __, ___, sslPolicyErrors) =>
                    {
                        if (sslPolicyErrors == SslPolicyErrors.None) return true;
                        Console.Error.WriteLine($"[CefSyslogSink] TLS certificate validation failed for {_host}:{_port}: {sslPolicyErrors}");
                        return false;
                    });
                await tls.AuthenticateAsClientAsync(_host).ConfigureAwait(false);
                _stream = tls;
            }
            else
            {
                _stream = net;
            }
        }

        private static string MapSeverity(SeverityLevel s) => s switch
        {
            SeverityLevel.Info => "3",        // INFO
            SeverityLevel.Low => "4",         // WARNING
            SeverityLevel.Medium => "6",      // ERROR
            SeverityLevel.High => "8",        // CRITICAL
            SeverityLevel.Critical => "10",   // EMERGENCY
            _ => "5"
        };

        private static string Esc(string? v) => (v ?? "-").Replace("\\", "\\\\").Replace("=", "\\=");

        private static string BuildCef(DetectionEvent e)
        {
            // CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|Signature|Name|Severity|extensions
            var header = $"CEF:0|Carthago|RuleEngine|1.0|{Esc(e.RuleId)}|{Esc(e.Description)}|{MapSeverity(e.Severity)}";
            var ext =
                $" src={Esc(e.SourceIp)} dst={Esc(e.DestinationIp)} dpt={(e.DestinationPort?.ToString() ?? "-")} proto={Esc(e.Protocol)}" +
                $" cnt={e.Count} flexNumber1={e.WindowSeconds} flexString1={Esc(e.SensitivityAtTrigger.ToString())}";
            return header + "|" + ext.Trim();
        }

        public void Dispose()
        {
            try { _stream?.Dispose(); } catch { }
            try { _client?.Dispose(); } catch { }
        }
    }
}
