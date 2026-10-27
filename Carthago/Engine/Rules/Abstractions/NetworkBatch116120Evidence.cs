// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // Narrow evidence contracts for R116-R120. Info describes a decoded action
    // only after transport and parser-attributed protocol fields agree.
    internal static class NetworkBatch116120Evidence
    {
        private static readonly Regex TelnetPrompt = new(
            @"\b(?:login|username|password)\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex ModbusWriteFunction = new(
            @"\b(?:function\s+(?:0?[56]|15|16)\b|write\s+(?:(?:single|multiple)\s+)?(?:coil|register)s?\b)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private static bool Same(string? actual, string expected)
            => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);

        private static bool ValidEndpoints(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty || !NetworkBatch076080Evidence.ValidTime(context)
                || r.IsQuic || r.IcmpTypeCode.HasValue || r.DnsQname != null
                || r.DnsAnswers != null || r.DnsIsResponse
                || !IPAddress.TryParse(r.Source, out var source)
                || !IPAddress.TryParse(r.Destination, out var destination)
                || source.Equals(destination)
                || source.AddressFamily != destination.AddressFamily
                || r.IpVersion == 4 && source.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && source.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
                || r.IpVersion is not (null or 4 or 6))
                return false;
            return true;
        }

        internal static bool SsdpDiscovery(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!ValidEndpoints(context) || !r.IsUdp || r.IsTcp || r.TcpFlags.HasValue
                || !Same(r.Protocol, "UDP") && !Same(r.Protocol, "SSDP")
                || r.HttpMethod != null || r.HttpUri != null || r.HttpRequestHeaders != null
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "SSDP") && !Same(r.ApplicationProtocol, "UPnP") && !Same(r.ApplicationProtocol, "UDP")
                || r.ApplicationService != null && !Same(r.ApplicationService, "SSDP") && !Same(r.ApplicationService, "UPnP")
                || r.DestinationPort != 1900 && !Same(r.ApplicationProtocol, "SSDP") && !Same(r.ApplicationService, "SSDP"))
                return false;
            // An unrelated packet's Info string must not create a protocol classification.
            if (!Same(r.ApplicationProtocol, "SSDP") && !Same(r.ApplicationProtocol, "UPnP")
                && !Same(r.ApplicationService, "SSDP") && !Same(r.ApplicationService, "UPnP"))
                return false;
            var info = r.Info ?? "";
            return info.Length <= 1024
                && (info.Contains("M-SEARCH", StringComparison.OrdinalIgnoreCase)
                    || info.Contains("ssdp:discover", StringComparison.OrdinalIgnoreCase));
        }

        internal static bool TelnetAuthentication(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!ValidEndpoints(context) || !r.IsTcp || r.IsUdp || r.DestinationPort != 23
                || !Same(r.Protocol, "TCP") && !Same(r.Protocol, "Telnet")
                || r.HttpMethod != null || r.HttpUri != null || r.HttpRequestHeaders != null
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "Telnet") && !Same(r.ApplicationProtocol, "TCP")
                || r.ApplicationService != null && !Same(r.ApplicationService, "Telnet")
                || !Same(r.ApplicationProtocol, "Telnet") && !Same(r.ApplicationService, "Telnet"))
                return false;
            var info = r.Info ?? "";
            return info.Length <= 1024 && TelnetPrompt.IsMatch(info);
        }

        internal static bool CredentialTransport(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!ValidEndpoints(context) || r.IsUdp || Same(r.Protocol, "UDP")
                || r.IsTcp && r.IsUdp || r.HttpMethod != null && r.DestinationPort == 23)
                return false;
            // Existing capture/replay HTTP records do not all carry an explicit
            // IsTcp flag; reject contradictory transport, never synthesize TCP.
            if (r.DestinationPort == 23)
                return r.IsTcp && (Same(r.Protocol, "TCP") || Same(r.Protocol, "Telnet"))
                    && r.HttpMethod == null && r.HttpRequestHeaders == null;
            if (!string.IsNullOrWhiteSpace(r.Sni) && !string.IsNullOrWhiteSpace(r.HttpHost)
                && !Same(r.Sni, r.HttpHost))
                return false;
            return true;
        }

        internal static bool CameraSource(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!ValidEndpoints(context) || r.IsTcp == r.IsUdp
                || r.HttpMethod != null && r.IsUdp
                || r.ApplicationProtocol != null && Same(r.ApplicationProtocol, "DNS")
                || r.ApplicationService != null && Same(r.ApplicationService, "DNS"))
                return false;
            if (r.IsTcp && !(Same(r.Protocol, "TCP") || Same(r.Protocol, "RTSP") || Same(r.Protocol, "HTTP")))
                return false;
            if (r.IsUdp && !(Same(r.Protocol, "UDP") || Same(r.Protocol, "RTSP")))
                return false;
            var process = r.ProcessName ?? "";
            // Device identity must not come solely from attacker-controlled
            // packet Info or an arbitrary external destination hostname.
            return process.Contains("camera", StringComparison.OrdinalIgnoreCase)
                || process.Contains("nvr", StringComparison.OrdinalIgnoreCase)
                || process.Contains("dvr", StringComparison.OrdinalIgnoreCase)
                || process.Contains("onvif", StringComparison.OrdinalIgnoreCase)
                || Same(r.ApplicationProtocol, "RTSP") || Same(r.ApplicationService, "RTSP")
                || Same(r.ApplicationProtocol, "ONVIF") || Same(r.ApplicationService, "ONVIF");
        }

        internal static bool DirectRtsp(TrafficRecord record)
            => (record.DestinationPort is 554 or 8554 || record.SourcePort is 554 or 8554)
                && (Same(record.ApplicationProtocol, "RTSP")
                    || Same(record.ApplicationService, "RTSP")
                    || Same(record.Protocol, "RTSP"));

        internal static bool ModbusTcp(RuleEvaluationContext context)
        {
            var r = context.Record;
            return ValidEndpoints(context) && r.IsTcp && !r.IsUdp
                && r.DestinationPort == 502
                && (Same(r.Protocol, "TCP") || Same(r.Protocol, "Modbus"))
                && (Same(r.ApplicationProtocol, "Modbus") || Same(r.ApplicationService, "Modbus"))
                && (r.ApplicationProtocol == null || Same(r.ApplicationProtocol, "Modbus") || Same(r.ApplicationProtocol, "TCP"))
                && (r.ApplicationService == null || Same(r.ApplicationService, "Modbus"))
                && r.HttpMethod == null && r.HttpUri == null && r.HttpRequestHeaders == null;
        }

        internal static bool ModbusWrite(string? info)
            => !string.IsNullOrWhiteSpace(info) && info.Length <= 1024
                && ModbusWriteFunction.IsMatch(info);
    }

    // Per-detector, bounded, duplicate-resistant observations. No packet text
    // or host credentials are retained; state is scoped to one detector instance.
    internal sealed class NetworkBatch116120Window
    {
        private sealed class Window
        {
            internal readonly List<(DateTime At, Guid Id)> Events = new();
            internal DateTime Last;
        }

        private readonly Dictionary<string, Window> _windows = new(StringComparer.Ordinal);
        private readonly object _gate = new();

        internal int Count(string key, Guid id, DateTime now, TimeSpan duration)
        {
            lock (_gate)
            {
                foreach (var expired in _windows.Where(item => now - item.Value.Last > duration)
                    .Select(item => item.Key).ToArray()) _windows.Remove(expired);
                if (!_windows.TryGetValue(key, out var window))
                {
                    if (_windows.Count >= 1024)
                        _windows.Remove(_windows.OrderBy(item => item.Value.Last).First().Key);
                    _windows[key] = window = new Window();
                }
                window.Events.RemoveAll(item => now - item.At > duration);
                // Replays and late arrivals must not manufacture independent
                // observations; duplicate packet identity never increases count.
                if (now < window.Last || window.Events.Any(item => item.Id == id))
                    return window.Events.Count;
                window.Last = now;
                if (window.Events.Count >= 5000) window.Events.RemoveAt(0);
                window.Events.Add((now, id));
                return window.Events.Count;
            }
        }
    }
}
