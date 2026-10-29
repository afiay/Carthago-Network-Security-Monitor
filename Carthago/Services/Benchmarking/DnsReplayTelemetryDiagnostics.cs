// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Non-authoritative, read-only replay diagnostics for structured DNS
    /// input. Stable codes, never IPs, QNAMEs, credentials or packet payloads.
    /// This class must NEVER enrich, infer, modify or authorize telemetry and
    /// does not take part in rule evaluation or confidence calculations.
    /// </summary>
    internal static class DnsReplayTelemetryDiagnostics
    {
        private static readonly HashSet<string> SupportedTypes =
            new(new[] { "A", "AAAA", "TXT", "NULL", "CNAME", "MX", "NS",
                        "SRV", "PTR", "SOA" }, StringComparer.OrdinalIgnoreCase);

        internal static IReadOnlyList<string> Inspect(TrafficRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));
            var codes = new List<string>();

            if (!record.IsUdp && !record.IsTcp)
                codes.Add("DNS_TRANSPORT_UNATTRIBUTED");
            else if (record.IsUdp && record.IsTcp)
                codes.Add("DNS_TRANSPORT_CONFLICT");

            if (record.IsQuic || record.IcmpTypeCode.HasValue
                || (record.IsUdp && record.TcpFlags.HasValue))
                codes.Add("DNS_TRANSPORT_FLAGS_CONFLICT");

            if (record.IsUdp && !IsDnsOrTransport(record.Protocol, "UDP")
                || record.IsTcp && !IsDnsOrTransport(record.Protocol, "TCP"))
                codes.Add("DNS_PROTOCOL_CONFLICT");

            if (record.IsTcp && record.TcpFlags.HasValue
                && ((record.TcpFlags.Value & 0x07) != 0
                    || (record.TcpFlags.Value & 0x18) == 0))
                codes.Add("DNS_TCP_NOT_DATA");

            if (record.SourcePort != 53 && record.DestinationPort != 53)
                codes.Add("DNS_PORT_53_MISSING");

            if (record.ApplicationProtocol != null
                && !string.Equals(record.ApplicationProtocol, "DNS",
                    StringComparison.OrdinalIgnoreCase))
                codes.Add("DNS_APPLICATION_PROTOCOL_CONFLICT");

            if (!string.Equals(record.ApplicationProtocol, "DNS",
                    StringComparison.OrdinalIgnoreCase)
                && !string.Equals(record.Protocol, "DNS",
                    StringComparison.OrdinalIgnoreCase))
                codes.Add("DNS_PROTOCOL_CLASSIFICATION_MISSING");

            if (record.HttpMethod != null || record.HttpUri != null
                || record.HttpRequestHeaders != null)
                codes.Add("DNS_HTTP_FIELDS_CONFLICT");

            if (record.DnsIsResponse)
                codes.Add("DNS_RESPONSE_NOT_QUERY");

            if (string.IsNullOrWhiteSpace(record.DnsQname))
                codes.Add("DNS_QNAME_MISSING");
            else if (!ValidQuestionName(record.DnsQname))
                codes.Add("DNS_QNAME_INVALID");

            if (string.IsNullOrWhiteSpace(record.DnsQtype))
                codes.Add("DNS_QTYPE_MISSING");
            else if (!SupportedTypes.Contains(record.DnsQtype))
                codes.Add("DNS_QTYPE_UNSUPPORTED");

            if (!IPAddress.TryParse(record.Source, out var source)
                || !IPAddress.TryParse(record.Destination, out var destination))
                codes.Add("DNS_IP_INVALID");
            else
            {
                if (source.Equals(destination)
                    || source.AddressFamily != destination.AddressFamily)
                    codes.Add("DNS_IP_FAMILY_OR_ENDPOINT_CONFLICT");
                if (record.IpVersion is not (null or 4 or 6)
                    || record.IpVersion == 4 && source.AddressFamily != AddressFamily.InterNetwork
                    || record.IpVersion == 6 && source.AddressFamily != AddressFamily.InterNetworkV6)
                    codes.Add("DNS_IP_VERSION_CONFLICT");
            }

            return codes;
        }

        private static bool IsDnsOrTransport(string? declared, string transport)
            => string.Equals(declared, "DNS", StringComparison.OrdinalIgnoreCase)
               || string.Equals(declared, transport, StringComparison.OrdinalIgnoreCase);

        private static bool ValidQuestionName(string raw)
        {
            var name = raw.Trim().TrimEnd('.');
            if (name.Length is < 3 or > 253 || !name.Contains('.'))
                return false;
            foreach (var label in name.Split('.'))
            {
                if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-'
                    || label.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not ('-' or '_')))
                    return false;
            }
            return true;
        }
    }
}
