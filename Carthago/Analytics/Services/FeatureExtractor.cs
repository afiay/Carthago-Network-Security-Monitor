// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Net;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class FeatureExtractor
    {
        public FlowFeature FromTrafficRecord(TrafficRecord record)
        {
            var timestampUtc = ParseTimestamp(record.Timestamp);
            var sourceIp = record.Source ?? "";
            var destinationIp = record.Destination;
            var isInternalSource = IsInternalIp(sourceIp);
            var isInternalDestination = IsInternalIp(destinationIp);

            return new FlowFeature
            {
                TimestampUtc = timestampUtc,
                SourceIp = sourceIp,
                DestinationIp = destinationIp,
                DestinationPort = record.DestinationPort,
                Protocol = record.Protocol ?? "",
                Bytes = Math.Max(0, record.Length),
                PacketCount = 1,
                ProcessName = NormalizeEmpty(record.ProcessName),
                Country = NormalizeEmpty(record.DstCountryIso2)
                    ?? NormalizeEmpty(record.DstCountry)
                    ?? NormalizeEmpty(record.WhoisCountry),
                Asn = NormalizeEmpty(record.WhoisASN),
                Domain = NormalizeEmpty(record.DnsQname)
                    ?? NormalizeEmpty(record.HttpHost)
                    ?? NormalizeEmpty(record.Sni),
                Sni = NormalizeEmpty(record.Sni),
                Ja4 = NormalizeEmpty(record.Ja4)
                    ?? NormalizeEmpty(record.Ja4S)
                    ?? NormalizeEmpty(record.Ja4T)
                    ?? NormalizeEmpty(record.Ja4SSH),
                Hassh = NormalizeEmpty(record.Hassh),
                IsInternalSource = isInternalSource,
                IsInternalDestination = isInternalDestination,
                Direction = DeriveDirection(isInternalSource, isInternalDestination),
                HourOfDay = timestampUtc.Hour,
                DayOfWeek = timestampUtc.DayOfWeek,
                IsDns = string.Equals(record.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                    || record.DestinationPort == 53
                    || record.SourcePort == 53,
                IsThreatFeedHit = record.ReputationIsMalicious == true
            };
        }

        public FlowFeature FromDetectionEvent(DetectionEvent evt)
        {
            var timestampUtc = evt.Timestamp == default ? DateTime.UtcNow : evt.Timestamp.ToUniversalTime();
            var sourceIp = evt.SourceIp ?? "";
            var destinationIp = evt.DestinationIp;
            var isInternalSource = IsInternalIp(sourceIp);
            var isInternalDestination = IsInternalIp(destinationIp);

            return new FlowFeature
            {
                TimestampUtc = timestampUtc,
                SourceIp = sourceIp,
                DestinationIp = destinationIp,
                DestinationPort = evt.DestinationPort,
                Protocol = evt.Protocol ?? "",
                Bytes = 0,
                PacketCount = Math.Max(1, evt.Count),
                ProcessName = NormalizeEmpty(evt.ProcessName),
                Country = NormalizeEmpty(evt.Country),
                Asn = NormalizeEmpty(evt.Asn),
                Domain = NormalizeEmpty(evt.DestinationHost),
                Ja4 = NormalizeEmpty(evt.Ja4),
                Hassh = NormalizeEmpty(evt.Hassh),
                RuleId = NormalizeEmpty(evt.RuleId),
                RuleName = NormalizeEmpty(evt.Description),
                RuleSeverity = evt.Severity.ToString(),
                DetectionSeverity = evt.Severity,
                IsInternalSource = isInternalSource,
                IsInternalDestination = isInternalDestination,
                Direction = DeriveDirection(isInternalSource, isInternalDestination),
                HourOfDay = timestampUtc.Hour,
                DayOfWeek = timestampUtc.DayOfWeek
            };
        }

        private static DateTime ParseTimestamp(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return DateTime.UtcNow;

            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var dto))
                return dto.UtcDateTime;

            if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var dt))
                return DateTime.SpecifyKind(dt, DateTimeKind.Local).ToUniversalTime();

            return DateTime.UtcNow;
        }

        private static string? NormalizeEmpty(string? value)
            => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        private static string DeriveDirection(bool internalSource, bool internalDestination)
        {
            if (internalSource && !internalDestination) return "outbound";
            if (!internalSource && internalDestination) return "inbound";
            if (internalSource && internalDestination) return "internal";
            return "external";
        }

        private static bool IsInternalIp(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || !IPAddress.TryParse(value, out var address))
                return false;

            if (IPAddress.IsLoopback(address))
                return true;

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = address.GetAddressBytes();
                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || (bytes[0] == 169 && bytes[1] == 254);
            }

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var text = address.ToString().ToLowerInvariant();
                return address.IsIPv6LinkLocal
                    || address.IsIPv6SiteLocal
                    || text.StartsWith("fc", StringComparison.Ordinal)
                    || text.StartsWith("fd", StringComparison.Ordinal);
            }

            return false;
        }
    }
}
