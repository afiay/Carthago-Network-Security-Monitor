// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Text.Json;

namespace Carthago.Services.Baseline
{
    // Identity only: constructing a scope does not attest capture or benign intent.
    // No live promotion or ordinary baseline writer consumes this contract.
    internal sealed record QualifiedDnsScope
    {
        internal const string ObservationKind = "dns.reviewed.v1";
        internal string Subject { get; }

        private QualifiedDnsScope(string subject) => Subject = subject;

        // JSON serialization can replace malformed UTF-16 with U+FFFD.
        // Reject it before serialization so distinct identities cannot alias.
        private static bool IsWellFormedUtf16(string value)
        {
            for (int i = 0; i < value.Length; i++)
            {
                if (char.IsHighSurrogate(value[i]))
                {
                    if (++i == value.Length || !char.IsLowSurrogate(value[i])) return false;
                }
                else if (char.IsLowSurrogate(value[i])) return false;
            }
            return true;
        }

        internal static QualifiedDnsScope Create(string source, string captureSource,
            string interfaceId, string networkId)
        {
            if (!IPAddress.TryParse(source, out var address) ||
                address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                throw new ArgumentException("A concrete source IP is required.", nameof(source));
            foreach (var value in new[] { captureSource, interfaceId, networkId })
                if (string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
                    !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
                    !IsWellFormedUtf16(value))
                    throw new ArgumentException("A bounded, exact capture identity is required.");
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            if (address.Equals(IPAddress.Any))
                throw new ArgumentException("A concrete source IP is required.", nameof(source));
            return new QualifiedDnsScope(JsonSerializer.Serialize(new[]
                { address.ToString(), captureSource, interfaceId, networkId }));
        }
    }
}
