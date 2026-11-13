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

        internal static QualifiedDnsScope Create(string source, string captureSource,
            string interfaceId, string networkId)
        {
            if (!IPAddress.TryParse(source, out var address) ||
                address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                throw new ArgumentException("A concrete source IP is required.", nameof(source));
            foreach (var value in new[] { captureSource, interfaceId, networkId })
                if (string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
                    !string.Equals(value, value.Trim(), StringComparison.Ordinal))
                    throw new ArgumentException("A bounded, exact capture identity is required.");
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            return new QualifiedDnsScope(JsonSerializer.Serialize(new[]
                { address.ToString(), captureSource, interfaceId, networkId }));
        }
    }
}
