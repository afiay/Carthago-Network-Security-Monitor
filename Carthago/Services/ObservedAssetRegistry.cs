// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Services;

internal sealed record ObservedAssetRow(string Evidence, string InterfaceScope, string? Mac,
    string Addresses, string Services, string FirstSeenUtc, string LastSeenUtc, long Observations);

// Passive session registry: no authorization decisions, no remote endpoint MAC
// attribution, no cross-interface merging. ARP is a claim, not authentication.
internal sealed class ObservedAssetRegistry
{
    private const int Capacity = 2048;
    private const int MaxAddresses = 32;
    private const int MaxServices = 64;
    private readonly object _gate = new();
    private bool _sealed;
    internal Guid SessionId { get; } = Guid.NewGuid();
    internal DateTimeOffset SessionStartedUtc { get; } = DateTimeOffset.UtcNow;
    internal void Seal() { lock (_gate) _sealed = true; }
    private readonly Dictionary<Key, Entry> _entries = new();
    private readonly record struct Key(string Scope, string Identity, bool Arp);
    private sealed class Entry
    {
        internal DateTimeOffset First, Last;
        internal long Count;
        internal readonly HashSet<string> Addresses = new(StringComparer.Ordinal);
        internal readonly SortedSet<int> Services = new();
    }

    internal void Observe(TrafficRecord r, DateTimeOffset now)
    {
        // ARP is meaningful only on an identified observation interface.
        var scope = r.CaptureInterfaceId;
        if (r.CaptureInterfaceEvidence == "WindowsInterfaceGuid" && Guid.TryParse(scope, out var id))
            scope = id.ToString("D");
        else
            scope = null;
        lock (_gate)
        {
            if (_sealed) return;
            if (r.Protocol == "ARP")
            {
                if (scope != null && r.ArpSenderMacMatchesFrame
                    && NormalizeMac(r.MacSource) is string mac
                    && NormalizeAddress(r.Source) is string sender
                    && LocalLanDiscovery.IsLocalHostAddress(IPAddress.Parse(sender)))
                    Add(new Key(scope, mac, true), sender, null, now);
                // Target address/MAC is never a sender claim.
                return;
            }
            if (!r.IsTcp && !r.IsUdp) return;
            // ETW or unresolved adapter has local-host IP evidence only.
            string localScope = scope ?? (r.CaptureBackend == "ETW" ? "ETW (interface unknown)" : "Interface unknown");
            bool synAck = r.IsTcp && r.TcpFlags is ushort flags && (flags & 0x17) == 0x12;
            int? service = synAck && r.SourcePort is > 0 and <= 65535 ? r.SourcePort : null;
            if (r.SrcIsLocalHost == true && NormalizeAddress(r.Source) is string localSource)
                Add(new Key(localScope, localSource, false), localSource, service, now);
            if (r.DstIsLocalHost == true && NormalizeAddress(r.Destination) is string localDestination
                && !(r.SrcIsLocalHost == true && localDestination == NormalizeAddress(r.Source)))
                Add(new Key(localScope, localDestination, false), localDestination, null, now);
        }
    }

    private void Add(Key key, string address, int? port, DateTimeOffset now)
    {
        if (!_entries.TryGetValue(key, out var entry))
        {
            if (_entries.Count >= Capacity) return; // bounded, preserve existing history
            _entries[key] = entry = new Entry { First = now, Last = now };
        }
        if (now < entry.First) entry.First = now;
        if (now > entry.Last) entry.Last = now;
        if (entry.Count < long.MaxValue) entry.Count++;
        if (entry.Addresses.Count < MaxAddresses) entry.Addresses.Add(address);
        if (port.HasValue && entry.Services.Count < MaxServices) entry.Services.Add(port.Value);
    }

    internal IReadOnlyList<ObservedAssetRow> Snapshot()
    {
        lock (_gate)
            return _entries.OrderByDescending(p => p.Value.Last).ThenBy(p => p.Key.Identity, StringComparer.Ordinal)
                .Select(p => new ObservedAssetRow(p.Key.Arp ? "ARP sender claim" : "Local host IP",
                    p.Key.Scope, p.Key.Arp ? p.Key.Identity : null,
                    string.Join("; ", p.Value.Addresses.OrderBy(a => a, StringComparer.Ordinal)),
                    string.Join("; ", p.Value.Services),
                    p.Value.First.UtcDateTime.ToString("u", CultureInfo.InvariantCulture),
                    p.Value.Last.UtcDateTime.ToString("u", CultureInfo.InvariantCulture), p.Value.Count)).ToArray();
    }

    private static string? NormalizeAddress(string? value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return null;
        ip = EndpointIpEnrichment.Normalize(ip);
        var scope = EndpointIpEnrichment.Classify(ip.ToString());
        return scope is "Private" or "Public" or "LinkLocal" or "SharedCGNAT" ? ip.ToString() : null;
    }

    private static string? NormalizeMac(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var raw = value.Replace(":", "").Replace("-", "");
        if (raw.Length != 12) return null;
        try
        {
            var bytes = Convert.FromHexString(raw);
            if ((bytes[0] & 1) != 0 || bytes.All(b => b == 0)) return null;
            return string.Join(":", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
        }
        catch (FormatException) { return null; }
    }
}
