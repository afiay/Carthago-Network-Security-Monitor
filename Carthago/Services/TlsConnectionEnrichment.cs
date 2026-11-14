// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Services;

// Capture-session owned, SYN anchored, bounded TCP investigation context.
// Never copy inferred values into packet-level SNI, JA4 or certificate fields.
internal sealed class TlsConnectionEnrichment
{
    private const int Capacity = 4096;
    private const long Lifetime = 120_000;
    private readonly object _gate = new();
    private readonly Dictionary<Key, State> _flows = new();
    private long _pruneAt;
    private readonly record struct Key(string Client, int ClientPort, string Server, int ServerPort)
    {
        internal Key Reverse() => new(Server, ServerPort, Client, ClientPort);
    }
    private sealed class State
    {
        internal long Seen;
        internal bool Closed;
        internal string? Sni, OfferedAlpn, Version, NegotiatedAlpn, CertHash, CertNames, CertStatus;
    }

    internal void Observe(TrafficRecord r, long now)
    {
        if (!r.IsTcp || r.TcpFlags is not ushort flags
            || r.SourcePort is not (> 0 and <= 65535) || r.DestinationPort is not (> 0 and <= 65535)
            || !IPAddress.TryParse(r.Source, out var source) || !IPAddress.TryParse(r.Destination, out var dest)) return;
        var key = new Key(EndpointIpEnrichment.Normalize(source).ToString(), r.SourcePort.Value,
            EndpointIpEnrichment.Normalize(dest).ToString(), r.DestinationPort.Value);
        lock (_gate)
        {
            if (now >= _pruneAt)
            {
                foreach (var expired in _flows.Where(p => now - p.Value.Seen >= Lifetime).Select(p => p.Key).ToArray())
                    _flows.Remove(expired);
                _pruneAt = now + 1000;
            }
            if ((flags & 0x12) == 0x02)
            {
                // A delayed SYN must not reset a newer observation in either direction.
                if ((_flows.TryGetValue(key, out var forward) && (now < forward.Seen || (forward.Closed && now == forward.Seen)))
                    || (_flows.TryGetValue(key.Reverse(), out var reverse) && (now < reverse.Seen || (reverse.Closed && now == reverse.Seen))))
                    return;
                _flows.Remove(key); _flows.Remove(key.Reverse());
                if (_flows.Count < Capacity) _flows[key] = new State { Seen = now };
                return;
            }
            bool client = _flows.TryGetValue(key, out var state);
            if (!client && !_flows.TryGetValue(key.Reverse(), out state)) return;
            if (state is null || state.Closed || now < state.Seen || now - state.Seen >= Lifetime) return;
            if ((flags & 0x05) != 0)
            {
                // Retain only a bounded termination timestamp; discard all identity evidence.
                _flows[client ? key : key.Reverse()] = new State { Seen = now, Closed = true };
                return;
            }
            state.Seen = now;
            if (client && r.ApplicationProtocol == "TLS" && !string.IsNullOrWhiteSpace(r.TlsJa4))
            {
                state.Sni = r.Sni;
                state.OfferedAlpn = r.Alpn;
            }
            if (!client)
            {
                state.Version = r.TlsObservedNegotiatedVersion ?? state.Version;
                state.NegotiatedAlpn = r.TlsObservedNegotiatedAlpn ?? state.NegotiatedAlpn;
                if (r.TlsCertificateSha256 is not null)
                {
                    state.CertHash = r.TlsCertificateSha256;
                    state.CertNames = r.TlsCertificateDnsNames;
                    state.CertStatus = r.TlsCertificateNameStatus;
                }
            }
            if (state.Sni is null && state.Version is null && state.CertHash is null) return;
            r.TlsCorrelatedSni = state.Sni;
            r.TlsCorrelatedClientAlpn = state.OfferedAlpn;
            r.TlsCorrelatedNegotiatedVersion = state.Version;
            r.TlsCorrelatedNegotiatedAlpn = state.NegotiatedAlpn;
            r.TlsCorrelatedCertificateSha256 = state.CertHash;
            r.TlsCorrelatedCertificateNameStatus = TlsIdentityEnrichment.MatchName(state.Sni, state.CertNames, state.CertStatus);
            r.TlsCorrelationEvidence = "ObservedSynTcpTuple";
        }
    }
}
