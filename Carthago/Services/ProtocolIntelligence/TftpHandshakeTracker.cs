// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>Bounded IPv4 initial TFTP request/first-response recognition.
    /// No filename, options, payload, transfer completion or authorization retained.
    /// Supports RFC 1350 DATA block 1 after RRQ and ACK block 0 after WRQ.
    /// OACK is deliberately not recognized until negotiated options can be validated.
    /// </summary>
    internal sealed class TftpHandshakeTracker
    {
        private const int MaxPending = 1024;
        private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(45);
        private readonly object _gate = new();
        private readonly Dictionary<(string Client, string Server, int ClientPort), Pending> _pending = new();
        private readonly record struct Pending(Guid RequestId, byte Opcode, DateTime At);
        internal void Observe(TrafficRecord record, ReadOnlySpan<byte> payload, bool complete, DateTime now)
        {
            if (!complete || now.Kind != DateTimeKind.Utc || !record.IsUdp || record.IsTcp
                || record.IsQuic || record.IpVersion != 4 || record.Id == Guid.Empty
                || record.Source == null || record.Destination == null || record.Source == record.Destination
                || record.SourcePort is not int sport || record.DestinationPort is not int dport
                || sport is < 1 or > 65535 || dport is < 1 or > 65535
                || record.ApplicationProtocol != null || record.DnsQname != null
                || record.HttpMethod != null || record.Sni != null || record.TlsVersion != null)
                return;

            if (dport == 69 && sport > 1024
                && TftpRequestInspector.TryInspect(payload, (ushort)sport, (ushort)dport, true, out var request))
            {
                var key = (record.Source, record.Destination, sport);
                byte opcode = (byte)request.RequestKind;
                lock (_gate)
                {
                    if (_pending.TryGetValue(key, out var old))
                    {
                        if (now < old.At) return;
                        // Do not extend a pending request on retransmission, or pair a
                        // conflicting request with the previous request's response.
                        if (now - old.At <= Lifetime)
                        {
                            if (opcode != old.Opcode) _pending.Remove(key);
                            return;
                        }
                        _pending.Remove(key);
                    }
                    if (_pending.Count >= MaxPending)
                    {
                        var expired = new List<(string, string, int)>();
                        foreach (var item in _pending)
                            if (now >= item.Value.At && now - item.Value.At > Lifetime) expired.Add(item.Key);
                        foreach (var stale in expired) _pending.Remove(stale);
                        if (_pending.Count >= MaxPending) return;
                    }
                    _pending.Add(key, new Pending(record.Id, opcode, now));
                    record.TftpInitialRequestOpcode = opcode;
                    record.TftpRequestCorrelationId = record.Id;
                    record.ApplicationProtocol = opcode == 1 ? "tftp.rrq" : "tftp.wrq";
                }
                return;
            }

            // Only a pending request permits classification on ephemeral ports.
            // A 4-byte arbitrary UDP datagram is not a TFTP ACK by itself.
            if (sport <= 1024 || dport <= 1024 || payload.Length < 4 || payload[0] != 0)
                return;
            byte response = payload[1];
            int block = (payload[2] << 8) | payload[3];
            var reverse = (record.Destination, record.Source, dport);
            lock (_gate)
            {
                if (!_pending.TryGetValue(reverse, out var pending) || now < pending.At) return;
                if (now - pending.At > Lifetime) { _pending.Remove(reverse); return; }
                bool valid = pending.Opcode == 1
                    ? response == 3 && block == 1 && payload.Length <= 516
                    : response == 4 && block == 0 && payload.Length == 4;
                if (!valid) return;
                _pending.Remove(reverse); // one first response, no invented session completion
                record.TftpInitialReplyOpcode = response;
                record.TftpRequestCorrelationId = pending.RequestId;
                record.ApplicationProtocol = response == 3 ? "tftp.data.first" : "tftp.ack.initial";
            }
        }
    }
}
