// SPDX-License-Identifier: MIT
using System;
using Carthago.Models;

namespace Carthago.Services;

public sealed record EnrichmentCoverageSnapshot(long Published, long LocalKnown, long InterfaceKnown,
    long DnsCorrelated, long TlsCorrelated, long ProcessEligible, long ProcessStrong, long ProcessUdpBinding);

// Service lifetime; publication and post-process-stage samples have different denominators.
internal sealed class EnrichmentCoverageHealth
{
    private readonly object _gate = new();
    private long _published, _local, _interface, _dns, _tls, _eligible, _strong, _udp;
    internal void ObservePublication(TrafficRecord r)
    {
        lock (_gate)
        {
            _published++;
            if (r.SrcIsLocalHost.HasValue && r.DstIsLocalHost.HasValue) _local++;
            if (r.CaptureInterfaceEvidence == "WindowsInterfaceGuid" &&
                Guid.TryParse(r.CaptureInterfaceId, out var id) && id != Guid.Empty) _interface++;
            if (r.DnsCorrelationEvidence == "MatchedDnsQueryResponse" &&
                !string.IsNullOrWhiteSpace(r.DnsCorrelatedNames)) _dns++;
            if (r.TlsCorrelationEvidence == "ObservedSynTcpTuple") _tls++;
        }
    }
    internal void ObserveProcess(TrafficRecord r)
    {
        if ((!r.IsTcp && !r.IsUdp) || (r.SrcIsLocalHost != true && r.DstIsLocalHost != true)) return;
        lock (_gate)
        {
            _eligible++;
            if (r.ProcessId <= 0) return;
            if (r.ProcessAttribution == "CaptureProvided" || (r.IsTcp && r.ProcessAttribution == "TcpSocketTable")) _strong++;
            else if (r.IsUdp && !r.IsTcp && r.ProcessAttribution == "UdpLocalBinding") _udp++;
        }
    }
    internal EnrichmentCoverageSnapshot Snapshot()
    {
        lock (_gate) return new(_published, _local, _interface, _dns, _tls, _eligible, _strong, _udp);
    }
}
