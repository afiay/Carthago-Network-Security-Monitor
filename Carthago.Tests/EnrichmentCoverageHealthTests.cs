using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentCoverageHealthTests
{
    [Fact]
    public void Publication_Counts_Only_Qualified_Evidence()
    {
        var h = new EnrichmentCoverageHealth();
        h.ObservePublication(new TrafficRecord { DnsCorrelatedNames = "example.com", CaptureInterfaceEvidence = "WindowsInterfaceGuid" });
        h.ObservePublication(new TrafficRecord {
            SrcIsLocalHost = true, DstIsLocalHost = false,
            CaptureInterfaceEvidence = "WindowsInterfaceGuid", CaptureInterfaceId = "12345678-1234-1234-1234-123456789abc",
            DnsCorrelationEvidence = "MatchedDnsQueryResponse", DnsCorrelatedNames = "example.com",
            TlsCorrelationEvidence = "ObservedSynTcpTuple"
        });
        Assert.Equal(new EnrichmentCoverageSnapshot(2,1,1,1,1,0,0,0), h.Snapshot());
    }

    [Fact]
    public void Process_Samples_Separate_Udp_Binding_And_Unknown()
    {
        var h = new EnrichmentCoverageHealth();
        h.ObserveProcess(new TrafficRecord { IsTcp = true });
        h.ObserveProcess(new TrafficRecord { IsTcp = true, SrcIsLocalHost = true });
        h.ObserveProcess(new TrafficRecord { IsTcp = true, SrcIsLocalHost = true, ProcessId = 1, ProcessAttribution = "TcpSocketTable" });
        h.ObserveProcess(new TrafficRecord { IsUdp = true, DstIsLocalHost = true, ProcessId = 2, ProcessAttribution = "UdpLocalBinding" });
        Assert.Equal(new EnrichmentCoverageSnapshot(0,0,0,0,0,3,1,1), h.Snapshot());
    }

    [Fact]
    public void Capture_Provided_And_Conflicting_Protocol_Are_Not_Strong_Ownership()
    {
        var h = new EnrichmentCoverageHealth();
        h.ObserveProcess(new TrafficRecord { IsTcp = true, SrcIsLocalHost = true, ProcessId = 42, ProcessAttribution = "CaptureProvided" });
        h.ObserveProcess(new TrafficRecord { IsUdp = true, SrcIsLocalHost = true, ProcessId = 42, ProcessAttribution = "CaptureProvided" });
        h.ObserveProcess(new TrafficRecord { IsTcp = true, IsUdp = true, SrcIsLocalHost = true, ProcessId = 42, ProcessAttribution = "TcpSocketTable" });
        h.ObserveProcess(new TrafficRecord { IsTcp = true, SrcIsLocalHost = true, ProcessId = 42, ProcessAttribution = "TcpSocketTable" });
        Assert.Equal(new EnrichmentCoverageSnapshot(0,0,0,0,0,4,1,0), h.Snapshot());
    }

    [Fact]
    public void Missing_Snapshot_Is_Not_Zero_Coverage()
    {
        Assert.Equal("Evidence coverage unavailable.", EnrichmentHealthPresentation.CoverageSummary(null));
    }
}
