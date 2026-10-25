using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CaptureSourceHealthTests
{
    [Fact]
    public void EtwReportsKernelEventsAndConsumerDrops()
    {
        var snapshot = new CaptureSourceHealth("ETW", true, 120, 117, 3, null);
        Assert.Equal("ETW · active · observed 120 · forwarded 117 · dropped 3", snapshot.ToDisplayText());
    }

    [Fact]
    public void NpcapReportsParsedPacketsSeparatelyFromObservedPackets()
    {
        var snapshot = new CaptureSourceHealth("Npcap", true, 80, 79, 1, null);
        Assert.Equal("Npcap · active · observed 80 · forwarded 79 · dropped 1", snapshot.ToDisplayText());
    }

    [Fact]
    public void StoppedSourceDoesNotClaimToBeCapturing()
    {
        var snapshot = new CaptureSourceHealth("ETW", false, 0, 0, 0, "Insufficient privileges");
        Assert.Equal("ETW · stopped · Insufficient privileges", snapshot.ToDisplayText());
    }
}
