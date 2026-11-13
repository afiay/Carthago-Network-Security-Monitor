using System;
using System.IO;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentStorageHealthTests
{
    [Fact]
    public void Capacity_Counts_Rejected_Observations_Not_Existing_Updates()
    {
        var registry = new ExternalCommunicationRegistry();
        var now = DateTimeOffset.UtcNow;
        TrafficRecord Packet(int i) => new()
        {
            Source = "192.168.1.10", Destination = $"8.8.{i / 256}.{i % 256}",
            IsTcp = true, TcpFlags = 2, SourcePort = 50000, DestinationPort = 443,
            SrcIsLocalHost = true, DstIsLocalHost = false,
            CaptureInterfaceId = "12345678-1234-1234-1234-123456789abc", CaptureInterfaceEvidence = "WindowsInterfaceGuid"
        };
        for (int i = 0; i < ExternalCommunicationRegistry.Capacity; i++) registry.Observe(Packet(i), now);
        registry.Observe(Packet(0), now);
        registry.Observe(Packet(2048), now);
        registry.Observe(Packet(2048), now);
        Assert.Equal(new RegistryCapacitySnapshot(2048, 2048, 2), registry.CapacitySnapshot());
        registry.Seal();
        registry.Observe(Packet(2049), now);
        Assert.Equal(2L, registry.CapacitySnapshot().Rejected);
    }

    [Fact]
    public void Empty_Save_Is_Not_A_Write_And_Failure_Is_Visible()
    {
        string path = Path.GetTempFileName();
        try
        {
            var store = new AssetHistoryStore(path);
            var registry = new ObservedAssetRegistry();
            Assert.True(store.Save(registry));
            Assert.Equal(new CheckpointHealthSnapshot(0, 0, null), store.HealthSnapshot());
            registry.Observe(new TrafficRecord { Source = "192.168.1.10", IsTcp = true, SrcIsLocalHost = true }, DateTimeOffset.UtcNow);
            Assert.False(store.Save(registry));
            Assert.Equal(1L, store.HealthSnapshot().Failures);
            Assert.NotNull(store.HealthSnapshot().LastError);
            File.Delete(path);
            Assert.True(store.Save(registry));
            Assert.Equal(new CheckpointHealthSnapshot(1, 1, null), store.HealthSnapshot());
        }
        finally { if (File.Exists(path)) File.Delete(path); if (Directory.Exists(path)) Directory.Delete(path, true); }
    }
}
