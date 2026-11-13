using System;
using System.IO;
using System.Linq;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class ExternalCommunicationTests
{
    private const string Scope = "12345678-1234-1234-1234-123456789abc";
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 10, 0, 0, TimeSpan.Zero);
    private static TrafficRecord Packet(string destination = "8.8.8.8") => new()
    {
        IsTcp = true, TcpFlags = 2, Source = "192.168.1.10", Destination = destination,
        SourcePort = 50000, DestinationPort = 443, SrcIsLocalHost = true, DstIsLocalHost = false,
        CaptureInterfaceId = Scope, CaptureInterfaceEvidence = "WindowsInterfaceGuid"
    };
    private static ExternalCommunicationRow Row(string destination = "8.8.8.8", string[]? asns = null,
        string[]? countries = null, string[]? processes = null) =>
        new(Scope, "192.168.1.10", destination, 1, Now.AddDays(-1), Now.AddDays(-1).AddMinutes(1),
            asns ?? Array.Empty<string>(), countries ?? Array.Empty<string>(), processes ?? Array.Empty<string>());
    private static CommunicationHistoryRow Saved(ExternalCommunicationRow row, Guid? session = null)
        => new(session ?? Guid.NewGuid(), Now.AddDays(-1), row);
    private static ObservedAssetSessionSnapshot Current(params ExternalCommunicationRow[] rows)
        => new(Guid.NewGuid(), Now, Array.Empty<ObservedAssetRow>(), rows);
    private static CommunicationComparisonSnapshot Compare(ObservedAssetSessionSnapshot current, params CommunicationHistoryRow[] rows)
        => ExternalCommunicationComparison.Compare(current, new(rows.Length, Array.Empty<AssetHistoryRow>(), null, rows,
            rows.Select(r => new CheckpointCoverage(r.SessionId, r.StartedUtc, 0, 0)).ToArray()));

    [Fact]
    public void Outbound_Syn_And_Udp_Are_Observed_Not_Inbound_Or_Ack()
    {
        var registry = new ExternalCommunicationRegistry();
        registry.Observe(Packet(), Now);
        var udp = Packet(); udp.IsTcp = false; udp.IsUdp = true; udp.TcpFlags = null;
        registry.Observe(udp, Now.AddSeconds(1));
        var ack = Packet(); ack.TcpFlags = 16; registry.Observe(ack, Now);
        var inbound = Packet(); inbound.SrcIsLocalHost = false; inbound.DstIsLocalHost = true; registry.Observe(inbound, Now);
        Assert.Equal(2L, Assert.Single(registry.Snapshot()).Observations);
    }

    [Fact]
    public void Private_Unknown_Local_And_Unscoped_Excluded()
    {
        var registry = new ExternalCommunicationRegistry();
        registry.Observe(Packet("192.168.1.20"), Now);
        var unknown = Packet(); unknown.DstIsLocalHost = null; registry.Observe(unknown, Now);
        var unscoped = Packet(); unscoped.CaptureInterfaceEvidence = "Unresolved"; registry.Observe(unscoped, Now);
        Assert.Empty(registry.Snapshot());
    }

    [Fact]
    public void Metadata_Does_Not_Create_Or_Double_Count_Observations()
    {
        var registry = new ExternalCommunicationRegistry();
        var packet = Packet(); packet.DstAsn = 15169; packet.DstCountryIso2 = "us";
        packet.ProcessId = 12; packet.ProcessName = "Chrome"; packet.ProcessAttribution = "TcpSocketTable";
        registry.AddMetadata(packet);
        Assert.Empty(registry.Snapshot());
        registry.Observe(packet, Now);
        registry.AddMetadata(packet); registry.AddMetadata(packet);
        var row = Assert.Single(registry.Snapshot());
        Assert.Equal(1L, row.Observations);
        Assert.Equal(new[] { "15169" }, row.Asns);
        Assert.Equal(new[] { "US" }, row.Countries);
        Assert.Equal(new[] { "chrome" }, row.Processes);
    }

    [Fact]
    public void Udp_Binding_And_Unresolved_Process_Are_Not_Process_Identity()
    {
        var registry = new ExternalCommunicationRegistry();
        var udp = Packet(); udp.IsTcp = false; udp.IsUdp = true;
        udp.ProcessId = 12; udp.ProcessName = "chrome"; udp.ProcessAttribution = "UdpLocalBinding";
        registry.Observe(udp, Now); registry.AddMetadata(udp);
        Assert.Empty(Assert.Single(registry.Snapshot()).Processes);
        registry.Seal();
        registry.Observe(Packet("1.1.1.1"), Now);
        Assert.Single(registry.Snapshot());
    }

    [Fact]
    public void Comparison_Uses_Same_Host_And_Earlier_Metadata()
    {
        var current = Current(Row("8.8.8.8", new[] { "15169" }, new[] { "US" }, new[] { "chrome" }));
        var prior = Saved(Row("8.8.8.8", new[] { "13335" }, new[] { "SE" }, new[] { "firefox" }));
        var row = Assert.Single(Compare(current, prior).Rows);
        Assert.Equal("Previously observed destination", row.Status);
        Assert.Equal("15169", row.NewAsns); Assert.Equal("US", row.NewCountries); Assert.Equal("chrome", row.NewProcesses);
    }

    [Fact]
    public void Legacy_Self_And_Overlapping_History_Are_Not_Coverage()
    {
        var current = Current(Row());
        var self = Saved(Row(), current.SessionId);
        var overlap = Saved(Row() with { LastSeenUtc = Now });
        var row = Assert.Single(Compare(current, self, overlap).Rows);
        Assert.Equal("No comparable prior communication", row.Status);
        Assert.Empty(row.NewAsns);
    }

    [Fact]
    public void New_Destination_And_Incomplete_History_Are_Distinct()
    {
        var current = Current(Row("1.1.1.1"));
        var prior = Saved(Row());
        Assert.Equal("Destination not in retained history", Assert.Single(Compare(current, prior).Rows).Status);
        var incomplete = ExternalCommunicationComparison.Compare(current,
            new(1, Array.Empty<AssetHistoryRow>(), "corrupt", new[] { prior }));
        Assert.Equal("History incomplete; novelty withheld", Assert.Single(incomplete.Rows).Status);
    }

    [Fact]
    public void Truncated_Or_Legacy_History_Withholds_Absence_But_Preserves_Presence()
    {
        var current = Current(Row(), Row("1.1.1.1"));
        var prior = Saved(Row());
        foreach (long? rejected in new long?[] { null, 1 })
        {
            var history = new AssetHistorySnapshot(1, Array.Empty<AssetHistoryRow>(), null, new[] { prior },
                new[] { new CheckpointCoverage(prior.SessionId, prior.StartedUtc, rejected, 0) });
            var result = ExternalCommunicationComparison.Compare(current, history);
            Assert.Equal("Previously observed destination", result.Rows[0].Status);
            Assert.Contains("novelty withheld", result.Rows[1].Status);
        }
    }

    [Fact]
    public void Missing_Coverage_Withholds_Absence()
    {
        var current = Current(Row("1.1.1.1"));
        var prior = Saved(Row());
        var result = ExternalCommunicationComparison.Compare(current,
            new(1, Array.Empty<AssetHistoryRow>(), null, new[] { prior }));
        Assert.Contains("novelty withheld", Assert.Single(result.Rows).Status);
    }

    [Theory]
    [InlineData(2, null, null, true)]
    [InlineData(3, null, 0L, false)]
    [InlineData(3, -1L, 0L, false)]
    [InlineData(3, 7L, 0L, true)]
    public void Checkpoint_Version_And_Capacity_Validation(int version, long? rejected, long? assetRejected, bool valid)
    {
        var dir = Path.Combine(Path.GetTempPath(), "carthago-migration-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            var id = Guid.NewGuid();
            var started = Now.AddDays(-1);
            var checkpoint = new AssetHistoryStore.Checkpoint(version, id, started,
                Array.Empty<ObservedAssetRow>(), new[] { Row() }, rejected, assetRejected);
            var path = Path.Combine(dir, $"asset-{started.UtcDateTime.Ticks:D19}-{id:N}.json");
            File.WriteAllText(path, System.Text.Json.JsonSerializer.Serialize(checkpoint));
            var history = new AssetHistoryStore(dir).Read();
            Assert.Equal(valid ? 1 : 0, history.SessionCount);
            if (valid)
            {
                Assert.Null(history.Error);
                Assert.Equal(rejected, Assert.Single(history.Coverage!).DestinationRejected);
                Assert.Single(history.Communications!);
            }
            else
            {
                Assert.NotNull(history.Error);
                Assert.Empty(history.Communications!);
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }

    [Fact]
    public void Saturated_Registry_Roundtrip_Withholds_Absent_Destination()
    {
        var dir = Path.Combine(Path.GetTempPath(), "carthago-saturated-" + Guid.NewGuid().ToString("N"));
        try
        {
            var registry = new ObservedAssetRegistry();
            var seen = registry.SessionStartedUtc.AddSeconds(1);
            for (int i = 0; i < ExternalCommunicationRegistry.Capacity; i++)
                registry.Communications.Observe(Packet($"8.8.{i / 256}.{i % 256}"), seen);
            registry.Communications.Observe(Packet("1.1.1.1"), seen);
            registry.Communications.Observe(Packet("1.1.1.1"), seen);
            registry.Seal();
            Assert.True(new AssetHistoryStore(dir).Save(registry));
            var history = new AssetHistoryStore(dir).Read();
            Assert.Null(history.Error);
            Assert.Equal(ExternalCommunicationRegistry.Capacity, history.Communications!.Count);
            Assert.Equal(2L, Assert.Single(history.Coverage!).DestinationRejected);
            var current = new ObservedAssetSessionSnapshot(Guid.NewGuid(), seen.AddMinutes(1),
                Array.Empty<ObservedAssetRow>(), new[] { Row("1.1.1.1"), Row("8.8.0.0") });
            var result = ExternalCommunicationComparison.Compare(current, history);
            Assert.Contains("novelty withheld", result.Rows.Single(x => x.Destination == "1.1.1.1").Status);
            Assert.Equal("Previously observed destination", result.Rows.Single(x => x.Destination == "8.8.0.0").Status);
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }

    [Fact]
    public void Version_Three_Checkpoint_Persists_Communication_Without_Count_Inflation()
    {
        var dir = Path.Combine(Path.GetTempPath(), "carthago-comms-" + Guid.NewGuid().ToString("N"));
        try
        {
            var registry = new ObservedAssetRegistry();
            registry.Communications.Observe(Packet(), registry.SessionStartedUtc.AddSeconds(1));
            var store = new AssetHistoryStore(dir);
            Assert.True(store.Save(registry)); Assert.True(store.Save(registry));
            var history = new AssetHistoryStore(dir).Read();
            Assert.Null(history.Error); Assert.Equal(1, history.SessionCount);
            Assert.Equal(0L, Assert.Single(history.Coverage!).DestinationRejected);
            Assert.Equal(1L, Assert.Single(history.Communications!).Row.Observations);
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
}
