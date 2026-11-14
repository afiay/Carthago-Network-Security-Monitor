using System;
using System.Net;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class ProcessAttributionEnrichmentTests
{
    [Fact]
    public void Udp_Distinct_Owners_Are_Ambiguous_In_Either_Order()
    {
        var first = new WindowsProcessResolver.UdpOwnerSelection();
        first.Observe(100);
        first.Observe(200);
        first.Observe(100);
        Assert.Equal(0, first.Pid);
        var second = new WindowsProcessResolver.UdpOwnerSelection();
        second.Observe(200);
        second.Observe(100);
        Assert.Equal(0, second.Pid);
    }

    [Fact]
    public void Udp_Multiple_Bindings_For_Same_Owner_Are_Not_Ambiguous()
    {
        var owners = new WindowsProcessResolver.UdpOwnerSelection();
        owners.Observe(100);
        owners.Observe(100);
        Assert.Equal(100, owners.Pid);
    }

    [Fact]
    public void Udp_Unknown_Owner_Does_Not_Confirm_A_Different_Owner()
    {
        var owners = new WindowsProcessResolver.UdpOwnerSelection();
        owners.Observe(0);
        owners.Observe(100);
        Assert.Equal(0, owners.Pid);
    }

    [Fact]
    public void Process_Cache_Requires_Matching_Creation_Time()
    {
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.True(WindowsProcessResolver.MatchesProcessIdentity(start, start));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(start, start.AddSeconds(1)));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(start, null));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(null, start));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(null, null));
    }

    [Fact]
    public void Mapped_Ipv4_And_Invalid_Address_Are_Handled_Conservatively()
    {
        Assert.True(WindowsProcessResolver.AddressMatchesForTests("::ffff:192.168.1.10", IPAddress.Parse("192.168.1.10")));
        Assert.True(WindowsProcessResolver.AddressMatchesForTests("::ffff:192.168.1.10", IPAddress.Any));
        Assert.False(WindowsProcessResolver.AddressMatchesForTests("invalid", IPAddress.Any));
        Assert.False(WindowsProcessResolver.AddressMatchesForTests("192.168.1.10", IPAddress.IPv6Any));
    }

    [Theory]
    [InlineData("192.168.1.10", 50000, "8.8.8.8", 443, true)]
    [InlineData("::ffff:192.168.1.10", 50000, "8.8.8.8", 443, true)]
    [InlineData("192.168.1.10", 50000, null, 443, false)]
    [InlineData("192.168.1.10", 50000, "8.8.8.8", null, false)]
    [InlineData("192.168.1.10", 50000, "0.0.0.0", 443, false)]
    [InlineData("192.168.1.10", 50000, "::1", 443, false)]
    [InlineData("192.168.1.10", 65536, "8.8.8.8", 443, false)]
    public void Tcp_Attribution_Requires_Complete_Concrete_Tuple(string local, int? lp, string? remote, int? rp, bool expected)
        => Assert.Equal(expected, WindowsProcessResolver.HasCompleteTcpTuple(local, lp, remote, rp));

    [Fact]
    public void Tcp_Local_Match_Does_Not_Accept_Wildcard_Listener()
    {
        Assert.False(WindowsProcessResolver.TcpLocalAddressMatches("192.168.1.10", IPAddress.Any));
        Assert.False(WindowsProcessResolver.TcpLocalAddressMatches("::1", IPAddress.IPv6Any));
        Assert.True(WindowsProcessResolver.TcpLocalAddressMatches("::ffff:192.168.1.10", IPAddress.Parse("192.168.1.10")));
    }

    [Theory]
    [InlineData(0u, false)]
    [InlineData(1u, false)]
    [InlineData(2u, false)]
    [InlineData(3u, true)]
    [InlineData(5u, true)]
    [InlineData(10u, true)]
    [InlineData(11u, false)]
    [InlineData(12u, false)]
    public void Tcp_Ownership_Excludes_Nonlive_States(uint state, bool expected)
        => Assert.Equal(expected, WindowsProcessResolver.IsTcpOwnershipState(state));

    [Fact]
    public void Cached_Metadata_Requires_Current_Owner_And_Identity()
    {
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var cached = new WindowsProcessResolver.ProcessInfo { ProcessId = 100, StartTime = start };
        Assert.True(WindowsProcessResolver.CanReuseProcessMetadata(cached, 100, start));
        Assert.False(WindowsProcessResolver.CanReuseProcessMetadata(cached, 0, start));
        Assert.False(WindowsProcessResolver.CanReuseProcessMetadata(cached, 200, start));
        Assert.False(WindowsProcessResolver.CanReuseProcessMetadata(cached, 100, start.AddSeconds(1)));
        Assert.False(WindowsProcessResolver.CanReuseProcessMetadata(cached, 100, null));
    }

    [Theory]
    [InlineData("192.168.1.10", System.Net.Sockets.AddressFamily.InterNetwork)]
    [InlineData("::ffff:192.168.1.10", System.Net.Sockets.AddressFamily.InterNetwork)]
    [InlineData("2001:db8::1", System.Net.Sockets.AddressFamily.InterNetworkV6)]
    [InlineData("invalid", System.Net.Sockets.AddressFamily.Unspecified)]
    [InlineData(null, System.Net.Sockets.AddressFamily.Unspecified)]
    public void Tcp_Lookup_Selects_Only_Normalized_Local_Family(string? address, System.Net.Sockets.AddressFamily expected)
        => Assert.Equal(expected, WindowsProcessResolver.TcpLookupFamily(address));

    [Fact]
    public void Native_Lookup_Metrics_Count_Completed_Candidates_Not_Packets()
    {
        var metrics = new WindowsProcessResolver.ProcessLookupMetrics();
        var v4 = System.Net.Sockets.AddressFamily.InterNetwork;
        var v6 = System.Net.Sockets.AddressFamily.InterNetworkV6;
        Assert.Equal(42, metrics.Measure("TCP", v4, () => 42));
        Assert.Equal(0, metrics.Measure("TCP", v4, () => 0));
        Assert.Throws<InvalidOperationException>(() => metrics.Measure("TCP", v4, () => throw new InvalidOperationException()));
        Assert.Equal(7, metrics.Measure("UDP", v6, () => 7));
        var tcp = metrics.Read("TCP", v4);
        Assert.Equal(3L, tcp.Completed);
        Assert.Equal(1L, tcp.Resolved);
        Assert.Equal(2L, tcp.Unresolved);
        Assert.True(tcp.ElapsedTicks >= 0);
        Assert.Equal(1L, metrics.Read("UDP", v6).Completed);
        Assert.Equal(0L, metrics.Read("TCP", v6).Completed);
        Assert.Equal(0, metrics.Measure("TCP", System.Net.Sockets.AddressFamily.Unspecified,
            () => throw new InvalidOperationException()));
    }

    [Fact]
    public void Native_Lookup_Concurrency_Tracks_Overlapping_Candidates_And_Exception()
    {
        var metrics = new WindowsProcessResolver.ProcessLookupMetrics();
        var family = System.Net.Sockets.AddressFamily.InterNetwork;
        Assert.Equal(42, metrics.Measure("TCP", family, () =>
        {
            Assert.Equal(1L, metrics.Read("TCP", family).Active);
            Assert.Throws<InvalidOperationException>(() => metrics.Measure("TCP", family, () =>
            {
                var overlap = metrics.Read("TCP", family);
                Assert.Equal(2L, overlap.Active);
                Assert.Equal(2L, overlap.PeakActive);
                Assert.Equal(0L, overlap.Completed);
                throw new InvalidOperationException();
            }));
            Assert.Equal(1L, metrics.Read("TCP", family).Active);
            return 42;
        }));
        var final = metrics.Read("TCP", family);
        Assert.Equal(0L, final.Active);
        Assert.Equal(2L, final.PeakActive);
        Assert.Equal(2L, final.Completed);
        Assert.Equal(1L, final.Resolved);
        Assert.Equal(1L, final.Unresolved);
        Assert.Equal(0L, metrics.Read("UDP", family).PeakActive);
    }
    [Fact]
    public void Metadata_Cache_Outcomes_Are_Exclusive_And_Require_Current_Identity()
    {
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var cached = new WindowsProcessResolver.ProcessInfo { ProcessId = 42, StartTime = start };
        var metrics = new WindowsProcessResolver.MetadataCacheMetrics();
        DateTime? UnexpectedRead() => throw new InvalidOperationException("Unnecessary identity read");
        void Check(WindowsProcessResolver.MetadataCacheOutcome expected,
            WindowsProcessResolver.ProcessInfo? entry, bool fresh, int pid, Func<DateTime?> read)
        {
            var outcome = WindowsProcessResolver.ClassifyMetadataCache(entry, fresh, pid, read);
            Assert.Equal(expected, outcome);
            metrics.Record(outcome);
        }
        Check(WindowsProcessResolver.MetadataCacheOutcome.Absent, null, false, 42, UnexpectedRead);
        Check(WindowsProcessResolver.MetadataCacheOutcome.Expired, cached, false, 42, UnexpectedRead);
        Check(WindowsProcessResolver.MetadataCacheOutcome.OwnerMismatch, cached, true, 0, UnexpectedRead);
        Check(WindowsProcessResolver.MetadataCacheOutcome.OwnerMismatch, cached, true, 43, UnexpectedRead);
        Check(WindowsProcessResolver.MetadataCacheOutcome.IdentityMismatch, cached, true, 42, () => null);
        Check(WindowsProcessResolver.MetadataCacheOutcome.IdentityMismatch, cached, true, 42, () => start.AddSeconds(1));
        Check(WindowsProcessResolver.MetadataCacheOutcome.Reused, cached, true, 42, () => start);
        var snapshot = metrics.Read();
        Assert.Equal(7L, snapshot.Completed);
        Assert.Equal(1L, snapshot.Absent);
        Assert.Equal(1L, snapshot.Expired);
        Assert.Equal(2L, snapshot.OwnerMismatch);
        Assert.Equal(2L, snapshot.IdentityMismatch);
        Assert.Equal(1L, snapshot.Reused);
    }
    [Fact]
    public void Metadata_Cache_Capacity_Evicts_One_And_Protects_Replacement()
    {
        var cache = new WindowsProcessResolver.BoundedMetadataCache<object>(2);
        var old = new object();
        var replacement = new object();
        cache.Set("a", old);
        cache.Set("b", new object());
        cache.Set("a", replacement);
        Assert.False(cache.Remove("a", old));
        Assert.Equal((2, 0L), cache.ReadHealth());
        cache.Set("c", new object());
        Assert.Equal((2, 1L), cache.ReadHealth());
        Assert.False(cache.TryGetValue("b", out _));
        Assert.True(cache.TryGetValue("a", out var actual));
        Assert.Same(replacement, actual);
        Assert.True(cache.Remove("a", replacement));
        cache.Set("d", new object());
        Assert.Equal((2, 1L), cache.ReadHealth());
        cache.Clear();
        Assert.Equal((0, 1L), cache.ReadHealth());
    }

    [Fact]
    public void Metadata_Cache_Concurrent_Admission_Remains_Bounded()
    {
        var cache = new WindowsProcessResolver.BoundedMetadataCache<object>(8);
        System.Threading.Tasks.Parallel.For(0, 256, i =>
        {
            cache.Set(i.ToString(), new object());
            Assert.InRange(cache.ReadHealth().Count, 0, 8);
        });
        Assert.Equal((8, 248L), cache.ReadHealth());
    }
}
