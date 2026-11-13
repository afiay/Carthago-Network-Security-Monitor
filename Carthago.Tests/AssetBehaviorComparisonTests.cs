using System;
using System.Linq;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class AssetBehaviorComparisonTests
{
    private const string Scope = "12345678-1234-1234-1234-123456789abc";
    private const string OtherScope = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string Mac = "02:11:22:33:44:55";
    private const string OtherMac = "02:11:22:33:44:66";
    private const string Earlier = "2026-11-12 10:00:00Z";
    private const string Last = "2026-11-12 10:01:00Z";
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 10, 0, 0, TimeSpan.Zero);
    private static ObservedAssetRow Arp(string addresses = "192.168.1.10", string mac = Mac, string scope = Scope)
        => new("ARP sender claim", scope, mac, addresses, "", Earlier, Last, 2);
    private static ObservedAssetRow Local(string ports, string scope = Scope)
        => new("Local host IP", scope, null, "192.168.1.10", ports, Earlier, Last, 2);
    private static AssetHistoryRow Saved(ObservedAssetRow row, Guid? session = null, string start = Earlier)
        => new((session ?? Guid.NewGuid()).ToString("N"), start, row);
    private static ObservedAssetSessionSnapshot Current(params ObservedAssetRow[] rows) => new(Guid.NewGuid(), Now, rows);
    private static AssetBehaviorSnapshot Compare(ObservedAssetSessionSnapshot current, params AssetHistoryRow[] rows)
        => AssetBehaviorComparison.Compare(current, new(rows.Length, rows, null));

    [Fact]
    public void Earlier_Same_Mac_Tracks_New_Address_Not_Removal()
    {
        var row = Assert.Single(Compare(Current(Arp("192.168.1.10; 192.168.1.20")), Saved(Arp())).Rows);
        Assert.Equal("Previously observed identity", row.Status);
        Assert.Equal("192.168.1.20", row.NewAddresses);
        Assert.Equal(1, row.PriorSessions);
    }

    [Fact]
    public void Current_Checkpoint_And_Overlapping_History_Are_Excluded()
    {
        var sameSecond = Arp() with
        {
            FirstSeenUtc = "2026-11-13 10:00:00Z",
            LastSeenUtc = "2026-11-13 10:01:00Z"
        };
        var current = Current(sameSecond);
        var overlap = Arp() with { LastSeenUtc = "2026-11-13 10:01:00Z" };
        // Keep all excluded checkpoints chronologically valid. A session
        // starting at the cutoff is ineligible, not corrupted.
        var row = Assert.Single(Compare(current, Saved(sameSecond, current.SessionId, "2026-11-13 10:00:00Z"),
            Saved(overlap), Saved(sameSecond, start: "2026-11-13 10:00:00Z")).Rows);
        Assert.Equal("No comparable prior observations", row.Status);
        Assert.Equal(0, row.PriorSessions);
    }

    [Fact]
    public void Last_Seen_Before_Session_Start_Withholds_Novelty()
    {
        var current = Current(Arp("192.168.1.10; 192.168.1.20"));
        var invalid = Saved(Arp(), start: "2026-11-12 11:00:00Z");
        var row = Assert.Single(Compare(current, Saved(Arp()), invalid).Rows);
        Assert.Equal("History incomplete; novelty withheld", row.Status);
        Assert.Equal(1, row.PriorSessions);
        Assert.Empty(row.NewAddresses);
    }

    [Fact]
    public void Overlapping_Session_Is_Excluded_As_A_Whole()
    {
        var session = Guid.NewGuid();
        var later = Arp(mac: OtherMac) with { LastSeenUtc = "2026-11-13 10:01:00Z" };
        var row = Assert.Single(Compare(Current(Arp()), Saved(Arp(), session), Saved(later, session)).Rows);
        Assert.Equal("No comparable prior observations", row.Status);
        Assert.Equal(0, row.PriorSessions);
    }

    [Fact]
    public void Different_Interface_Or_Evidence_Type_Does_Not_Establish_Coverage()
    {
        var row = Assert.Single(Compare(Current(Arp()), Saved(Arp(scope: OtherScope)), Saved(Local("443"))).Rows);
        Assert.Equal("No comparable prior observations", row.Status);
        Assert.Empty(row.HistoricalMacClaims);
    }

    [Fact]
    public void New_Identity_And_Historical_Different_Mac_Are_Explicit()
    {
        var row = Assert.Single(Compare(Current(Arp(mac: OtherMac)), Saved(Arp())).Rows);
        Assert.Equal("Identity not in retained history", row.Status);
        Assert.Contains(Mac, row.HistoricalMacClaims);
        Assert.Empty(row.SessionMacClaims);
    }

    [Fact]
    public void Different_Current_Claims_Do_Not_Require_History()
    {
        var result = Compare(Current(Arp(), Arp(mac: OtherMac)));
        Assert.Equal(2, result.Rows.Count);
        Assert.All(result.Rows, r => Assert.NotEmpty(r.SessionMacClaims));
        Assert.All(result.Rows, r => Assert.Empty(r.HistoricalMacClaims));
    }

    [Fact]
    public void Services_Compare_Across_All_Earlier_Sessions()
    {
        var row = Assert.Single(Compare(Current(Local("22; 443; 8080")), Saved(Local("22")), Saved(Local("443"))).Rows);
        Assert.Equal("8080", row.NewServices);
        Assert.Equal(2, row.PriorSessions);
    }

    [Fact]
    public void Incomplete_History_Withholds_Novelty_But_Preserves_Positive_Claims()
    {
        var result = AssetBehaviorComparison.Compare(Current(Arp(mac: OtherMac)),
            new AssetHistorySnapshot(1, new[] { Saved(Arp()) }, "corrupt checkpoint"));
        var row = Assert.Single(result.Rows);
        Assert.Equal("History incomplete; novelty withheld", row.Status);
        Assert.Empty(row.NewAddresses);
        Assert.Contains(Mac, row.HistoricalMacClaims);
    }

    [Fact]
    public void Unknown_Interface_And_Empty_History_Do_Not_Invent_Comparison()
    {
        var result = Compare(Current(Local("443", "ETW (interface unknown)"), Arp()));
        Assert.Single(result.Rows);
        Assert.Equal("No comparable prior observations", result.Rows[0].Status);
        Assert.Contains("1 unscoped or invalid", result.Summary);
    }
}
