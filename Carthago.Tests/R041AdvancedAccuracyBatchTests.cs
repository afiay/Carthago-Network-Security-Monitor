// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R041AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R041_Ja4FanOutSweepRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 7, 0, 0, DateTimeKind.Utc);
    public R041AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds=0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Tls(string sni="a.example.org", string ja4="t13d1516h2_abcd1234", string src="10.41.0.2", string dst="8.8.8.8")
        => new() { Source=src, Destination=dst, Protocol="TLS", DestinationPort=443, SourcePort=50141,
            Length=220, Ja4=ja4, Sni=sni };
    [Fact] public async Task Eight_Distinct_Sni_Hosts_In_One_Minute_Match()
    {
        for (int i=0;i<7;i++) Assert.False((await See(Tls(sni:$"host{i}.example.org"),i)).Matched);
        var e=Assert.Single((await See(Tls(sni:"host7.example.org"),7)).Events);
        Assert.Equal("R041",e.RuleId); Assert.Equal(8,e.Count); Assert.Equal(60,e.WindowSeconds);
    }
    [Fact] public async Task Seven_Distinct_Hosts_Do_Not_Reach_Threshold()
    {
        for(int i=0;i<7;i++) Assert.False((await See(Tls(sni:$"h{i}.example.org"),i)).Matched);
    }
    [Fact] public async Task Tls_Evidence_And_Public_Egress_Are_Required()
    {
        foreach(var r in new[]{Tls(dst:"10.0.0.4"),Tls(dst:"203.0.113.5"),Tls(src:"8.8.4.4"),Tls(src:"bad")})
            Assert.False((await See(r)).Matched);
        var tcp=Tls(); tcp.Protocol="TCP"; Assert.False((await See(tcp)).Matched);
        var empty=Tls(); empty.Length=0; Assert.False((await See(empty)).Matched);
    }
    [Fact] public async Task Invalid_Sni_And_Ja4_Are_Not_Added_To_Fanout()
    {
        foreach(string host in new[]{"bad","127.0.0.1","bad\r\n.example.org","bad..example.org"})
            Assert.False((await See(Tls(sni:host))).Matched);
        foreach(string fp in new[]{"bad fp","x","secret\nvalue"})
            Assert.False((await See(Tls(ja4:fp))).Matched);
    }
    [Fact] public async Task Sources_And_Fingerprints_Are_Isolated()
    {
        for(int i=0;i<7;i++) Assert.False((await See(Tls(sni:$"h{i}.example.org"),i)).Matched);
        Assert.False((await See(Tls(sni:"h7.example.org",src:"10.41.0.3"),7)).Matched);
        Assert.False((await See(Tls(sni:"h7.example.org",ja4:"t13d1516h2_other1234"),7)).Matched);
        Assert.True((await See(Tls(sni:"h7.example.org"),8)).Matched);
    }
    [Fact] public async Task Duplicate_Sni_Timestamp_And_Expired_Window_Do_Not_Inflate()
    {
        for(int i=0;i<12;i++) Assert.False((await See(Tls(),0)).Matched);
        for(int i=1;i<7;i++) Assert.False((await See(Tls(sni:$"h{i}.example.org"),i)).Matched);
        Assert.False((await See(Tls(sni:"stale.example.org"),100)).Matched);
        Assert.False((await See(Tls(sni:"outoforder.example.org"),2)).Matched);
    }
    [Fact] public async Task Alert_Redacts_Sni_And_Ja4_And_Clears_Completed_Window()
    {
        for(int i=0;i<7;i++) await See(Tls(sni:$"h{i}.example.org"),i);
        var e=Assert.Single((await See(Tls(sni:"secret.example.net"),7)).Events);
        Assert.DoesNotContain("secret.example.net",e.Description);
        Assert.DoesNotContain("t13d1516h2",e.Description);
        for(int i=8;i<15;i++) Assert.False((await See(Tls(sni:$"next{i}.example.org"),i)).Matched);
        Assert.True((await See(Tls(sni:"next15.example.org"),15)).Suppressed);
    }
}
