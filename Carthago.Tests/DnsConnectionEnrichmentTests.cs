using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class DnsConnectionEnrichmentTests
{
    private static TrafficRecord Query(string name = "example.com", ushort id = 7, string client = "192.168.1.10") => new()
    {
        Source = client, Destination = "192.168.1.1", SourcePort = 50000, DestinationPort = 53,
        SrcIsLocalHost = true, IsUdp = true, ApplicationProtocol = "DNS",
        DnsValidatedAQuestion = true, DnsValidatedTransactionId = id, DnsValidatedQuestionName = name
    };

    private static TrafficRecord Reply(string name = "example.com", ushort id = 7, int ttl = 10, string client = "192.168.1.10") => new()
    {
        Source = "192.168.1.1", Destination = client, SourcePort = 53, DestinationPort = 50000,
        DstIsLocalHost = true, IsUdp = true, ApplicationProtocol = "DNS", DnsIsResponse = true,
        DnsValidatedAQuestion = true, DnsValidatedTransactionId = id, DnsValidatedQuestionName = name,
        DnsValidatedSingleAAnswer = true, DnsValidatedAnswerAddress = "8.8.8.8", DnsValidatedAnswerTtl = ttl
    };

    private static TrafficRecord Flow(string client = "192.168.1.10", string? sni = null) => new()
    {
        Source = client, Destination = "8.8.8.8", SourcePort = 50100, DestinationPort = 443,
        SrcIsLocalHost = true, IsTcp = true, Sni = sni
    };

    [Fact]
    public void Matched_Answer_Enriches_Later_Flow_And_Preserves_Sni()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(), 100);
        cache.Observe(Reply(), 200);
        var flow = Flow(sni: "EXAMPLE.COM.");
        cache.Observe(flow, 300);
        Assert.Equal("example.com", flow.DnsCorrelatedNames);
        Assert.Equal(1, flow.DnsCorrelatedNameCount);
        Assert.Equal("MatchesObservedCandidate", flow.DnsSniAgreement);
        Assert.Equal("EXAMPLE.COM.", flow.Sni);
    }

    [Fact]
    public void Unmatched_Or_Wrong_Transaction_Does_Not_Seed_Cache()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Reply(), 100);
        cache.Observe(Query(), 200);
        cache.Observe(Reply(id: 8), 300);
        var flow = Flow();
        cache.Observe(flow, 400);
        Assert.Null(flow.DnsCorrelatedNames);
    }

    [Fact]
    public void Ttl_Expiration_And_Zero_Ttl_Are_Respected()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(), 100);
        cache.Observe(Reply(ttl: 1), 200);
        var expired = Flow();
        cache.Observe(expired, 1200);
        Assert.Null(expired.DnsCorrelatedNames);
        cache.Observe(Query(id: 8), 1300);
        cache.Observe(Reply(id: 8, ttl: 0), 1400);
        var zero = Flow();
        cache.Observe(zero, 1401);
        Assert.Null(zero.DnsCorrelatedNames);
    }

    [Fact]
    public void Shared_Ip_Keeps_Multiple_Candidates_And_Does_Not_Override_Sni()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query("a.example", 7), 100);
        cache.Observe(Reply("a.example", 7), 200);
        cache.Observe(Query("b.example", 8), 300);
        cache.Observe(Reply("b.example", 8), 400);
        var flow = Flow(sni: "other.example");
        cache.Observe(flow, 500);
        Assert.Equal("a.example; b.example", flow.DnsCorrelatedNames);
        Assert.Equal(2, flow.DnsCorrelatedNameCount);
        Assert.Equal("NotInObservedCandidates", flow.DnsSniAgreement);
        Assert.Equal("other.example", flow.Sni);
    }

    [Fact]
    public void Client_And_Session_Are_Isolated()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(), 100);
        cache.Observe(Reply(), 200);
        var otherClient = Flow("192.168.1.20");
        cache.Observe(otherClient, 300);
        Assert.Null(otherClient.DnsCorrelatedNames);
        var newSession = Flow();
        new DnsConnectionEnrichment().Observe(newSession, 300);
        Assert.Null(newSession.DnsCorrelatedNames);
    }

    [Fact]
    public void Unvalidated_And_Expired_Query_Responses_Are_Rejected()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(), 100);
        var loose = Reply();
        loose.DnsValidatedAQuestion = false;
        cache.Observe(loose, 200);
        var flow = Flow();
        cache.Observe(flow, 300);
        Assert.Null(flow.DnsCorrelatedNames);
        cache.Observe(Reply(), 30100);
        cache.Observe(flow, 30101);
        Assert.Null(flow.DnsCorrelatedNames);
    }

    [Fact]
    public void Older_Query_Cannot_Replace_Newer_Pending_Observation()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(), 200);
        cache.Observe(Query(), 100);
        cache.Observe(Reply(), 150);
        var early = Flow();
        cache.Observe(early, 175);
        Assert.Null(early.DnsCorrelatedNames);
        cache.Observe(Reply(), 250);
        var later = Flow();
        cache.Observe(later, 300);
        Assert.Equal("example.com", later.DnsCorrelatedNames);
    }

    [Fact]
    public void Older_Response_Cannot_Replace_Newer_Mapping()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(id: 7), 100);
        cache.Observe(Query(id: 8), 200);
        cache.Observe(Reply(id: 8, ttl: 10), 400);
        cache.Observe(Reply(id: 7, ttl: 1), 300);
        var early = Flow();
        cache.Observe(early, 350);
        Assert.Null(early.DnsCorrelatedNames);
        var later = Flow();
        cache.Observe(later, 2000);
        Assert.Equal("example.com", later.DnsCorrelatedNames);
    }

    [Fact]
    public void Wrong_Resolver_Or_Client_Port_Does_Not_Match()
    {
        var cache = new DnsConnectionEnrichment();
        cache.Observe(Query(), 100);
        var wrong = Reply();
        wrong.Source = "192.168.1.2";
        cache.Observe(wrong, 200);
        wrong = Reply();
        wrong.DestinationPort = 50001;
        cache.Observe(wrong, 300);
        var flow = Flow();
        cache.Observe(flow, 400);
        Assert.Null(flow.DnsCorrelatedNames);
    }
}
