using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class TlsIdentityEnrichmentTests
{
    private static byte[] Hello(bool tls13, bool alpn = false)
    {
        var body = new List<byte> { 3, 3 };
        body.AddRange(new byte[32]);
        body.AddRange(new byte[] { 0, 0x13, 1, 0 });
        var ext = new List<byte>();
        if (tls13) ext.AddRange(new byte[] { 0, 43, 0, 2, 3, 4 });
        if (alpn) ext.AddRange(new byte[] { 0, 16, 0, 5, 0, 3, 2, (byte)'h', (byte)'2' });
        body.Add(0); body.Add((byte)ext.Count); body.AddRange(ext);
        var record = new List<byte> { 22, 3, 3, 0, (byte)(body.Count + 4), 2, 0, 0, (byte)body.Count };
        record.AddRange(body);
        return record.ToArray();
    }

    [Fact]
    public void Negotiated_Tls13_Is_Not_Legacy_Tls12()
    {
        Assert.True(TlsIdentityEnrichment.TryReadServerHello(Hello(true), out var value));
        Assert.Equal("TLS1.3", value.Version);
        Assert.Null(value.Alpn);
    }

    [Fact]
    public void Tls12_Server_Alpn_Is_Observed()
    {
        Assert.True(TlsIdentityEnrichment.TryReadServerHello(Hello(false, true), out var value));
        Assert.Equal("TLS1.2", value.Version);
        Assert.Equal("h2", value.Alpn);
    }

    [Fact]
    public void Truncated_Or_Plaintext_Tls13_Alpn_Is_Rejected()
    {
        var valid = Hello(true);
        Assert.False(TlsIdentityEnrichment.TryReadServerHello(valid.AsSpan(0, valid.Length - 1), out _));
        Assert.False(TlsIdentityEnrichment.TryReadServerHello(Hello(true, true), out _));
    }

    [Theory]
    [InlineData("www.example.com", "*.example.com", "MatchesDnsSan")]
    [InlineData("a.b.example.com", "*.example.com", "DoesNotMatchDnsSan")]
    [InlineData("example.com", "*.example.com", "DoesNotMatchDnsSan")]
    [InlineData("EXAMPLE.COM.", "example.com", "MatchesDnsSan")]
    [InlineData("8.8.8.8", "example.com", "SniUnavailable")]
    public void Dns_San_Matching_Is_Conservative(string sni, string names, string expected)
        => Assert.Equal(expected, TlsIdentityEnrichment.MatchName(sni, names, "DnsSanObserved"));

    [Fact]
    public void Certificate_Der_San_And_Sha256_Are_Extracted()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=not-the-san.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("example.com");
        san.AddDnsName("www.example.com");
        request.CertificateExtensions.Add(san.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var record = new TrafficRecord();
        TlsIdentityEnrichment.ApplyCertificate(record, cert);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant(), record.TlsCertificateSha256);
        Assert.Equal("example.com; www.example.com", record.TlsCertificateDnsNames);
        Assert.Equal("DnsSanObserved", record.TlsCertificateNameStatus);
        Assert.Equal("WithinValidityPeriod", record.TlsCertificateValidityStatus);
    }

    [Fact]
    public void Validity_Is_Not_Trust()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.Equal("WithinValidityPeriod", TlsIdentityEnrichment.Validity(now.AddDays(-1), now.AddDays(1), now));
        Assert.Equal("Expired", TlsIdentityEnrichment.Validity(now.AddDays(-2), now.AddDays(-1), now));
        Assert.Equal("NotYetValid", TlsIdentityEnrichment.Validity(now.AddDays(1), now.AddDays(2), now));
    }

    private static TrafficRecord Flow(bool reverse = false, ushort flags = 0x10) => new()
    {
        IsTcp = true, TcpFlags = flags, Source = reverse ? "8.8.8.8" : "192.168.1.10",
        Destination = reverse ? "192.168.1.10" : "8.8.8.8",
        SourcePort = reverse ? 443 : 50000, DestinationPort = reverse ? 50000 : 443
    };

    [Fact]
    public void Syn_Anchored_Identity_Correlates_Without_Overwriting_Packet_Evidence()
    {
        var cache = new TlsConnectionEnrichment();
        cache.Observe(Flow(flags: 2), 100);
        var client = Flow(); client.ApplicationProtocol = "TLS"; client.TlsJa4 = "client"; client.Sni = "example.com"; client.Alpn = "h2";
        cache.Observe(client, 200);
        var server = Flow(true); server.TlsObservedNegotiatedVersion = "TLS1.2";
        server.TlsCertificateSha256 = "hash"; server.TlsCertificateDnsNames = "example.com"; server.TlsCertificateNameStatus = "DnsSanObserved";
        cache.Observe(server, 300);
        Assert.Equal("example.com", server.TlsCorrelatedSni);
        Assert.Equal("MatchesDnsSan", server.TlsCorrelatedCertificateNameStatus);
        Assert.Null(server.Sni);
        var later = Flow(); cache.Observe(later, 400);
        Assert.Equal("hash", later.TlsCorrelatedCertificateSha256);
        Assert.Null(later.TlsCertificateSha256);
        cache.Observe(Flow(flags: 2), 500);
        var reused = Flow(); cache.Observe(reused, 600);
        Assert.Null(reused.TlsCorrelatedSni);
    }

    [Fact]
    public void Midstream_And_Closed_Flows_Do_Not_Propagate_Identity()
    {
        var cache = new TlsConnectionEnrichment();
        var client = Flow(); client.ApplicationProtocol = "TLS"; client.TlsJa4 = "client"; client.Sni = "example.com";
        cache.Observe(client, 100);
        Assert.Null(client.TlsCorrelatedSni);
        cache.Observe(Flow(flags: 2), 200);
        cache.Observe(client, 300);
        cache.Observe(Flow(flags: 1), 400);
        var next = Flow(); cache.Observe(next, 500);
        Assert.Null(next.TlsCorrelatedSni);
    }

    [Theory]
    [InlineData(false, 2)]
    [InlineData(true, 2)]
    [InlineData(false, 1)]
    [InlineData(true, 4)]
    public void Older_Control_Packet_Cannot_Reset_Newer_Tls_Evidence(bool reverse, ushort flags)
    {
        var cache = new TlsConnectionEnrichment();
        cache.Observe(Flow(flags: 2), 100);
        var hello = Flow();
        hello.ApplicationProtocol = "TLS"; hello.TlsJa4 = "client"; hello.Sni = "example.com";
        cache.Observe(hello, 300);
        cache.Observe(Flow(reverse, flags), 200);
        var later = Flow();
        cache.Observe(later, 400);
        Assert.Equal("example.com", later.TlsCorrelatedSni);
        Assert.Null(later.Sni);
        cache.Observe(Flow(reverse, flags), 500);
        var after = Flow();
        cache.Observe(after, 600);
        Assert.Null(after.TlsCorrelatedSni);
    }
    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 4)]
    public void Terminated_Tuple_Rejects_Older_And_Equal_Syn_But_Allows_Newer_Reuse(bool reverse, ushort flags)
    {
        var cache = new TlsConnectionEnrichment();
        cache.Observe(Flow(flags: 2), 100);
        cache.Observe(Flow(reverse, flags), 300);
        foreach (var timestamp in new long[] { 200, 300 })
        {
            cache.Observe(Flow(flags: 2), timestamp);
            cache.Observe(Flow(true, 2), timestamp);
            var stale = Flow();
            stale.ApplicationProtocol = "TLS"; stale.TlsJa4 = "client"; stale.Sni = "old.example";
            cache.Observe(stale, 310);
            Assert.Null(stale.TlsCorrelatedSni);
        }
        cache.Observe(Flow(flags: 2), 400);
        var fresh = Flow();
        fresh.ApplicationProtocol = "TLS"; fresh.TlsJa4 = "client"; fresh.Sni = "new.example";
        cache.Observe(fresh, 410);
        Assert.Equal("new.example", fresh.TlsCorrelatedSni);
        var later = Flow(true);
        cache.Observe(later, 420);
        Assert.Equal("new.example", later.TlsCorrelatedSni);
        Assert.Null(later.Sni);
    }

    [Fact]
    public void Termination_History_Expires_And_Does_Not_Cross_Instances()
    {
        var cache = new TlsConnectionEnrichment();
        cache.Observe(Flow(flags: 2), 100);
        cache.Observe(Flow(flags: 4), 200);
        var other = new TlsConnectionEnrichment();
        other.Observe(Flow(flags: 2), 100);
        var hello = Flow();
        hello.ApplicationProtocol = "TLS"; hello.TlsJa4 = "client"; hello.Sni = "example.com";
        other.Observe(hello, 150);
        Assert.Equal("example.com", hello.TlsCorrelatedSni);
        cache.Observe(Flow(flags: 2), 121200);
        var fresh = Flow();
        fresh.ApplicationProtocol = "TLS"; fresh.TlsJa4 = "client"; fresh.Sni = "fresh.example";
        cache.Observe(fresh, 121201);
        Assert.Equal("fresh.example", fresh.TlsCorrelatedSni);
    }
    [Fact]
    public void Tls_Capacity_Counts_Rejected_Syn_And_Releases_Expired_History()
    {
        var cache = new TlsConnectionEnrichment();
        for (int i = 0; i < 4096; i++)
        {
            var syn = Flow(flags: 2);
            syn.SourcePort = 10000 + i;
            cache.Observe(syn, 100);
            var close = Flow(flags: 4);
            close.SourcePort = syn.SourcePort;
            cache.Observe(close, 200);
        }
        Assert.Equal((4096, 0L), cache.GetCapacityHealth());
        cache.Observe(Flow(flags: 2), 300);
        Assert.Equal((4096, 1L), cache.GetCapacityHealth());
        var rejected = Flow();
        rejected.ApplicationProtocol = "TLS"; rejected.TlsJa4 = "client"; rejected.Sni = "rejected.example";
        cache.Observe(rejected, 400);
        Assert.Null(rejected.TlsCorrelatedSni);
        var reuse = Flow(flags: 2);
        reuse.SourcePort = 10000;
        cache.Observe(reuse, 500);
        Assert.Equal((4096, 1L), cache.GetCapacityHealth());
        cache.Observe(Flow(flags: 2), 121200);
        Assert.Equal((1, 1L), cache.GetCapacityHealth());
        var fresh = Flow();
        fresh.ApplicationProtocol = "TLS"; fresh.TlsJa4 = "client"; fresh.Sni = "fresh.example";
        cache.Observe(fresh, 121201);
        Assert.Equal("fresh.example", fresh.TlsCorrelatedSni);
        Assert.Equal((0, 0L), new TlsConnectionEnrichment().GetCapacityHealth());
    }
}
