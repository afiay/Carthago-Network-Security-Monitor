// SPDX-License-Identifier: MIT
using System.Net;
using System.Net.Sockets;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class DnsIntegritySensorTests
{
    private static readonly LocalLanInterface Adapter = new("test", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128"));
    private static readonly IPAddress Resolver = IPAddress.Parse("192.168.1.131");
    private static readonly IPAddress Expected = IPAddress.Parse("192.0.2.10");
    private const string Name = "lab.example";
    private const ushort Id = 1234;

    private static byte[] Response(byte[] query, byte flagsLow = 0x80, bool answer = true)
    {
        var bytes = query.ToList();
        bytes[2] = 0x81; bytes[3] = flagsLow;
        if (answer)
        {
            bytes[7] = 1;
            bytes.AddRange(new byte[] { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10 });
        }
        return bytes.ToArray();
    }

    [Theory]
    [InlineData("match", DnsIntegrityStatus.AnswersMatch)]
    [InlineData("different", DnsIntegrityStatus.AnswersDiffer)]
    [InlineData("observe", DnsIntegrityStatus.AnswersObserved)]
    [InlineData("nxdomain", DnsIntegrityStatus.NameError)]
    [InlineData("nodata", DnsIntegrityStatus.NoAddress)]
    [InlineData("servfail", DnsIntegrityStatus.DnsError)]
    [InlineData("refused", DnsIntegrityStatus.DnsError)]
    [InlineData("truncated", DnsIntegrityStatus.Truncated)]
    [InlineData("wrong-id", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("wrong-name", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("wrong-type", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("wrong-class", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("query", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("bad-opcode", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("bad-pointer", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("short", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("trailing", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("unrelated-answer", DnsIntegrityStatus.NoAddress)]
    [InlineData("nxdomain-answer", DnsIntegrityStatus.InvalidResponse)]
    [InlineData("error-answer", DnsIntegrityStatus.InvalidResponse)]
    public void ResponseEvidenceIsStrict(string change, DnsIntegrityStatus expected)
    {
        var query = DnsIntegritySensor.BuildQuery(Name, Id);
        var wire = Response(query);
        var baseline = new HashSet<string> { Expected.ToString() };
        switch (change)
        {
            case "different": baseline = new() { "192.0.2.11" }; break;
            case "observe": baseline.Clear(); break;
            case "nxdomain": wire = Response(query, 0x83, false); break;
            case "nodata": wire = Response(query, 0x80, false); break;
            case "servfail": wire = Response(query, 0x82, false); break;
            case "refused": wire = Response(query, 0x85, false); break;
            case "truncated": wire = Response(query, 0x80, false); wire[2] |= 2; break;
            case "wrong-id": wire[1]++; break;
            case "wrong-name": wire[13] = (byte)'x'; break;
            case "wrong-type": wire[query.Length - 3] = 28; break;
            case "wrong-class": wire[query.Length - 1] = 3; break;
            case "query": wire = query; break;
            case "bad-opcode": wire[2] |= 8; break;
            case "bad-pointer": wire[query.Length + 1] = 255; break;
            case "short": Array.Resize(ref wire, wire.Length - 1); break;
            case "trailing": wire = wire.Concat(new byte[] { 0 }).ToArray(); break;
            case "unrelated-answer": wire[query.Length + 1] = 16; break; // points to example
            case "nxdomain-answer": wire[3] = 0x83; break;
            case "error-answer": wire[3] = 0x82; break;
        }
        var result = DnsIntegritySensor.Inspect(wire, Name, Id, baseline, out var answers, out var code);
        Assert.Equal(expected, result);
        if (expected is DnsIntegrityStatus.AnswersMatch or DnsIntegrityStatus.AnswersDiffer or DnsIntegrityStatus.AnswersObserved)
            Assert.Equal(new[] { Expected.ToString() }, answers.ToArray());
        else Assert.Empty(answers);
        if (expected == DnsIntegrityStatus.InvalidResponse) Assert.Null(code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a..b")]
    [InlineData("-bad.example")]
    [InlineData("bad-.example")]
    [InlineData("https://example.com")]
    [InlineData("192.0.2.1")]
    [InlineData("éxample.com")]
    public void InvalidNamesRejected(string name) =>
        Assert.Throws<ArgumentException>(() => DnsIntegritySensor.BuildQuery(name, Id));

    [Fact]
    public void NameCaseAndTrailingDotNormalize() =>
        Assert.Equal(DnsIntegritySensor.BuildQuery(Name, Id), DnsIntegritySensor.BuildQuery("LAB.Example.", Id));

    [Fact]
    public async Task ScopeAndBaselineRejectedBeforeNetwork()
    {
        int calls = 0;
        Task<byte[]> Exchange(IPAddress source, IPAddress target, byte[] data, CancellationToken token)
        { calls++; return Task.FromResult(data); }
        await Assert.ThrowsAsync<ArgumentException>(() => DnsIntegritySensor.CheckCoreAsync(Adapter,
            IPAddress.Parse("8.8.8.8"), Name, Array.Empty<IPAddress>(), Exchange, TimeSpan.FromSeconds(1), default));
        await Assert.ThrowsAsync<ArgumentException>(() => DnsIntegritySensor.CheckCoreAsync(Adapter,
            Resolver, Name, new[] { IPAddress.IPv6Loopback }, Exchange, TimeSpan.FromSeconds(1), default));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task SingleQueryUsesSelectedSourceAndResolver()
    {
        int calls = 0;
        var observation = await DnsIntegritySensor.CheckCoreAsync(Adapter, Resolver, Name, new[] { Expected },
            (source, target, query, _) =>
            {
                calls++;
                Assert.Equal(Adapter.Address, source);
                Assert.Equal(Resolver, target);
                return Task.FromResult(Response(query));
            }, TimeSpan.FromSeconds(1), default);
        Assert.Equal(1, calls);
        Assert.Equal(DnsIntegrityStatus.AnswersMatch, observation.Status);
        Assert.Equal(Resolver, observation.Resolver);
    }

    [Fact]
    public async Task TimeoutIsNotMismatch()
    {
        var observation = await DnsIntegritySensor.CheckCoreAsync(Adapter, Resolver, Name, new[] { Expected },
            async (_, _, _, token) => { await Task.Delay(Timeout.Infinite, token); return Array.Empty<byte>(); },
            TimeSpan.FromMilliseconds(20), default);
        Assert.Equal(DnsIntegrityStatus.TimedOut, observation.Status);
        Assert.Empty(observation.Addresses);
    }

    [Fact]
    public async Task TransportErrorIsNotMismatch()
    {
        var observation = await DnsIntegritySensor.CheckCoreAsync(Adapter, Resolver, Name, new[] { Expected },
            (_, _, _, _) => throw new SocketException((int)SocketError.ConnectionReset),
            TimeSpan.FromSeconds(1), default);
        Assert.Equal(DnsIntegrityStatus.TransportError, observation.Status);
        Assert.Equal(SocketError.ConnectionReset, observation.SocketError);
    }

    [Fact]
    public async Task CancelledQueryPropagatesCancellation()
    {
        using var cts = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsIntegritySensor.CheckCoreAsync(
            Adapter, Resolver, Name, Array.Empty<IPAddress>(), (_, _, _, token) =>
            {
                cts.Cancel(); token.ThrowIfCancellationRequested(); return Task.FromResult(Array.Empty<byte>());
            }, TimeSpan.FromSeconds(1), cts.Token));
    }
}
