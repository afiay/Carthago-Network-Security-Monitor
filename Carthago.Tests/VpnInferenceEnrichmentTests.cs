using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class VpnInferenceEnrichmentTests
{
    private static InferenceEngine Engine(params IVpnSignal[] signals) => new(
        new Dictionary<string, double>
        {
            ["rdns.vpn"] = 1.3, ["rdns.proxy"] = 0.9, ["rdns.cdn"] = 0.1,
            ["port.proto"] = 0.7, ["proc.vpn"] = 1.8, ["abuse.score"] = 0.6,
            ["rdap.hosting"] = 1.2
        }, TimeSpan.FromHours(1), signals);

    [Fact]
    public async Task Https_And_Local_WireGuard_Do_Not_Classify_Remote_Ip_As_Proxy_Or_Vpn()
    {
        var engine = Engine(new PortProtocolSignal(), new ProcessNameSignal(), new AbuseScoreSignal());
        var result = await engine.ClassifyAsync(new VpnContext
        {
            Ip = "8.8.8.8", DstPort = 443, ProcessName = "wireguardtun", AbuseScore = 99
        }, default);
        Assert.True(result.LocalVpnProcessHint);
        Assert.False(result.VpnPortHint);
        Assert.False(result.IsVpn);
        Assert.False(result.IsProxy);
        Assert.Equal("Unknown", result.NetworkType);
        Assert.Equal(0, result.Confidence);
    }

    [Fact]
    public async Task Connection_Hints_Are_Not_Reused_For_Same_Ip()
    {
        var engine = Engine(new PortProtocolSignal(), new ProcessNameSignal());
        var first = await engine.ClassifyAsync(new VpnContext
        {
            Ip = "8.8.8.8", DstPort = 51820, ProcessName = "wireguard.exe"
        }, default);
        var second = await engine.ClassifyAsync(new VpnContext
        {
            Ip = "8.8.8.8", DstPort = 443, ProcessName = "chrome"
        }, default);
        Assert.True(first.LocalVpnProcessHint);
        Assert.True(first.VpnPortHint);
        Assert.False(second.LocalVpnProcessHint);
        Assert.False(second.VpnPortHint);
        Assert.False(first.IsVpn);
        Assert.False(second.IsVpn);
    }

    [Fact]
    public async Task Ip_Metadata_Is_Cached_But_Disabled_Rdap_Is_Not_Reused()
    {
        var rdap = new FakeSignal("rdap", new("metadata.rdap", 0, "metadata", Organization: "Example"));
        var ptr = new FakeSignal("rdns", new("rdns.vpn", 1, "PTR", ReverseDns: "vpn.example"));
        var engine = Engine(rdap, ptr);
        var first = await engine.ClassifyAsync(new VpnContext { Ip = "8.8.8.8" }, default);
        var second = await engine.ClassifyAsync(new VpnContext { Ip = "8.8.8.8", AllowRdap = false }, default);
        Assert.Equal("Example", first.Organization);
        Assert.Equal("vpn.example", first.ReverseDns);
        Assert.Null(second.Organization);
        Assert.Equal("vpn.example", second.ReverseDns);
        Assert.True(second.IsVpn);
        Assert.Equal(1, rdap.Calls);
        Assert.Equal(1, ptr.Calls);
    }

    [Fact]
    public async Task Cdn_And_Vpn_Port_Do_Not_Imply_Proxy()
    {
        var engine = Engine(new FakeSignal("rdns", new("rdns.cdn", 1, "CDN")), new PortProtocolSignal());
        var result = await engine.ClassifyAsync(new VpnContext { Ip = "8.8.8.8", DstPort = 1194 }, default);
        Assert.Equal("CDN", result.NetworkType);
        Assert.True(result.VpnPortHint);
        Assert.False(result.IsProxy);
        Assert.False(result.IsVpn);
    }

    [Fact]
    public async Task Special_Address_Does_Not_Query_Remote_Providers()
    {
        var signal = new FakeSignal("rdap", new("rdap.hosting", 1, "hosting"));
        var engine = Engine(signal);
        var result = await engine.ClassifyAsync(new VpnContext { Ip = "100.64.0.1" }, default);
        Assert.Equal("Bogon", result.NetworkType);
        Assert.Equal(0, signal.Calls);
    }

    private sealed class FakeSignal : IVpnSignal
    {
        private readonly SignalScore _score;
        public string Name { get; }
        public TimeSpan Ttl => TimeSpan.FromHours(1);
        public int Calls { get; private set; }
        public FakeSignal(string name, SignalScore score) { Name = name; _score = score; }
        public Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult<IReadOnlyList<SignalScore>>(new[] { _score });
        }
    }
}
