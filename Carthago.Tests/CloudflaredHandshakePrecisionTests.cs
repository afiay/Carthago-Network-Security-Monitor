using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class CloudflaredHandshakePrecisionTests
{
    [Theory]
    [InlineData("chrome.exe", "trycloudflare.com")]
    [InlineData("cloudflared.exe", "ordinary-cdn.example.org")]
    public async Task R516_Requires_Both_Tunnel_Process_And_Endpoint(string process, string sni)
    {
        var record = new TrafficRecord
        {
            Source = "10.0.0.68", Destination = "198.51.100.68", Protocol = "TCP",
            DestinationPort = 443, ProcessName = process, Sni = sni,
            TlsVersion = "TLSv1.3", Info = "TLS client handshake"
        };

        var result = await new R516_CloudflaredTunnelHandshakeRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));

        Assert.False(result.Matched);
    }
}
