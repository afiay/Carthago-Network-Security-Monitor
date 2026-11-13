// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableR589Tests
{
    private static readonly DateTime Epoch = new(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);
    private static TrafficRecord Record(string method, string path) => new()
    {
        Source = "192.0.2.1", Destination = "198.51.100.2", SourcePort = 51000,
        DestinationPort = 7001, Protocol = "TCP", IsTcp = true, Length = 128,
        L4Len = 88, ApplicationProtocol = "HTTP", HttpMethod = method, HttpUri = path
    };
    private static PacketEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    [Theory]
    [InlineData("GET", "/config/keystore/test.jsp", true)]
    [InlineData("POST", "/config/keystore/test.jspx?x=1", true)]
    [InlineData("GET", "/CONFIG/KEYSTORE/test.JSF", true)]
    [InlineData("GET", "/config/keystore/test.txt", false)]
    [InlineData("GET", "/other/test.jsp", false)]
    [InlineData("GET", "/other?x=/config/keystore/test.jsp", false)]
    [InlineData("PUT", "/config/keystore/test.jsp", false)]
    [InlineData("GET", "/config/keystore/test.jsp/extra", false)]
    public void ExistingRequestSignature(string method, string path, bool matched)
    {
        var result = new PortableR589Detector().Evaluate(At(Record(method, path)), out _);
        Assert.Equal(matched ? WebSignatureObservation.Match : WebSignatureObservation.None, result);
    }

    [Fact]
    public void ContradictoryOrMissingTelemetryFailsClosed()
    {
        var mutations = new Action<TrafficRecord>[] {
            r => r.HttpUri = null, r => r.ApplicationProtocol = "TLS",
            r => r.Sni = "example.test", r => r.DnsIsResponse = true,
            r => r.IsUdp = true, r => r.Id = Guid.Empty,
            r => r.L4Len = 15, r => r.SourcePort = 0
        };
        foreach (var mutate in mutations)
        {
            var r = Record("GET", "/config/keystore/test.jsp");
            mutate(r);
            Assert.Equal(WebSignatureObservation.None, new PortableR589Detector().Evaluate(At(r), out _));
        }
    }

    [Fact]
    public void CooldownDuplicateReverseTimeBoundaryAndSessionIsolation()
    {
        var d = new PortableR589Detector();
        var first = Record("GET", "/config/keystore/test.jsp");
        var next = Record("GET", "/config/keystore/test.jsp");
        Assert.Equal(WebSignatureObservation.Match, d.Evaluate(At(first), out _));
        Assert.Equal(WebSignatureObservation.None, d.Evaluate(At(first, 1), out _));
        Assert.Equal(WebSignatureObservation.None, d.Evaluate(At(next, -1), out _));
        Assert.Equal(WebSignatureObservation.Suppressed, d.Evaluate(At(next, 599), out _));
        Assert.Equal(WebSignatureObservation.Match, d.Evaluate(At(next, 600), out _));
        Assert.Equal(WebSignatureObservation.Match, new PortableR589Detector().Evaluate(At(first), out _));
    }

    [Fact]
    public void RawTcpFrameProducesDetectableRequest()
    {
        var payload = Encoding.ASCII.GetBytes("GET /config/keystore/test.jsp HTTP/1.1\r\nHost: example.test\r\n\r\n");
        var wire = new byte[40 + payload.Length];
        wire[0] = 0x45; wire[8] = 64; wire[9] = 6;
        new byte[] { 192, 0, 2, 1, 198, 51, 100, 2 }.CopyTo(wire, 12);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(2), (ushort)wire.Length);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(20), 51000);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(22), 7001);
        wire[32] = 0x50; wire[33] = 0x18; payload.CopyTo(wire, 40);
        var r = new PortablePacketProcessor(() => Epoch).ParseFrame(wire, 101);
        Assert.NotNull(r);
        Assert.Equal("HTTP", r!.ApplicationProtocol);
        Assert.Equal(WebSignatureObservation.Match, new PortableR589Detector().Evaluate(At(r), out var method));
        Assert.Equal("GET", method);
    }
}
