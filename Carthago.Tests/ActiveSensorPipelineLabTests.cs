// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

/// <summary>Actual local socket exchanges plus the real parser, projection,
/// LiteDB storage, baseline approval and qualification. Test-only logical scope
/// maps loopback transports to a private fixture; no LAN probe is performed.</summary>
public sealed class ActiveSensorPipelineLabTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly IPAddress Source = IPAddress.Parse("192.168.50.10");
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private static readonly LocalLanInterface Adapter = new("lab-fixture", Source, IPAddress.Parse("255.255.255.0"));
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-wire-lab-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Initial;
    private ActiveEvidenceStore Store() => new(Path.Combine(_dir, "active.db"), clock: () => _now);

    private static byte[] Answer(byte[] query, byte last)
    {
        var bytes = query.ToList();
        bytes[2] = 0x81; bytes[3] = 0x80; bytes[7] = 1;
        bytes.AddRange(new byte[] { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last });
        return bytes.ToArray();
    }

    private async Task<ActiveEvidenceRow> ObserveDnsAsync(UdpClient server, byte last, CancellationToken token)
    {
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        var observation = await DnsIntegritySensor.CheckCoreAsync(Adapter, Target, "lab.example",
            Array.Empty<IPAddress>(), async (source, target, query, budget) =>
            {
                Assert.Equal(Source, source);
                Assert.Equal(Target, target);
                async Task Respond()
                {
                    var request = await server.ReceiveAsync(budget);
                    Assert.Equal(IPAddress.Loopback, request.RemoteEndPoint.Address);
                    Assert.Equal(query, request.Buffer);
                    var response = Answer(request.Buffer, last);
                    await server.SendAsync(response.AsMemory(), request.RemoteEndPoint, budget);
                }
                var responder = Respond();
                try
                {
                    return await DnsIntegritySensor.ExchangeEndpointAsync(IPAddress.Loopback,
                        IPAddress.Loopback, port, query, budget);
                }
                finally { await responder; }
            }, TimeSpan.FromSeconds(5), token);
        Assert.Equal(DnsIntegrityStatus.AnswersObserved, observation.Status);
        Assert.Equal("192.0.2." + last, Assert.Single(observation.Addresses));
        return ActiveEvidenceProjection.From(AdapterId, observation with { ObservedUtc = _now });
    }

    [Theory]
    [InlineData(10, false)]
    [InlineData(20, true)]
    public async Task RealDnsWireThroughSchedulerAndStore(int newAnswer, bool expectFinding)
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var baseline = await ObserveDnsAsync(server, 10, cts.Token);
        Assert.True(Store().Save(baseline));
        Assert.True(Store().Approve(baseline.Id));
        var manager = new ActiveSensorManager(() => _now, _ => Adapter, async (_, _, token) =>
        {
            var row = await ObserveDnsAsync(server, (byte)newAnswer, token);
            return new ActiveSensorRun("AnswersObserved", true, row);
        }, row => Store().Save(row));
        manager.Add(ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns,
            "lab.example", 53, TimeSpan.FromMinutes(5), true));
        _now = Initial.AddMinutes(5);
        Assert.True(await manager.RunDueAsync(cts.Token));
        Assert.Equal("Saved", Assert.Single(manager.Snapshot()).HistoryStatus);
        Assert.Empty(Store().ReadFindings().Rows);
        _now = Initial.AddMinutes(10);
        Assert.True(await manager.RunDueAsync(cts.Token));
        Assert.Equal("Saved", Assert.Single(manager.Snapshot()).HistoryStatus);
        Assert.Equal(3, Store().Read().Rows.Count);
        var findings = Store().ReadFindings().Rows;
        if (expectFinding)
        {
            var finding = Assert.Single(findings);
            Assert.Equal("ASD003", finding.RuleId);
            Assert.Equal("192.0.2.10", finding.Before);
            Assert.Equal("192.0.2.20", finding.After);
            Assert.Equal(baseline.Id, finding.BaselineId);
        }
        else Assert.Empty(findings);
        _now = Initial.AddMinutes(15);
        Assert.True(await manager.RunDueAsync(cts.Token));
        Assert.Equal(expectFinding ? 1 : 0, Store().ReadFindings().Rows.Count);
    }

    private async Task<ActiveEvidenceRow> ObserveHttpAsync(TcpListener listener, string response,
        HttpHealthStatus expected, CancellationToken token)
    {
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        async Task Serve()
        {
            using var peer = await listener.AcceptTcpClientAsync(token);
            Assert.Equal(IPAddress.Loopback, ((IPEndPoint)peer.Client.RemoteEndPoint!).Address);
            using var stream = peer.GetStream();
            var request = await HttpHealthSensor.ReadHeaderAsync(stream, token);
            Assert.NotNull(request);
            var text = Encoding.ASCII.GetString(request!);
            Assert.Equal($"HEAD / HTTP/1.1\r\nHost: lab.example:{port}\r\nConnection: close\r\nUser-Agent: Carthago-ActiveSensor/1\r\n\r\n", text);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response).AsMemory(), token);
        }
        var server = Serve();
        var observed = await HttpHealthSensor.CheckEndpointAsync(IPAddress.Loopback, IPAddress.Loopback,
            port, "lab.example", false, TimeSpan.FromSeconds(5), token);
        await server;
        Assert.Equal(expected, observed.Status);
        // Map only test transport identity and clock. The parsed response is untouched.
        return ActiveEvidenceProjection.From(AdapterId,
            observed with { Source = Source, Target = Target, Port = 80, ObservedUtc = _now });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealHttpHeaderDriftRequiresUninterruptedConfirmation(bool interrupt)
    {
        const string before = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n";
        const string after = "HTTP/1.1 200 OK\r\n\r\n";
        const string malformed = "HTTP/1.1 200 OK\r\ninvalid header\r\n\r\n";
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            var baseline = await ObserveHttpAsync(listener, before, HttpHealthStatus.ResponseObserved, cts.Token);
            Assert.True(Store().Save(baseline));
            Assert.True(Store().Approve(baseline.Id));
            _now = Initial.AddMinutes(5);
            var first = await ObserveHttpAsync(listener, after, HttpHealthStatus.ResponseObserved, cts.Token);
            Assert.True(Store().Save(first));
            Assert.Empty(Store().ReadFindings().Rows);
            if (interrupt)
            {
                _now = Initial.AddMinutes(10);
                var invalid = await ObserveHttpAsync(listener, malformed, HttpHealthStatus.InvalidResponse, cts.Token);
                Assert.True(Store().Save(invalid));
            }
            _now = Initial.AddMinutes(15);
            var second = await ObserveHttpAsync(listener, after, HttpHealthStatus.ResponseObserved, cts.Token);
            Assert.True(Store().Save(second));
            if (interrupt)
            {
                Assert.Empty(Store().ReadFindings().Rows);
                _now = Initial.AddMinutes(20);
                Assert.True(Store().Save(await ObserveHttpAsync(listener, after, HttpHealthStatus.ResponseObserved, cts.Token)));
            }
            var finding = Assert.Single(Store().ReadFindings().Rows);
            Assert.Equal("ASD008", finding.RuleId);
            Assert.Equal("X-Content-Type-Options", finding.Field);
            Assert.Equal("Absent", finding.After);
            Assert.Equal(interrupt ? second.Id : first.Id, finding.FirstObservationId);
            Assert.False(listener.Pending());
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task TcpRealConnectionDoesNotSendApplicationBytes()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var scan = await TcpExposureSensor.ScanCoreAsync(Adapter, Target, async (source, target, logicalPort, token) =>
            {
                Assert.Equal(Source, source); Assert.Equal(Target, target);
                if (logicalPort != 443) throw new SocketException((int)SocketError.ConnectionRefused);
                await TcpExposureSensor.ConnectAsync(IPAddress.Loopback, IPAddress.Loopback, port, token);
            }, TimeSpan.FromSeconds(2), cts.Token);
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            using var stream = peer.GetStream();
            Assert.Equal(0, await stream.ReadAsync(new byte[1].AsMemory(), cts.Token));
            Assert.Equal(TcpExposureStatus.Open, scan.Single(x => x.Port == 443).Status);
            Assert.All(scan.Where(x => x.Port != 443), x => Assert.Equal(TcpExposureStatus.Refused, x.Status));
            Assert.False(listener.Pending());
            Assert.True(Store().Save(ActiveEvidenceProjection.From(AdapterId,
                scan.Select(x => x with { ObservedUtc = _now }).ToArray())));
            Assert.Single(Store().Read().Rows);
        }
        finally { listener.Stop(); }
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
