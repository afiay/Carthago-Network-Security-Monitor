// SPDX-License-Identifier: MIT
using System.Net;
using System.Net.Sockets;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class TcpExposureSensorTests
{
    private static readonly LocalLanInterface Adapter = new(
        "test", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.1.131");

    [Fact]
    public async Task ChecksOnlyFixedPortsOnSelectedSourceAndTarget()
    {
        var calls = new List<int>();
        var results = await TcpExposureSensor.ScanCoreAsync(Adapter, Target, (source, target, port, _) =>
        {
            Assert.Equal(Adapter.Address, source);
            Assert.Equal(Target, target);
            calls.Add(port);
            return Task.CompletedTask;
        }, TimeSpan.FromSeconds(1), CancellationToken.None);
        Assert.Equal(TcpExposureSensor.DefaultPorts.ToArray(), calls.ToArray());
        Assert.Equal(12, results.Count);
        Assert.All(results, r =>
        {
            Assert.Equal(TcpExposureStatus.Open, r.Status);
            Assert.Null(r.SocketError);
            Assert.Equal(Adapter.Address, r.Source);
            Assert.Equal(Target, r.Target);
        });
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.168.1.1")]
    [InlineData("192.168.1.128")]
    [InlineData("192.168.1.130")]
    [InlineData("192.168.1.255")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task InvalidScopeNeverConnects(string target)
    {
        var calls = 0;
        await Assert.ThrowsAsync<ArgumentException>(() => TcpExposureSensor.ScanCoreAsync(
            Adapter, IPAddress.Parse(target), (_, _, _, _) => { calls++; return Task.CompletedTask; },
            TimeSpan.FromSeconds(1), CancellationToken.None));
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData(SocketError.ConnectionRefused, TcpExposureStatus.Refused)]
    [InlineData(SocketError.TimedOut, TcpExposureStatus.TimedOut)]
    [InlineData(SocketError.HostUnreachable, TcpExposureStatus.Unreachable)]
    [InlineData(SocketError.NetworkUnreachable, TcpExposureStatus.Unreachable)]
    [InlineData(SocketError.AccessDenied, TcpExposureStatus.Error)]
    [InlineData(SocketError.AddressNotAvailable, TcpExposureStatus.Error)]
    public void SocketErrorsDoNotBecomeOpen(SocketError error, TcpExposureStatus expected)
        => Assert.Equal(expected, TcpExposureSensor.Classify(error));

    [Fact]
    public async Task TimeoutAndRefusalRemainDistinctAndDoNotAbortRemainingChecks()
    {
        var results = await TcpExposureSensor.ScanCoreAsync(Adapter, Target, async (_, _, port, token) =>
        {
            if (port == 21) await Task.Delay(Timeout.Infinite, token);
            if (port == 22) throw new SocketException((int)SocketError.ConnectionRefused);
        }, TimeSpan.FromMilliseconds(30), CancellationToken.None);
        Assert.Equal(TcpExposureStatus.TimedOut, results[0].Status);
        Assert.Equal(TcpExposureStatus.Refused, results[1].Status);
        Assert.Equal(SocketError.ConnectionRefused, results[1].SocketError);
        Assert.Equal(TcpExposureStatus.Open, results[2].Status);
        Assert.Equal(12, results.Count);
    }

    [Fact]
    public async Task UserCancellationStopsFurtherProbes()
    {
        using var cts = new CancellationTokenSource();
        var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TcpExposureSensor.ScanCoreAsync(
            Adapter, Target, (_, _, _, token) =>
            {
                calls++;
                cts.Cancel();
                token.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }, TimeSpan.FromSeconds(1), cts.Token));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task PreCancelledRunDoesNotConnect()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TcpExposureSensor.ScanCoreAsync(
            Adapter, Target, (_, _, _, _) => { calls++; return Task.CompletedTask; },
            TimeSpan.FromSeconds(1), cts.Token));
        Assert.Equal(0, calls);
    }
}
