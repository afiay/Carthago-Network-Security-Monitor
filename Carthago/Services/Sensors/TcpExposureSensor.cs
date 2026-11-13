// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;

namespace Carthago.Services.Sensors;

public enum TcpExposureStatus
{
    Open, Refused, TimedOut, Unreachable, Error
}

public sealed record TcpExposureObservation(
    IPAddress Source, IPAddress Target, int Port, TcpExposureStatus Status,
    DateTimeOffset ObservedUtc, TimeSpan Duration, SocketError? SocketError);

/// <summary>
/// Explicit, bounded TCP connect checks for one approved local IPv4 peer.
/// Observations are not protocol identification, vulnerability findings or traffic records.
/// </summary>
public static class TcpExposureSensor
{
    private static readonly int[] Ports = { 21, 22, 23, 53, 80, 443, 445, 3389, 5985, 8080, 8443, 9100 };
    public static IReadOnlyList<int> DefaultPorts { get; } = Array.AsReadOnly(Ports);
    public static TimeSpan PerPortTimeout { get; } = TimeSpan.FromMilliseconds(750);

    public static Task<IReadOnlyList<TcpExposureObservation>> ScanAsync(
        LocalLanInterface adapter, IPAddress target, CancellationToken token = default) =>
        ScanCoreAsync(adapter, target, ConnectAsync, PerPortTimeout, token);

    internal static async Task<IReadOnlyList<TcpExposureObservation>> ScanCoreAsync(
        LocalLanInterface adapter, IPAddress target,
        Func<IPAddress, IPAddress, int, CancellationToken, Task> connect,
        TimeSpan timeout, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(connect);
        token.ThrowIfCancellationRequested();
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(5))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        // Reuse the exact local LAN scope, including own-address, network,
        // broadcast and current-/24 exclusions. No DNS or routed public targets.
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(target))
            throw new ArgumentException("Target must be another host in the selected local IPv4 scope.", nameof(target));

        var result = new List<TcpExposureObservation>(Ports.Length);
        foreach (int port in Ports)
        {
            token.ThrowIfCancellationRequested();
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
            budget.CancelAfter(timeout);
            var watch = Stopwatch.StartNew();
            TcpExposureStatus status;
            SocketError? error = null;
            try
            {
                await connect(adapter.Address, target, port, budget.Token).ConfigureAwait(false);
                status = TcpExposureStatus.Open;
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested && budget.IsCancellationRequested)
            {
                status = TcpExposureStatus.TimedOut;
            }
            catch (SocketException ex)
            {
                error = ex.SocketErrorCode;
                status = Classify(ex.SocketErrorCode);
            }
            token.ThrowIfCancellationRequested();
            result.Add(new(adapter.Address, target, port, status, DateTimeOffset.UtcNow, watch.Elapsed, error));
        }
        return result.AsReadOnly();
    }

    internal static TcpExposureStatus Classify(SocketError error) => error switch
    {
        SocketError.ConnectionRefused => TcpExposureStatus.Refused,
        SocketError.TimedOut => TcpExposureStatus.TimedOut,
        SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown
            => TcpExposureStatus.Unreachable,
        _ => TcpExposureStatus.Error
    };

    private static async Task ConnectAsync(IPAddress source, IPAddress target, int port,
        CancellationToken token)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(source, 0));
        await socket.ConnectAsync(new IPEndPoint(target, port), token).ConfigureAwait(false);
        // No application payload, banners, credentials or authentication attempts.
    }
}
