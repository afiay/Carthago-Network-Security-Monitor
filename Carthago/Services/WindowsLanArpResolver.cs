// SPDX-License-Identifier: MIT
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services;

public static class WindowsLanArpResolver
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint SendARP(uint destIp, uint srcIp, [Out] byte[] macAddress, ref uint length);

    // IPAddr is an IPv4 address in network byte order in native memory.
    public static uint ToNativeAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("IPv4 required.", nameof(address));
        return BitConverter.ToUInt32(address.GetAddressBytes(), 0);
    }

    public static string? FormatMac(byte[] bytes, uint length)
    {
        if (length != 6 || bytes.Length < 6 || (bytes[0] & 1) != 0 ||
            bytes.Take(6).All(b => b == 0))
            return null;
        return string.Join(":", bytes.Take(6).Select(b => b.ToString("X2")));
    }

    private static string? ResolveOne(IPAddress destination, IPAddress source)
    {
        var bytes = new byte[8];
        uint length = 6;
        return SendARP(ToNativeAddress(destination), ToNativeAddress(source), bytes, ref length) == 0
            ? FormatMac(bytes, length)
            : null;
    }

    // Only attempt targets belonging to an explicit source interface's actual
    // permitted subnet. Do not re-resolve usable cached entries or our own IPs.
    public static async Task<IReadOnlyDictionary<string, string>> ResolveAsync(
        IReadOnlyList<LocalLanInterface> interfaces, IReadOnlyList<IPAddress> targets,
        IEnumerable<string> alreadyKnown, CancellationToken token,
        Func<IPAddress, IPAddress, string?>? resolver = null)
    {
        resolver ??= ResolveOne;
        var known = new HashSet<string>(alreadyKnown, StringComparer.OrdinalIgnoreCase);
        var allowed = new HashSet<IPAddress>(targets);
        var own = new HashSet<IPAddress>(interfaces.Select(i => i.Address));
        var jobs = new Dictionary<IPAddress, IPAddress>();
        foreach (var adapter in interfaces)
        {
            foreach (var target in LocalLanDiscovery.PlanProbeTargets(new[] { adapter }))
            {
                if (allowed.Contains(target) && !own.Contains(target) && !known.Contains(target.ToString()))
                    jobs.TryAdd(target, adapter.Address);
            }
        }

        var found = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        await Parallel.ForEachAsync(jobs, new ParallelOptions
        {
            MaxDegreeOfParallelism = 24,
            CancellationToken = token
        }, (job, cancellation) =>
        {
            cancellation.ThrowIfCancellationRequested();
            var mac = resolver(job.Key, job.Value);
            if (!string.IsNullOrWhiteSpace(mac))
                found.TryAdd(job.Key.ToString(), mac);
            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);
        return found;
    }
}
