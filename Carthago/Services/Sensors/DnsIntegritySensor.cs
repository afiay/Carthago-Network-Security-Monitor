// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.ProtocolIntelligence;

namespace Carthago.Services.Sensors;

public enum DnsIntegrityStatus
{
    AnswersObserved, AnswersMatch, AnswersDiffer, NoAddress, NameError,
    DnsError, Truncated, InvalidResponse, TimedOut, TransportError
}

public sealed record DnsIntegrityObservation(
    IPAddress Source, IPAddress Resolver, string Name, DnsIntegrityStatus Status,
    IReadOnlyList<string> Addresses, int? ResponseCode, DateTimeOffset ObservedUtc,
    TimeSpan Duration, SocketError? SocketError);

/// <summary>One explicitly requested UDP IN/A query to an approved local IPv4 peer.</summary>
public static class DnsIntegritySensor
{
    public static TimeSpan QueryTimeout { get; } = TimeSpan.FromSeconds(2);

    public static Task<DnsIntegrityObservation> CheckAsync(LocalLanInterface adapter,
        IPAddress resolver, string name, IReadOnlyCollection<IPAddress> expected,
        CancellationToken token = default) =>
        CheckCoreAsync(adapter, resolver, name, expected, ExchangeAsync, QueryTimeout, token);

    internal static async Task<DnsIntegrityObservation> CheckCoreAsync(LocalLanInterface adapter,
        IPAddress resolver, string name, IReadOnlyCollection<IPAddress> expected,
        Func<IPAddress, IPAddress, byte[], CancellationToken, Task<byte[]>> exchange,
        TimeSpan timeout, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(exchange);
        token.ThrowIfCancellationRequested();
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(5))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(resolver))
            throw new ArgumentException("Resolver must be another host in the selected local IPv4 scope.", nameof(resolver));
        var normalized = NormalizeName(name);
        if (expected.Count > 16 || expected.Any(ip => ip is null || ip.AddressFamily != AddressFamily.InterNetwork))
            throw new ArgumentException("Provide up to 16 expected IPv4 addresses.", nameof(expected));
        var baseline = new HashSet<string>(expected.Select(ip => ip.ToString()), StringComparer.Ordinal);
        var id = (ushort)RandomNumberGenerator.GetInt32(65536);
        var query = BuildQuery(normalized, id);
        var watch = Stopwatch.StartNew();
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(timeout);
        DnsIntegrityObservation Result(DnsIntegrityStatus status, IReadOnlyList<string>? answers = null,
            int? rcode = null, SocketError? error = null) =>
            new(adapter.Address, resolver, normalized, status, answers ?? Array.Empty<string>(),
                rcode, DateTimeOffset.UtcNow, watch.Elapsed, error);
        try
        {
            var response = await exchange(adapter.Address, resolver, query, budget.Token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) return Result(DnsIntegrityStatus.TimedOut);
            var status = Inspect(response, normalized, id, baseline, out var answers, out var rcode);
            return Result(status, answers, rcode);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && budget.IsCancellationRequested)
        {
            return Result(DnsIntegrityStatus.TimedOut);
        }
        catch (SocketException ex)
        {
            token.ThrowIfCancellationRequested();
            return Result(ex.SocketErrorCode == SocketError.TimedOut
                ? DnsIntegrityStatus.TimedOut : DnsIntegrityStatus.TransportError, error: ex.SocketErrorCode);
        }
    }

    internal static string NormalizeName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var normalized = name.Trim();
        if (normalized.EndsWith(".", StringComparison.Ordinal)) normalized = normalized[..^1];
        if (normalized.Length is < 1 or > 253 || IPAddress.TryParse(normalized, out _))
            throw new ArgumentException("Enter a DNS hostname (ASCII or punycode), not an IP address.", nameof(name));
        foreach (var label in normalized.Split('.'))
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(c => !(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-')))
                throw new ArgumentException("DNS hostname contains an invalid label.", nameof(name));
        return normalized.ToLowerInvariant();
    }

    internal static byte[] BuildQuery(string name, ushort id)
    {
        var bytes = new List<byte> { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in NormalizeName(name).Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange(new byte[] { 0, 0, 1, 0, 1 }); // root, A, IN
        return bytes.ToArray();
    }

    private static ushort U16(byte[] data, int index) =>
        BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(index, 2));

    internal static DnsIntegrityStatus Inspect(byte[] data, string name, ushort id,
        IReadOnlySet<string> expected, out IReadOnlyList<string> answers, out int? rcode)
    {
        answers = Array.Empty<string>();
        rcode = null;
        if (data.Length is < 17 or > 4096 || U16(data, 0) != id || U16(data, 4) != 1)
            return DnsIntegrityStatus.InvalidResponse;
        ushort flags = U16(data, 2);
        if ((flags & 0x8000) == 0 || (flags & 0x7840) != 0)
            return DnsIntegrityStatus.InvalidResponse; // response, standard opcode, reserved Z clear

        // Initial question must be literal; reuse the shared codec for its canonical name.
        int end = 12;
        while (end < data.Length)
        {
            int len = data[end++];
            if (len == 0) break;
            if (len > 63 || len > data.Length - end) return DnsIntegrityStatus.InvalidResponse;
            end += len;
        }
        if (end > data.Length - 4 || data[end - 1] != 0 ||
            !DnsWireNameCodec.TryReadQuestion(data, 12, out var wire, out var next, out _) ||
            wire is null || next != end || !DnsWireNameCodec.TryGetSafeAsciiQName(wire, out var display) ||
            !string.Equals(display, name, StringComparison.OrdinalIgnoreCase) ||
            U16(data, end) != 1 || U16(data, end + 2) != 1)
            return DnsIntegrityStatus.InvalidResponse;

        int code = flags & 15;
        if ((flags & 0x0200) != 0)
        {
            rcode = code;
            return DnsIntegrityStatus.Truncated;
        }
        // Shared address inspector validates full framing, answer ownership and CNAME chains.
        // For other error codes, validate the same envelope without accepting any answer data.
        byte[] inspect = data;
        if (code != 0 && code != 3)
        {
            if (U16(data, 6) != 0) return DnsIntegrityStatus.InvalidResponse;
            inspect = (byte[])data.Clone();
            inspect[3] &= 0xf0;
        }
        if (!DnsAddressObservationInspector.TryInspect(inspect, out var parsed) || parsed is null ||
            !parsed.IsResponse || parsed.TransactionId != id || parsed.QuestionType != 1 ||
            !string.Equals(parsed.Name, name, StringComparison.OrdinalIgnoreCase))
            return DnsIntegrityStatus.InvalidResponse;
        rcode = code;
        if (code == 3) return DnsIntegrityStatus.NameError;
        if (code != 0) return DnsIntegrityStatus.DnsError;
        var observed = parsed.Answers.Select(a => a.Address).Distinct(StringComparer.Ordinal)
            .OrderBy(a => a, StringComparer.Ordinal).ToArray();
        answers = Array.AsReadOnly(observed);
        if (observed.Length == 0) return DnsIntegrityStatus.NoAddress;
        if (expected.Count == 0) return DnsIntegrityStatus.AnswersObserved;
        return expected.SetEquals(observed) ? DnsIntegrityStatus.AnswersMatch : DnsIntegrityStatus.AnswersDiffer;
    }

    private static async Task<byte[]> ExchangeAsync(IPAddress source, IPAddress resolver,
        byte[] query, CancellationToken token)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(source, 0));
        await socket.ConnectAsync(new IPEndPoint(resolver, 53), token).ConfigureAwait(false);
        await socket.SendAsync(query.AsMemory(), SocketFlags.None, token).ConfigureAwait(false);
        // Connected UDP socket filters other source endpoints. Oversize datagrams fail closed.
        var buffer = new byte[4097];
        int length = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, token).ConfigureAwait(false);
        return buffer.AsSpan(0, length).ToArray();
    }
}
