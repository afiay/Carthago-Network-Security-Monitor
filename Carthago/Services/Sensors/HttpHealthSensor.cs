// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Sensors;

public enum HttpHealthStatus { ResponseObserved, InvalidResponse, TimedOut, TransportError, TlsRejected, TlsFailed }
public enum HttpRedirectScope { NotRedirect, MissingLocation, InvalidLocation, SameOrigin, DifferentOrigin }
public sealed record HttpHeaderEvidence(string Name, IReadOnlyList<string> Values);
public sealed record HttpHealthObservation(IPAddress Source, IPAddress Target, int Port, string HostName,
    bool Https, HttpHealthStatus Status, int? StatusCode, IReadOnlyList<HttpHeaderEvidence> Headers,
    HttpRedirectScope Redirect, TlsCertificateEvidence? Certificate, DateTimeOffset ObservedUtc, TimeSpan Duration);

/// <summary>One explicit HEAD request to a scoped LAN peer. No redirects, body reads, proxy or credentials.</summary>
public static class HttpHealthSensor
{
    public static IReadOnlyList<int> AllowedPorts { get; } = Array.AsReadOnly(new[] { 80, 443, 8080, 8443 });
    public static TimeSpan Timeout { get; } = TimeSpan.FromSeconds(5);
    internal const int MaxHeaderBytes = 16 * 1024;
    private static readonly string[] HeaderNames =
        { "Server", "Strict-Transport-Security", "Content-Security-Policy", "Content-Security-Policy-Report-Only",
          "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy" };

    public static Task<HttpHealthObservation> CheckAsync(LocalLanInterface adapter, IPAddress target,
        int port, string hostName, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(target);
        token.ThrowIfCancellationRequested();
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(target))
            throw new ArgumentException("Target must be another host in the selected local IPv4 scope.", nameof(target));
        if (!AllowedPorts.Contains(port)) throw new ArgumentException("Select an approved HTTP(S) port.", nameof(port));
        var name = DnsIntegritySensor.NormalizeName(hostName);
        return CheckEndpointAsync(adapter.Address, target, port, name, port is 443 or 8443, Timeout, token);
    }

    internal static byte[] BuildRequest(string name, int port, bool https)
    {
        name = DnsIntegritySensor.NormalizeName(name);
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        string authority = port == (https ? 443 : 80) ? name : $"{name}:{port}";
        return Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: Carthago-ActiveSensor/1\r\n\r\n");
    }

    internal sealed record Parsed(int Code, IReadOnlyList<HttpHeaderEvidence> Headers, HttpRedirectScope Redirect);

    private static bool TokenChar(char c) => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
        || "!#$%&'*+-.^_`|~".Contains(c);

    internal static bool TryParse(byte[] bytes, Uri origin, out Parsed? parsed)
    {
        parsed = null;
        if (bytes.Length is < 16 or > MaxHeaderBytes ||
            !bytes.AsSpan(bytes.Length - 4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) return false;
        // Strict CRLF framing, no obsolete folded lines or control characters.
        var lines = Encoding.Latin1.GetString(bytes, 0, bytes.Length - 4).Split("\r\n", StringSplitOptions.None);
        if (lines.Length > 129 || lines[0].Length < 12 ||
            !(lines[0].StartsWith("HTTP/1.1 ", StringComparison.Ordinal) || lines[0].StartsWith("HTTP/1.0 ", StringComparison.Ordinal)) ||
            !lines[0].AsSpan(9, 3).ToArray().All(c => c is >= '0' and <= '9') ||
            !int.TryParse(lines[0].AsSpan(9, 3), out int code) || code is < 200 or > 599 ||
            (lines[0].Length > 12 && lines[0][12] != ' ') ||
            lines[0].Any(c => c < 32 || c == 127)) return false;
        var all = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon <= 0 || !line[..colon].All(TokenChar) ||
                line.Any(c => (c < 32 && c != '\t') || c == 127)) return false;
            string key = line[..colon], value = line[(colon + 1)..].Trim(' ', '\t');
            if (!all.TryGetValue(key, out var values)) all[key] = values = new List<string>();
            values.Add(value);
        }
        var headers = HeaderNames.Where(all.ContainsKey)
            .Select(name => new HttpHeaderEvidence(name, all[name].AsReadOnly())).ToArray();
        var redirect = HttpRedirectScope.NotRedirect;
        if (code is 301 or 302 or 303 or 307 or 308)
        {
            redirect = !all.TryGetValue("Location", out var locations) ? HttpRedirectScope.MissingLocation :
                locations.Count != 1 ? HttpRedirectScope.InvalidLocation : ClassifyRedirect(origin, locations[0]);
        }
        parsed = new(code, Array.AsReadOnly(headers), redirect);
        return true;
    }

    internal static HttpRedirectScope ClassifyRedirect(Uri origin, string location)
    {
        if (string.IsNullOrWhiteSpace(location) || location.Any(c => char.IsControl(c) || c == '\\') ||
            !Uri.TryCreate(origin, location, out var destination) ||
            (destination.Scheme != "http" && destination.Scheme != "https") ||
            !string.IsNullOrEmpty(destination.UserInfo)) return HttpRedirectScope.InvalidLocation;
        return destination.Scheme == origin.Scheme && destination.Port == origin.Port &&
            string.Equals(destination.IdnHost, origin.IdnHost, StringComparison.OrdinalIgnoreCase)
            ? HttpRedirectScope.SameOrigin : HttpRedirectScope.DifferentOrigin;
    }

    // Read exactly through the header terminator. Never deliberately consume body bytes.
    // A small bounded buffer and one overall budget also limit slow/malformed peers.
    internal static async Task<byte[]?> ReadHeaderAsync(Stream stream, CancellationToken token)
    {
        var bytes = new byte[MaxHeaderBytes];
        for (int used = 0; used < bytes.Length; used++)
        {
            if (await stream.ReadAsync(bytes.AsMemory(used, 1), token).ConfigureAwait(false) == 0) return null;
            if (used >= 3 && bytes[used - 3] == 13 && bytes[used - 2] == 10 &&
                bytes[used - 1] == 13 && bytes[used] == 10)
                return bytes.AsSpan(0, used + 1).ToArray();
        }
        return null;
    }

    internal static async Task<HttpHealthObservation> CheckEndpointAsync(IPAddress source, IPAddress target,
        int port, string name, bool https, TimeSpan timeout, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var request = BuildRequest(name, port, https);
        var origin = new UriBuilder(https ? "https" : "http", name, port).Uri;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(timeout);
        var watch = Stopwatch.StartNew();
        TlsCertificateEvidence? evidence = null;
        bool negotiating = false;
        HttpHealthObservation Result(HttpHealthStatus status, Parsed? response = null) =>
            new(source, target, port, name, https, status, response?.Code,
                response?.Headers ?? Array.Empty<HttpHeaderEvidence>(), response?.Redirect ?? HttpRedirectScope.NotRedirect,
                evidence, DateTimeOffset.UtcNow, watch.Elapsed);
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(source, 0));
            await socket.ConnectAsync(new IPEndPoint(target, port), budget.Token).ConfigureAwait(false);
            using var network = new NetworkStream(socket, ownsSocket: false);
            using var tls = https ? new SslStream(network, leaveInnerStreamOpen: true) : null;
            if (tls is not null)
            {
                negotiating = true;
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = name, EnabledSslProtocols = SslProtocols.None, AllowTlsResume = false,
                    CertificateChainPolicy = new X509ChainPolicy
                    { RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true },
                    RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
                    {
                        if (cert is null) return false;
                        using var leaf = new X509Certificate2(cert);
                        evidence = TlsInspectionSensor.Capture(leaf, errors, chain, null, DateTimeOffset.UtcNow);
                        return TlsInspectionSensor.AcceptCertificate(errors, evidence);
                    }
                }, budget.Token).ConfigureAwait(false);
                if (!tls.IsAuthenticated || !TlsInspectionSensor.AcceptCertificate(
                        evidence?.PolicyErrors ?? SslPolicyErrors.RemoteCertificateNotAvailable, evidence))
                    return Result(HttpHealthStatus.TlsFailed);
                negotiating = false;
            }
            token.ThrowIfCancellationRequested();
            budget.Token.ThrowIfCancellationRequested();
            Stream stream = tls is null ? network : tls;
            await stream.WriteAsync(request.AsMemory(), budget.Token).ConfigureAwait(false);
            var header = await ReadHeaderAsync(stream, budget.Token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) return Result(HttpHealthStatus.TimedOut);
            return header is not null && TryParse(header, origin, out var parsed)
                ? Result(HttpHealthStatus.ResponseObserved, parsed) : Result(HttpHealthStatus.InvalidResponse);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && budget.IsCancellationRequested)
        { return Result(HttpHealthStatus.TimedOut); }
        catch (AuthenticationException)
        {
            token.ThrowIfCancellationRequested();
            return Result(budget.IsCancellationRequested ? HttpHealthStatus.TimedOut :
                evidence is not null && evidence.PolicyErrors != SslPolicyErrors.None ? HttpHealthStatus.TlsRejected : HttpHealthStatus.TlsFailed);
        }
        catch (SocketException ex)
        {
            token.ThrowIfCancellationRequested();
            return Result(budget.IsCancellationRequested || ex.SocketErrorCode == SocketError.TimedOut
                ? HttpHealthStatus.TimedOut : HttpHealthStatus.TransportError);
        }
        catch (IOException)
        {
            token.ThrowIfCancellationRequested();
            return Result(budget.IsCancellationRequested ? HttpHealthStatus.TimedOut :
                negotiating ? evidence is not null && evidence.PolicyErrors != SslPolicyErrors.None
                    ? HttpHealthStatus.TlsRejected : HttpHealthStatus.TlsFailed : HttpHealthStatus.TransportError);
        }
    }
}
