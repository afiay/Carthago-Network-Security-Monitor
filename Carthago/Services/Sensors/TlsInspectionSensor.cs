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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services.Sensors;

public enum TlsInspectionStatus
{
    Authenticated, CertificateRejected, HandshakeFailed, TimedOut, TransportError
}

public sealed record TlsCertificateEvidence(string Subject, string Issuer, string SerialNumber,
    string Sha256, DateTimeOffset NotBeforeUtc, DateTimeOffset NotAfterUtc, string Validity,
    string? DnsNames, string? DnsNameEvidence, SslPolicyErrors PolicyErrors,
    IReadOnlyList<X509ChainStatusFlags> ChainErrors, bool? FingerprintMatches);

public sealed record TlsInspectionObservation(IPAddress Source, IPAddress Target, int Port,
    string HostName, TlsInspectionStatus Status, TlsCertificateEvidence? Certificate,
    string? Protocol, string? CipherSuite, DateTimeOffset ObservedUtc, TimeSpan Duration);

/// <summary>One explicitly requested, source-bound TLS handshake. Reject invalid certificates;
/// retain their observation separately from authentication. No application payload.</summary>
public static class TlsInspectionSensor
{
    public static IReadOnlyList<int> AllowedPorts { get; } = Array.AsReadOnly(new[] { 443, 8443, 5986, 636, 8883 });
    public static TimeSpan Timeout { get; } = TimeSpan.FromSeconds(5);

    public static Task<TlsInspectionObservation> CheckAsync(LocalLanInterface adapter, IPAddress target,
        int port, string hostName, string? expectedSha256 = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(target);
        token.ThrowIfCancellationRequested();
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(target))
            throw new ArgumentException("Target must be another host in the selected local IPv4 scope.", nameof(target));
        if (!AllowedPorts.Contains(port))
            throw new ArgumentException("Select an approved direct TLS port.", nameof(port));
        var name = DnsIntegritySensor.NormalizeName(hostName);
        var fingerprint = NormalizeFingerprint(expectedSha256);
        return CheckEndpointAsync(adapter.Address, target, port, name, fingerprint, Timeout, token);
    }

    internal static string? NormalizeFingerprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var normalized = value.Trim().ToLowerInvariant();
        if (normalized.Length != 64 || normalized.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new ArgumentException("Expected fingerprint must be 64 hexadecimal SHA-256 characters.", nameof(value));
        return normalized;
    }

    internal static TlsCertificateEvidence Capture(X509Certificate2 cert, SslPolicyErrors errors,
        X509Chain? chain, string? expected, DateTimeOffset now)
    {
        // Reuse existing certificate SAN and validity extraction; never enqueue a TrafficRecord.
        var record = new TrafficRecord();
        TlsIdentityEnrichment.ApplyCertificate(record, cert);
        var hash = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        var from = new DateTimeOffset(cert.NotBefore.ToUniversalTime());
        var to = new DateTimeOffset(cert.NotAfter.ToUniversalTime());
        return new(cert.Subject, cert.Issuer, cert.SerialNumber, hash, from, to,
            TlsIdentityEnrichment.Validity(from.UtcDateTime, to.UtcDateTime, now.UtcDateTime),
            record.TlsCertificateDnsNames, record.TlsCertificateNameStatus, errors,
            Array.AsReadOnly(chain?.ChainStatus.Select(s => s.Status).ToArray() ?? Array.Empty<X509ChainStatusFlags>()),
            expected is null ? null : string.Equals(hash, expected, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool AcceptCertificate(SslPolicyErrors errors, TlsCertificateEvidence? evidence) =>
        errors == SslPolicyErrors.None && evidence is not null;

    // Internal endpoint seam also permits isolated loopback tests; the public entry enforces LAN scope.
    internal static async Task<TlsInspectionObservation> CheckEndpointAsync(IPAddress source,
        IPAddress target, int port, string name, string? fingerprint, TimeSpan timeout, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(timeout);
        var watch = Stopwatch.StartNew();
        TlsCertificateEvidence? evidence = null;
        TlsInspectionObservation Result(TlsInspectionStatus status, string? protocol = null, string? cipher = null) =>
            new(source, target, port, name, status, evidence, protocol, cipher, DateTimeOffset.UtcNow, watch.Elapsed);
        bool validating = false;
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(source, 0));
            await socket.ConnectAsync(new IPEndPoint(target, port), budget.Token).ConfigureAwait(false);
            using var stream = new NetworkStream(socket, ownsSocket: false);
            using var tls = new SslStream(stream, leaveInnerStreamOpen: false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = name, // SNI and platform hostname verification; no DNS resolution
                EnabledSslProtocols = SslProtocols.None,
                AllowTlsResume = false,
                CertificateChainPolicy = new X509ChainPolicy
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    DisableCertificateDownloads = true
                },
                RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
                {
                    if (cert is null) return false;
                    using var leaf = new X509Certificate2(cert);
                    evidence = Capture(leaf, errors, chain, fingerprint, DateTimeOffset.UtcNow);
                    return AcceptCertificate(errors, evidence); // no trust bypass, even on fingerprint match
                }
            };
            validating = true;
            await tls.AuthenticateAsClientAsync(options, budget.Token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) return Result(TlsInspectionStatus.TimedOut);
            if (!tls.IsAuthenticated || !AcceptCertificate(evidence?.PolicyErrors ?? SslPolicyErrors.RemoteCertificateNotAvailable, evidence))
                return Result(TlsInspectionStatus.HandshakeFailed);
            return Result(TlsInspectionStatus.Authenticated, tls.SslProtocol.ToString(), tls.NegotiatedCipherSuite.ToString());
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && budget.IsCancellationRequested)
        {
            return Result(TlsInspectionStatus.TimedOut);
        }
        catch (AuthenticationException)
        {
            token.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) return Result(TlsInspectionStatus.TimedOut);
            return Result(evidence is not null && evidence.PolicyErrors != SslPolicyErrors.None
                ? TlsInspectionStatus.CertificateRejected : TlsInspectionStatus.HandshakeFailed);
        }
        catch (SocketException ex)
        {
            token.ThrowIfCancellationRequested();
            return Result(budget.IsCancellationRequested || ex.SocketErrorCode == SocketError.TimedOut
                ? TlsInspectionStatus.TimedOut : TlsInspectionStatus.TransportError);
        }
        catch (IOException)
        {
            token.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) return Result(TlsInspectionStatus.TimedOut);
            return Result(evidence is not null && evidence.PolicyErrors != SslPolicyErrors.None
                ? TlsInspectionStatus.CertificateRejected : validating ? TlsInspectionStatus.HandshakeFailed : TlsInspectionStatus.TransportError);
        }
    }
}
