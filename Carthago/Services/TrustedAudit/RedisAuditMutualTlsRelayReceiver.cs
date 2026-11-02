// SPDX-License-Identifier: MIT
// R437 authenticated relay-transport boundary — SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Operator-provisioned relay identity. The hex SHA-256 is the hash of the
    /// complete client TLS certificate DER; the relay identifier does not come
    /// from a vendor notification, TCP peer claim or JSON payload.
    /// </summary>
    public sealed record RedisAuditPinnedRelay(string RelayId, string ClientCertificateSha256Hex);

    public enum RedisAuditRelaySessionStatus
    {
        PeerAuthenticationFailed,
        InvalidFrame,
        HandlerRejected,
        IdleTimeout,
        FrameBudgetExceeded,
        Completed
    }

    /// <summary>
    /// An authenticated relay connection is NOT an authenticated Redis server.
    /// Accepted frame counts are not proof Redis emitted/delivered every event.
    /// </summary>
    public sealed record RedisAuditRelaySessionResult(
        RedisAuditRelaySessionStatus Status,
        int FramesRead,
        string Diagnostic)
    {
        public bool RedisServerAuthenticated => false;
        public bool ConfigSetVerified => false;
        public bool AlertPermitted => false;
    }

    public delegate ValueTask RedisAuditRelayFrameHandler(
        string provisionedRelayId, ReadOnlyMemory<byte> completeVendorJson,
        CancellationToken cancellationToken);

    /// <summary>
    /// Opt-in local mTLS receiver for an operator-managed forwarding relay.
    ///
    /// Redis Software's vendor audit sink is plain, best-effort TCP and does
    /// NOT connect directly to this receiver. An operator-provisioned relay
    /// must separately receive and delimit Redis Software notifications and
    /// send precisely one length-prefixed JSON event per frame over mTLS.
    ///
    /// The receiver binds no sockets by itself, does not install certificates
    /// or generate trust keys, and refuses listeners not bound to loopback.
    /// The framed callback receives a certificate-pinned RELAY identity, never
    /// a claim of authenticated Redis daemon identity.
    /// </summary>
    public sealed class RedisAuditMutualTlsRelayReceiver
    {
        private const int MaxFrameBytes = 16 * 1024;
        private const int MaxFramesPerSession = 512;
        private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(15);

        private readonly X509Certificate2 _serverCertificate;
        private readonly string _relayId;
        private readonly byte[] _pinnedLeafSha256;

        public RedisAuditMutualTlsRelayReceiver(
            X509Certificate2 serverCertificate, RedisAuditPinnedRelay relay)
        {
            _serverCertificate = serverCertificate
                ?? throw new ArgumentNullException(nameof(serverCertificate));
            if (!_serverCertificate.HasPrivateKey
                || !ValidAt(_serverCertificate, DateTimeOffset.UtcNow))
                throw new ArgumentException(
                    "The TLS receiver needs an unexpired server certificate with private key.",
                    nameof(serverCertificate));

            if (relay == null || !ValidRelayId(relay.RelayId)
                || relay.ClientCertificateSha256Hex is not { Length: 64 }
                || !IsLowercaseHex(relay.ClientCertificateSha256Hex))
                throw new ArgumentException(
                    "Pin an explicit relay identity and lowercase SHA-256 certificate hash.",
                    nameof(relay));

            _relayId = relay.RelayId;
            _pinnedLeafSha256 = Convert.FromHexString(relay.ClientCertificateSha256Hex);
        }

        /// <summary>
        /// Reusable TLS peer-verification primitive: exact pinned client cert
        /// DER hash, certificate validity period and client-auth EKU. A
        /// deliberately operator-pinned self-signed relay cert is supported,
        /// with no implicit trust in a public CA or a claimed DNS name.
        /// The TLS receiver's server certificate is independently provisioned.
        /// </summary>
        public bool IsPinnedRelayCertificate(X509Certificate2? peer,
            DateTimeOffset checkedAtUtc)
        {
            if (peer == null || !ValidAt(peer, checkedAtUtc)
                || !ClientAuthenticationAllowed(peer))
                return false;

            try
            {
                var actualSha = peer.GetCertHash(HashAlgorithmName.SHA256);
                return CryptographicOperations.FixedTimeEquals(
                    actualSha, _pinnedLeafSha256);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>
        /// Accepts exactly one relay connection on an already-started,
        /// loopback-bound TcpListener. Callers own listener lifecycle and must
        /// explicitly invoke this API; no automatic background listener exists.
        /// A 4-byte unsigned big-endian frame size (1..16384) precedes each
        /// vendor JSON event. The callback must complete before its memory is
        /// wiped; it should parse immediately and must not retain frame bytes.
        ///
        /// Cancellation is fail-fast and controlled by the owner; this method
        /// accepts one connection only, never queues sessions or raw audit data.
        /// </summary>
        public async Task<RedisAuditRelaySessionResult> AcceptOneAsync(
            TcpListener listener, RedisAuditRelayFrameHandler onFrame,
            CancellationToken cancellationToken = default)
        {
            if (listener == null)
                throw new ArgumentNullException(nameof(listener));
            if (onFrame == null)
                throw new ArgumentNullException(nameof(onFrame));
            if (listener.LocalEndpoint is not IPEndPoint endpoint
                || !IPAddress.IsLoopback(endpoint.Address))
                throw new ArgumentException(
                    "The audit receiver must listen on IPv4/IPv6 loopback only.",
                    nameof(listener));

            using var connection = await listener.AcceptTcpClientAsync(
                cancellationToken).ConfigureAwait(false);
            connection.NoDelay = true;

            using var tls = new SslStream(connection.GetStream(),
                leaveInnerStreamOpen: false,
                (_, peerCertificate, _, _) =>
                {
                    try
                    {
                        if (peerCertificate == null) return false;
                        using var peer = new X509Certificate2(peerCertificate);
                        return IsPinnedRelayCertificate(peer, DateTimeOffset.UtcNow);
                    }
                    catch (CryptographicException)
                    {
                        return false;
                    }
                });

            // The leaf certificate pin is the complete relay trust root.
            // No global CA store, packet metadata, Redis JSON issuer field
            // or certificate subject is accepted as a source identity.
            var serverOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _serverCertificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };

            using var sessionBudget = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            sessionBudget.CancelAfter(IdleTimeout);
            try
            {
                await tls.AuthenticateAsServerAsync(
                    serverOptions, sessionBudget.Token).ConfigureAwait(false);
            }
            catch (AuthenticationException)
            {
                return new(RedisAuditRelaySessionStatus.PeerAuthenticationFailed, 0,
                    "R437_RELAY_MTLS_AUTHENTICATION_REJECTED");
            }
            catch (IOException)
            {
                return new(RedisAuditRelaySessionStatus.PeerAuthenticationFailed, 0,
                    "R437_RELAY_MTLS_TRANSPORT_INTERRUPTED");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new(RedisAuditRelaySessionStatus.IdleTimeout, 0,
                    "R437_RELAY_MTLS_HANDSHAKE_TIMEOUT");
            }

            var frames = 0;
            var lengthPrefix = new byte[4];
            while (frames < MaxFramesPerSession)
            {
                // This budget is reset ONLY after a complete authenticated
                // event was handled; slowloris/truncated frames fail closed.
                sessionBudget.CancelAfter(IdleTimeout);
                int first;
                try
                {
                    first = await tls.ReadAsync(
                        lengthPrefix.AsMemory(0, 1), sessionBudget.Token)
                        .ConfigureAwait(false);
                    if (first == 0)
                        return new(RedisAuditRelaySessionStatus.Completed, frames,
                            "R437_RELAY_MTLS_SESSION_COMPLETE");
                    await tls.ReadExactlyAsync(
                        lengthPrefix.AsMemory(1, 3), sessionBudget.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return new(RedisAuditRelaySessionStatus.IdleTimeout, frames,
                        "R437_RELAY_MTLS_FRAME_TIMEOUT");
                }
                catch (IOException)
                {
                    return new(RedisAuditRelaySessionStatus.InvalidFrame, frames,
                        "R437_RELAY_MTLS_TRUNCATED_PREFIX");
                }

                var length = BinaryPrimitives.ReadInt32BigEndian(lengthPrefix);
                if (length is <= 0 or > MaxFrameBytes)
                    return new(RedisAuditRelaySessionStatus.InvalidFrame, frames,
                        "R437_RELAY_MTLS_INVALID_FRAME_LENGTH");

                var buffer = new byte[length];
                try
                {
                    await tls.ReadExactlyAsync(buffer.AsMemory(),
                        sessionBudget.Token).ConfigureAwait(false);
                    await onFrame(_relayId, buffer, sessionBudget.Token)
                        .ConfigureAwait(false);
                    frames++;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return new(RedisAuditRelaySessionStatus.IdleTimeout, frames,
                        "R437_RELAY_MTLS_FRAME_TIMEOUT");
                }
                catch (IOException)
                {
                    return new(RedisAuditRelaySessionStatus.InvalidFrame, frames,
                        "R437_RELAY_MTLS_TRUNCATED_FRAME");
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Callback errors never become success and never leak raw
                    // audit content through exception messages or diagnostics.
                    return new(RedisAuditRelaySessionStatus.HandlerRejected, frames,
                        "R437_RELAY_MTLS_FRAME_HANDLER_REJECTED");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer);
                }
            }

            return new(RedisAuditRelaySessionStatus.FrameBudgetExceeded, frames,
                "R437_RELAY_MTLS_SESSION_FRAME_BUDGET_EXHAUSTED");
        }

        private static bool ValidAt(X509Certificate2 cert, DateTimeOffset now)
            => now.UtcDateTime >= cert.NotBefore.ToUniversalTime()
                && now.UtcDateTime <= cert.NotAfter.ToUniversalTime();

        private static bool ClientAuthenticationAllowed(X509Certificate2 cert)
        {
            // Certificates with no EKU extension are rejected: the relay must
            // explicitly have client-auth capability, not a server-only cert.
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509EnhancedKeyUsageExtension eku)
                {
                    foreach (var oid in eku.EnhancedKeyUsages)
                        if (oid.Value == "1.3.6.1.5.5.7.3.2")
                            return true;
                    return false;
                }
            }
            return false;
        }

        private static bool ValidRelayId(string? id)
        {
            if (id is not { Length: >= 3 and <= 64 }) return false;
            foreach (var c in id)
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))
                    return false;
            return true;
        }

        private static bool IsLowercaseHex(string text)
        {
            foreach (var c in text)
                if (c is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
                    return false;
            return true;
        }
    }
}
