// SPDX-License-Identifier: MIT
// R437 pinned relay transport GA — SOURCE CANDIDATE — UNVERIFIED.
// All credentials/certificates are ephemeral self-signed test fixtures only.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class RedisAuditMutualTlsRelayReceiverTests
{
    private static X509Certificate2 NewCertificate(string name,
        bool clientAuth = false, bool serverAuth = false,
        bool expired = false)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var usages = new OidCollection();
        if (clientAuth) usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        if (serverAuth) usages.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        if (usages.Count > 0)
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                usages, true));

        var now = DateTimeOffset.UtcNow;
        return expired
            ? request.CreateSelfSigned(now.AddDays(-3), now.AddDays(-1))
            : request.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
    }

    private static RedisAuditPinnedRelay Pin(X509Certificate2 client)
        => new("operator-redis-relay",
            Convert.ToHexString(client.GetCertHash(HashAlgorithmName.SHA256))
                .ToLowerInvariant());

    private static SslClientAuthenticationOptions ClientOptions(
        X509Certificate2 client, X509Certificate2 server)
        => new()
        {
            TargetHost = "localhost",
            ClientCertificates = new X509CertificateCollection { client },
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, remote, _, _) =>
            {
                if (remote == null) return false;
                using var peer = new X509Certificate2(remote);
                return CryptographicOperations.FixedTimeEquals(
                    peer.GetCertHash(HashAlgorithmName.SHA256),
                    server.GetCertHash(HashAlgorithmName.SHA256));
            }
        };

    private static byte[] Frame(byte[] eventBytes)
    {
        var output = new byte[4 + eventBytes.Length];
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(0, 4),
            eventBytes.Length);
        eventBytes.CopyTo(output, 4);
        return output;
    }

    private static async Task<RedisAuditRelaySessionResult> RunSessionAsync(
        X509Certificate2 server, X509Certificate2 actualClient,
        RedisAuditPinnedRelay configuredPin,
        byte[] framedPayload,
        RedisAuditRelayFrameHandler handler,
        bool useBridge = false)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var receiver = new RedisAuditMutualTlsRelayReceiver(server, configuredPin);
        var sessionTask = receiver.AcceptOneAsync(listener, handler, timeout.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,
            ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        using (var tlsClient = new SslStream(client.GetStream(), false))
        {
            try
            {
                await tlsClient.AuthenticateAsClientAsync(
                    ClientOptions(actualClient, server), timeout.Token);
                if (framedPayload.Length > 0)
                {
                    await tlsClient.WriteAsync(framedPayload, timeout.Token);
                    await tlsClient.FlushAsync(timeout.Token);
                }
            }
            catch (AuthenticationException)
            {
                // For negative certificates the server closes the connection
                // as soon as it rejects the presented mTLS client identity.
            }
            catch (IOException)
            {
                // A rejected TLS handshake can surface as an I/O failure on
                // the client depending on the Windows TLS provider.
            }
        }

        return await sessionTask.WaitAsync(timeout.Token);
    }

    [Fact]
    public void Client_Pinning_Requires_Exact_Certificate_Hash_Eku_And_Expiry()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var relay = NewCertificate("relay", clientAuth: true);
        using var other = NewCertificate("attacker", clientAuth: true);
        using var serverOnly = NewCertificate("wrong-eku", serverAuth: true);
        using var expired = NewCertificate("expired", clientAuth: true,
            expired: true);

        var receiver = new RedisAuditMutualTlsRelayReceiver(server, Pin(relay));
        Assert.True(receiver.IsPinnedRelayCertificate(relay, DateTimeOffset.UtcNow));
        Assert.False(receiver.IsPinnedRelayCertificate(other, DateTimeOffset.UtcNow));
        Assert.False(receiver.IsPinnedRelayCertificate(serverOnly, DateTimeOffset.UtcNow));
        Assert.False(receiver.IsPinnedRelayCertificate(expired, DateTimeOffset.UtcNow));
        Assert.False(receiver.IsPinnedRelayCertificate(null, DateTimeOffset.UtcNow));

        Assert.Throws<ArgumentException>(() => new RedisAuditMutualTlsRelayReceiver(
            server, new RedisAuditPinnedRelay("source", "not-a-hash")));
        Assert.Throws<ArgumentException>(() => new RedisAuditMutualTlsRelayReceiver(
            server, new RedisAuditPinnedRelay("source",
                Convert.ToHexString(relay.GetCertHash(HashAlgorithmName.SHA256)))));
    }

    [Fact]
    public async Task Pinned_Mtls_Receives_Two_Length_Framed_Events_Without_Retaining_Json()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var relay = NewCertificate("relay", clientAuth: true);
        var received = new List<(string Identity, RedisSoftwareAuditEventKind Kind)>();
        RedisAuditRelayFrameHandler handler = (identity, raw, _) =>
        {
            Assert.True(RedisSoftwareAuditNotificationParser.TryParse(
                raw, out var observation));
            received.Add((identity,
                Assert.IsType<RedisSoftwareAuditObservation>(observation).Kind));
            return ValueTask.CompletedTask;
        };

        var first = Frame(RedisSoftwareAuditSourceTests.Connection());
        var second = Frame(RedisSoftwareAuditSourceTests.Command());
        var bytes = new byte[first.Length + second.Length];
        first.CopyTo(bytes, 0);
        second.CopyTo(bytes, first.Length);

        var result = await RunSessionAsync(server, relay, Pin(relay),
            bytes, handler);
        Assert.Equal(RedisAuditRelaySessionStatus.Completed, result.Status);
        Assert.Equal(2, result.FramesRead);
        Assert.Equal(2, received.Count);
        Assert.All(received,
            item => Assert.Equal("operator-redis-relay", item.Identity));
        Assert.Equal(RedisSoftwareAuditEventKind.ConnectionOpened,
            received[0].Kind);
        Assert.Equal(RedisSoftwareAuditEventKind.Command, received[1].Kind);
        Assert.False(result.RedisServerAuthenticated);
        Assert.False(result.ConfigSetVerified);
        Assert.False(result.AlertPermitted);
    }

    [Fact]
    public async Task Wrong_Client_Certificate_Is_Rejected_Before_Any_Event()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var approved = NewCertificate("approved", clientAuth: true);
        using var attacker = NewCertificate("attacker", clientAuth: true);
        var count = 0;
        var result = await RunSessionAsync(server, attacker, Pin(approved),
            Frame(RedisSoftwareAuditSourceTests.Command()),
            (_, _, _) =>
            {
                count++;
                return ValueTask.CompletedTask;
            });
        Assert.Equal(RedisAuditRelaySessionStatus.PeerAuthenticationFailed,
            result.Status);
        Assert.Equal(0, count);
        Assert.False(result.AlertPermitted);
    }

    [Fact]
    public async Task Oversized_And_Zero_Length_Frames_Fail_Before_Handler()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var relay = NewCertificate("relay", clientAuth: true);
        foreach (var length in new[] { 0, 16385, int.MaxValue })
        {
            var prefix = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(prefix, length);
            var count = 0;
            var result = await RunSessionAsync(server, relay, Pin(relay),
                prefix, (_, _, _) =>
                {
                    count++;
                    return ValueTask.CompletedTask;
                });

            Assert.Equal(RedisAuditRelaySessionStatus.InvalidFrame, result.Status);
            Assert.Equal(0, count);
            Assert.Equal(0, result.FramesRead);
        }
    }

    [Fact]
    public async Task Malformed_Vendor_Event_Closes_Authenticated_Bridge()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var relay = NewCertificate("relay", clientAuth: true);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var receiver = new RedisAuditMutualTlsRelayReceiver(server, Pin(relay));
        var intake = new RedisSoftwareAuditDiagnosticIntake(
            new ApprovedAssetRegistry(new EnvironmentTuningOptions()));
        var bridge = new RedisAuditMutualTlsDiagnosticBridge(receiver, intake);
        var diagnostics = new List<RedisSoftwareWireCorrelationAssessment>();

        var receiving = bridge.AcceptOneAsync(listener,
            (_, _) => ValueTask.FromResult<(TrafficRecord?, DateTimeOffset)>(
                (null, DateTimeOffset.UtcNow)),
            (assessment, _) =>
            {
                diagnostics.Add(assessment);
                return ValueTask.CompletedTask;
            }, timeout.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,
            ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        using (var tls = new SslStream(client.GetStream()))
        {
            await tls.AuthenticateAsClientAsync(
                ClientOptions(relay, server), timeout.Token);
            await tls.WriteAsync(Frame(System.Text.Encoding.UTF8.GetBytes(
                "{bad-json")), timeout.Token);
            await tls.FlushAsync(timeout.Token);
        }

        var result = await receiving.WaitAsync(timeout.Token);
        Assert.Equal(RedisAuditRelaySessionStatus.HandlerRejected, result.Status);
        Assert.Single(diagnostics);
        Assert.Equal(RedisSoftwareWireCorrelationStatus.MalformedVendorNotification,
            diagnostics[0].Status);
        Assert.False(diagnostics[0].AlertPermitted);
    }

    [Fact]
    public async Task Bridge_Uses_Pinned_Relay_Id_For_Existing_Diagnostic_Intake()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var relay = NewCertificate("relay", clientAuth: true);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var options = new EnvironmentTuningOptions();
        options.Approved.RedisServers.Add("10.4.0.10");
        options.Approved.AdminHosts.Add("10.4.0.8");
        var bridge = new RedisAuditMutualTlsDiagnosticBridge(
            new RedisAuditMutualTlsRelayReceiver(server, Pin(relay)),
            new RedisSoftwareAuditDiagnosticIntake(
                new ApprovedAssetRegistry(options)));
        var diagnostics = new List<RedisSoftwareWireCorrelationStatus>();
        var capture = new TrafficRecord
        {
            Source = "10.4.0.10", Destination = "10.4.0.9",
            SourcePort = 6379, DestinationPort = 40000,
            Protocol = "TCP", ApplicationProtocol = "redis.resp2",
            IsTcp = true, RedisRespConfigSetReplyOkObserved = true
        };

        var receiving = bridge.AcceptOneAsync(listener,
            (_, _) => ValueTask.FromResult<(TrafficRecord?, DateTimeOffset)>(
                (capture, DateTimeOffset.FromUnixTimeSeconds(
                    RedisSoftwareAuditSourceTests.EventSecond))),
            (assessment, _) =>
            {
                diagnostics.Add(assessment.Status);
                return ValueTask.CompletedTask;
            }, timeout.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,
            ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        using (var tls = new SslStream(client.GetStream()))
        {
            await tls.AuthenticateAsClientAsync(
                ClientOptions(relay, server), timeout.Token);
            var first = Frame(RedisSoftwareAuditSourceTests.Connection());
            var second = Frame(RedisSoftwareAuditSourceTests.Command());
            await tls.WriteAsync(first, timeout.Token);
            await tls.WriteAsync(second, timeout.Token);
            await tls.FlushAsync(timeout.Token);
        }

        var result = await receiving.WaitAsync(timeout.Token);
        Assert.Equal(RedisAuditRelaySessionStatus.Completed, result.Status);
        Assert.Equal(2, result.FramesRead);
        Assert.Equal(2, diagnostics.Count);
        Assert.Equal(RedisSoftwareWireCorrelationStatus.AuditNotCommand,
            diagnostics[0]);
        Assert.Equal(RedisSoftwareWireCorrelationStatus.GenericConfigSubcommandUnproven,
            diagnostics[1]);
        Assert.False(result.AlertPermitted);
    }

    [Fact]
    public async Task Refuses_Non_Loopback_Listener_Before_Accepting_Connections()
    {
        using var server = NewCertificate("server", serverAuth: true);
        using var relay = NewCertificate("relay", clientAuth: true);
        using var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();

        var receiver = new RedisAuditMutualTlsRelayReceiver(server, Pin(relay));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            receiver.AcceptOneAsync(listener,
                (_, _, _) => ValueTask.CompletedTask));
    }
}
