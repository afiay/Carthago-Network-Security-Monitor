// SPDX-License-Identifier: MIT
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class TlsInspectionSensorTests
{
    private static readonly LocalLanInterface Adapter = new("test", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.1.131");

    private static X509Certificate2 Certificate(DateTimeOffset start, DateTimeOffset end)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=lab.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("lab.example");
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(start, end);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.168.1.128")]
    [InlineData("192.168.1.130")]
    [InlineData("192.168.1.255")]
    [InlineData("192.168.1.1")]
    [InlineData("127.0.0.1")]
    public void OutOfScopeRejected(string target) =>
        Assert.Throws<ArgumentException>(() => { _ = TlsInspectionSensor.CheckAsync(Adapter, IPAddress.Parse(target), 443, "lab.example"); });

    [Theory]
    [InlineData(0)]
    [InlineData(80)]
    [InlineData(25)]
    [InlineData(65536)]
    public void NonApprovedPortsRejected(int port) =>
        Assert.Throws<ArgumentException>(() => { _ = TlsInspectionSensor.CheckAsync(Adapter, Target, port, "lab.example"); });

    [Theory]
    [InlineData("https://lab.example")]
    [InlineData("192.168.1.131")]
    [InlineData("bad..example")]
    public void InvalidIdentityRejected(string name) =>
        Assert.Throws<ArgumentException>(() => { _ = TlsInspectionSensor.CheckAsync(Adapter, Target, 443, name); });

    [Fact]
    public void FingerprintValidationAndNormalization()
    {
        Assert.Null(TlsInspectionSensor.NormalizeFingerprint(" "));
        Assert.Equal(new string('a', 64), TlsInspectionSensor.NormalizeFingerprint(new string('A', 64)));
        Assert.Throws<ArgumentException>(() => TlsInspectionSensor.NormalizeFingerprint(new string('g', 64)));
        Assert.Throws<ArgumentException>(() => TlsInspectionSensor.NormalizeFingerprint("abcd"));
    }

    [Theory]
    [InlineData(-2, -1, "Expired")]
    [InlineData(1, 2, "NotYetValid")]
    [InlineData(-1, 1, "WithinValidityPeriod")]
    public void ValidityAndFingerprintAreEvidenceNotTrust(int start, int end, string status)
    {
        var now = DateTimeOffset.UtcNow;
        using var cert = Certificate(now.AddDays(start), now.AddDays(end));
        var sha = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        var evidence = TlsInspectionSensor.Capture(cert, SslPolicyErrors.RemoteCertificateChainErrors, null, sha, now);
        Assert.Equal(status, evidence.Validity);
        Assert.Equal("lab.example", evidence.DnsNames);
        Assert.Equal(sha, evidence.Sha256);
        Assert.True(evidence.FingerprintMatches == true);
        Assert.False(TlsInspectionSensor.AcceptCertificate(evidence.PolicyErrors, evidence));
        Assert.False(TlsInspectionSensor.Capture(cert, evidence.PolicyErrors, null, new string('0', 64), now).FingerprintMatches == true);
    }

    [Fact]
    public void NoCertificateCannotAuthenticate()
        => Assert.False(TlsInspectionSensor.AcceptCertificate(SslPolicyErrors.None, null));

    [Fact]
    public void PolicyErrorsAreNeverOverriddenByExpectedFingerprint()
    {
        var now = DateTimeOffset.UtcNow;
        using var cert = Certificate(now.AddDays(-1), now.AddDays(1));
        var sha = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        var valid = TlsInspectionSensor.Capture(cert, SslPolicyErrors.None, null, sha, now);
        Assert.True(TlsInspectionSensor.AcceptCertificate(SslPolicyErrors.None, valid));
        Assert.False(TlsInspectionSensor.AcceptCertificate(SslPolicyErrors.RemoteCertificateNameMismatch, valid));
        Assert.False(TlsInspectionSensor.AcceptCertificate(SslPolicyErrors.RemoteCertificateChainErrors, valid));
    }

    [Fact]
    public async Task SelfSignedLoopbackHandshakeRetainsEvidenceButRejectsTrust()
    {
        var now = DateTimeOffset.UtcNow;
        using var cert = Certificate(now.AddDays(-1), now.AddDays(1));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        async Task Serve()
        {
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            using var tls = new SslStream(peer.GetStream());
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                { ServerCertificate = cert, EnabledSslProtocols = SslProtocols.Tls12 }, cts.Token);
            }
            catch (AuthenticationException) { }
            catch (System.IO.IOException) { }
        }
        var server = Serve();
        try
        {
            var result = await TlsInspectionSensor.CheckEndpointAsync(IPAddress.Loopback, IPAddress.Loopback,
                ((IPEndPoint)listener.LocalEndpoint).Port, "wrong.example", null, TimeSpan.FromSeconds(5), cts.Token);
            Assert.Equal(TlsInspectionStatus.CertificateRejected, result.Status);
            Assert.NotNull(result.Certificate);
            Assert.True(result.Certificate!.PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch));
            Assert.Null(result.Protocol);
            Assert.Null(result.CipherSuite);
        }
        finally { listener.Stop(); cts.Cancel(); try { await server; } catch (OperationCanceledException) { } }
    }

    [Fact]
    public async Task SilentLoopbackEndpointTimesOutWithoutCertificate()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            var client = TlsInspectionSensor.CheckEndpointAsync(IPAddress.Loopback, IPAddress.Loopback,
                ((IPEndPoint)listener.LocalEndpoint).Port, "lab.example", null, TimeSpan.FromMilliseconds(300), cts.Token);
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            var result = await client;
            Assert.Equal(TlsInspectionStatus.TimedOut, result.Status);
            Assert.Null(result.Certificate);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public void PreCancelledRequestStopsBeforeConnect()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => { _ = TlsInspectionSensor.CheckAsync(Adapter, Target, 443, "lab.example", token: cts.Token); });
    }
}
