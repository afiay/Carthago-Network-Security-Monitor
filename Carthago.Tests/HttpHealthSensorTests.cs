// SPDX-License-Identifier: MIT
using System.Net;
using System.Net.Sockets;
using System.Text;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class HttpHealthSensorTests
{
    private static readonly LocalLanInterface Adapter = new("test", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.1.131");
    private static readonly Uri Origin = new("https://lab.example/");
    private static byte[] Wire(string text) => Encoding.ASCII.GetBytes(text);

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.168.1.128")]
    [InlineData("192.168.1.130")]
    [InlineData("192.168.1.255")]
    [InlineData("127.0.0.1")]
    public void ScopeRejected(string address) =>
        Assert.Throws<ArgumentException>(() => { _ = HttpHealthSensor.CheckAsync(Adapter, IPAddress.Parse(address), 80, "lab.example"); });

    [Theory]
    [InlineData(0)]
    [InlineData(22)]
    [InlineData(65536)]
    public void PortRejected(int port) =>
        Assert.Throws<ArgumentException>(() => { _ = HttpHealthSensor.CheckAsync(Adapter, Target, port, "lab.example"); });

    [Fact]
    public void RequestIsSingleHeadWithNoCredentials()
    {
        string request = Encoding.ASCII.GetString(HttpHealthSensor.BuildRequest("LAB.Example.", 8443, true));
        Assert.StartsWith("HEAD / HTTP/1.1\r\nHost: lab.example:8443\r\n", request);
        Assert.EndsWith("\r\n\r\n", request);
        Assert.DoesNotContain("Authorization:", request);
        Assert.DoesNotContain("Cookie:", request);
        Assert.Throws<ArgumentException>(() => HttpHealthSensor.BuildRequest("lab.example\r\nX-Evil: yes", 80, false));
    }

    [Theory]
    [InlineData(200)]
    [InlineData(401)]
    [InlineData(405)]
    [InlineData(503)]
    public void StatusIsObservedNotAutomaticallyHealthy(int code)
    {
        Assert.True(HttpHealthSensor.TryParse(Wire($"HTTP/1.1 {code} status\r\nServer: Lab\r\n\r\n"), Origin, out var parsed));
        Assert.Equal(code, parsed!.Code);
        Assert.Equal("Lab", Assert.Single(Assert.Single(parsed.Headers).Values));
    }

    [Fact]
    public void SelectedHeadersRetainDuplicatesWithoutCookiesOrLocation()
    {
        var response = Wire("HTTP/1.1 200 OK\r\nContent-Security-Policy: a\r\ncontent-security-policy: b\r\nSet-Cookie: secret\r\nLocation: /secret\r\n\r\n");
        Assert.True(HttpHealthSensor.TryParse(response, Origin, out var parsed));
        var header = Assert.Single(parsed!.Headers);
        Assert.Equal("Content-Security-Policy", header.Name);
        Assert.Equal(new[] { "a", "b" }, header.Values.ToArray());
    }

    [Theory]
    [InlineData("/next", HttpRedirectScope.SameOrigin)]
    [InlineData("https://LAB.example:443/next", HttpRedirectScope.SameOrigin)]
    [InlineData("http://lab.example/", HttpRedirectScope.DifferentOrigin)]
    [InlineData("//other.example/", HttpRedirectScope.DifferentOrigin)]
    [InlineData("https://lab.example:8443/", HttpRedirectScope.DifferentOrigin)]
    [InlineData("https://user@lab.example/", HttpRedirectScope.InvalidLocation)]
    [InlineData("file:///tmp/a", HttpRedirectScope.InvalidLocation)]
    [InlineData("", HttpRedirectScope.InvalidLocation)]
    public void RedirectIsClassifiedWithoutFollowing(string location, HttpRedirectScope expected)
    {
        Assert.True(HttpHealthSensor.TryParse(Wire($"HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n"), Origin, out var parsed));
        Assert.Equal(expected, parsed!.Redirect);
        Assert.Empty(parsed.Headers);
    }

    [Theory]
    [InlineData("HTTP/1.1 302 Found\r\n\r\n", HttpRedirectScope.MissingLocation)]
    [InlineData("HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\n\r\n", HttpRedirectScope.InvalidLocation)]
    [InlineData("HTTP/1.1 304 Not Modified\r\nLocation: /a\r\n\r\n", HttpRedirectScope.NotRedirect)]
    public void RedirectEdgeCases(string wire, HttpRedirectScope expected)
    {
        Assert.True(HttpHealthSensor.TryParse(Wire(wire), Origin, out var parsed));
        Assert.Equal(expected, parsed!.Redirect);
    }

    [Theory]
    [InlineData("HTTP/1.1 100 Continue\r\n\r\n")]
    [InlineData("HTTP/1.1 999 Bad\r\n\r\n")]
    [InlineData("HTTP/2 200 OK\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\nServer: a\n\n")]
    [InlineData("HTTP/1.1 200 OK\r\nServer : a\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nServer: a\r\n folded\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nServer: a\u0001\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nServer: a\r\n")]
    public void MalformedOrUnsupportedResponseRejected(string wire) =>
        Assert.False(HttpHealthSensor.TryParse(Wire(wire), Origin, out _));

    [Fact]
    public async Task HeaderReaderStopsBeforeBodyAndRejectsOversized()
    {
        var header = Wire("HTTP/1.1 200 OK\r\nServer: Lab\r\n\r\n");
        using var stream = new MemoryStream(header.Concat(Wire("BODY")).ToArray());
        Assert.Equal(header, await HttpHealthSensor.ReadHeaderAsync(stream, default));
        Assert.Equal((long)header.Length, stream.Position);
        using var oversized = new MemoryStream(new byte[HttpHealthSensor.MaxHeaderBytes + 1]);
        Assert.Null(await HttpHealthSensor.ReadHeaderAsync(oversized, default));
        Assert.Equal((long)HttpHealthSensor.MaxHeaderBytes, oversized.Position);
    }

    [Fact]
    public async Task LoopbackRedirectProducesOneHeadAndNoSecondConnection()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var client = HttpHealthSensor.CheckEndpointAsync(IPAddress.Loopback, IPAddress.Loopback,
                port, "lab.example", false, TimeSpan.FromSeconds(5), cts.Token);
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            using var stream = peer.GetStream();
            var request = await HttpHealthSensor.ReadHeaderAsync(stream, cts.Token);
            Assert.NotNull(request);
            Assert.StartsWith("HEAD / HTTP/1.1\r\n", Encoding.ASCII.GetString(request!));
            await stream.WriteAsync(Wire("HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\n\r\n").AsMemory(), cts.Token);
            var result = await client;
            Assert.Equal(HttpHealthStatus.ResponseObserved, result.Status);
            Assert.Equal(HttpRedirectScope.DifferentOrigin, result.Redirect);
            Assert.False(listener.Pending());
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task SilentEndpointTimesOut()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            var client = HttpHealthSensor.CheckEndpointAsync(IPAddress.Loopback, IPAddress.Loopback,
                ((IPEndPoint)listener.LocalEndpoint).Port, "lab.example", false, TimeSpan.FromMilliseconds(300), cts.Token);
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            Assert.Equal(HttpHealthStatus.TimedOut, (await client).Status);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task UntrustedHttpsPeerCannotReceiveHttpRequest()
    {
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var certRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=lab.example", key, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var san = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
        san.AddDnsName("lab.example");
        certRequest.CertificateExtensions.Add(san.Build());
        using var cert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        async Task<int> Serve()
        {
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            using var tls = new System.Net.Security.SslStream(peer.GetStream());
            try
            {
                await tls.AuthenticateAsServerAsync(new System.Net.Security.SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                }, cts.Token);
                var buffer = new byte[1];
                return await tls.ReadAsync(buffer.AsMemory(), cts.Token);
            }
            catch (System.Security.Authentication.AuthenticationException) { return 0; }
            catch (System.IO.IOException) { return 0; }
        }
        var server = Serve();
        try
        {
            var result = await HttpHealthSensor.CheckEndpointAsync(IPAddress.Loopback, IPAddress.Loopback,
                ((IPEndPoint)listener.LocalEndpoint).Port, "wrong.example", true, TimeSpan.FromSeconds(5), cts.Token);
            Assert.Equal(HttpHealthStatus.TlsRejected, result.Status);
            Assert.NotNull(result.Certificate);
            Assert.True(result.Certificate!.PolicyErrors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch));
            Assert.Null(result.StatusCode);
            Assert.Empty(result.Headers);
            Assert.Equal(0, await server);
        }
        finally
        {
            listener.Stop();
            cts.Cancel();
            try { await server; } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public void PreCancelledRequestDoesNotConnect()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => { _ = HttpHealthSensor.CheckAsync(Adapter, Target, 80, "lab.example", cts.Token); });
    }
}
