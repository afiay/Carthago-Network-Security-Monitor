// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using Carthago.Engine.Rules;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableApplicationParserTests
{
    [Fact]
    public void ApplicationParsersAndCredentialContractShareCore()
    {
        var core=typeof(HttpLight).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        Assert.Same(core,typeof(TlsLight).Assembly);
        Assert.Same(core,typeof(DnsLight).Assembly);
        Assert.Same(core,typeof(QuicLight).Assembly);
        Assert.Same(core,typeof(SensitiveTelemetryContracts).Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a =>
            a.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Theory]
    [InlineData("Authorization")]
    [InlineData("Cookie")]
    [InlineData("X-Api-Key")]
    [InlineData("X-Vault-Token")]
    public void HttpSensitiveHeadersAreRedacted(string header)
    {
        const string secret="synthetic-private-fixture";
        var request=Encoding.ASCII.GetBytes("GET /admin HTTP/1.1\r\nHost: example.test\r\n"+
            header+": "+secret+"\r\n\r\n");
        Assert.True(HttpLight.TryParseHttp(request,out var info));
        Assert.Equal("GET",info.Method);
        Assert.Equal("/admin",info.Path);
        Assert.Equal("example.test",info.Host);
        Assert.Contains(header+": [REDACTED]",info.JoinedHeaderLines);
        Assert.DoesNotContain(secret,info.JoinedHeaderLines);
    }

    [Theory]
    [InlineData("Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n",true)]
    [InlineData("Authorization: Basic YWRtaW46YWRtaW4=\r\n",false)]
    [InlineData("Authorization: Basic YWRtaW46YWRtaW4=\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n",false)]
    [InlineData("Authorization: Basic invalid!!\r\n\r\n",false)]
    public void HttpCredentialEvidenceRequiresCompleteSingletonAuthorization(string headers,bool expected)
    {
        var bytes=Encoding.ASCII.GetBytes("GET /admin HTTP/1.1\r\nHost: camera.test\r\n"+headers);
        Assert.True(HttpLight.TryParseHttp(bytes,out var info));
        Assert.Equal(expected,info.ObservedDefaultBasicCredential);
        Assert.DoesNotContain("YWRtaW46YWRtaW4=",info.JoinedHeaderLines);
    }

    private static byte[] DnsQuestion() => new byte[]
    {
        0x12,0x34,1,0,0,1,0,0,0,0,0,0,
        7,101,120,97,109,112,108,101,4,116,101,115,116,0,0,1,0,1
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DnsQuestionSupportsUdpAndTcpFraming(bool tcp)
    {
        var query=DnsQuestion();
        byte[] wire=tcp?new byte[]{0,(byte)query.Length}.Concat(query).ToArray():query;
        Assert.True(DnsLight.TryParse(wire,tcp,out var info));
        Assert.Equal("example.test",info.QName);
        Assert.Equal("A",info.QType);
        Assert.Equal("NOERROR",info.Rcode);
        Assert.False(info.IsResponse);
        for(int n=0;n<wire.Length;n++) Assert.False(DnsLight.TryParse(wire.AsSpan(0,n),tcp,out _));
    }

    [Fact]
    public void DnsForwardCompressionPointerIsRejected()
    {
        var wire=DnsQuestion();
        wire[12]=0xc0;wire[13]=14;
        Assert.False(DnsLight.TryParse(wire,false,out _));
    }

    private static byte[] ClientHello()
    {
        // Minimal TLS 1.2 ClientHello with one cipher, null compression, SNI and ALPN.
        var name=Encoding.ASCII.GetBytes("example.test");
        var extensions=new List<byte>();
        extensions.AddRange(new byte[]{0,0,0,(byte)(5+name.Length),0,(byte)(3+name.Length),0,0,(byte)name.Length});
        extensions.AddRange(name);
        extensions.AddRange(new byte[]{0,16,0,5,0,3,2,(byte)'h',(byte)'2'});
        var body=new List<byte>{3,3};
        body.AddRange(new byte[32]);
        body.AddRange(new byte[]{0,0,2,0x13,1,1,0,0,(byte)extensions.Count});
        body.AddRange(extensions);
        var handshake=new byte[]{1,0,0,(byte)body.Count}.Concat(body).ToArray();
        return new byte[]{0x16,3,3,0,(byte)handshake.Length}.Concat(handshake).ToArray();
    }

    [Fact]
    public void TlsClientHelloRetainsSniAlpnAndJa3()
    {
        var wire=ClientHello();
        Assert.True(TlsLight.LooksLikeTlsRecord(wire));
        Assert.True(TlsLight.TryParseClientHello(wire,out var info));
        Assert.Equal("TLS1.2",info.VersionLabel);
        Assert.Equal("example.test",info.ServerName);
        Assert.Equal("h2",info.Alpn);
        Assert.NotNull(info.Ja3);
        Assert.Equal(32,info.Ja3!.Length);
        for(int n=0;n<wire.Length;n++) Assert.False(TlsLight.TryParseClientHello(wire.AsSpan(0,n),out _));
    }

    [Theory]
    [InlineData(0xc0,1,true)]
    [InlineData(0x80,1,false)]
    [InlineData(0x40,1,false)]
    [InlineData(0xc0,0,false)]
    public void QuicLongHeaderRequiresFixedBitAndNonzeroVersion(int first,int version,bool expected)
    {
        var wire=new byte[]{(byte)first,0,0,0,(byte)version};
        Assert.Equal(expected,QuicLight.TryDetectQuic(wire,out var info));
        if(expected) Assert.Equal("0x00000001",info.VersionLabel);
        Assert.False(QuicLight.TryDetectQuic(wire.AsSpan(0,4),out _));
    }
}
