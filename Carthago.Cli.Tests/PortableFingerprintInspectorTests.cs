// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Carthago.Services.Fingerprints;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableFingerprintInspectorTests
{
    [Fact]
    public void ExtractedTypesHaveOnePortableOwner()
    {
        var core=typeof(HttpJa4H).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        foreach(var type in new[]{typeof(TlsJa4),typeof(TcpJa4T),typeof(SshJa4SSH),typeof(Hassh),
            typeof(Resp2CommandInspector),typeof(Resp2CommandObservation),typeof(Resp2CommandKind),
            typeof(Resp2SimpleReplyInspector),typeof(Resp2SimpleReplyKind),typeof(Smb2CompleteWriteInspector)})
            Assert.Same(core,type.Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a=>a.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    private static string Sha8(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant()[..8];
    private static string Md5(string value)=>Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant();

    [Fact]
    public void HttpFingerprintRetainsHeaderOrderAndStableTag()
    {
        const string expected="GET|HTTP/1.1|host,accept|ua:curl";
        var result=HttpJa4H.Compute("GET","HTTP/1.1",new[]{"Host","Accept"},"curl/8.0");
        Assert.Equal("h:"+expected,result.readable);
        Assert.Equal(Sha8(expected),result.tag);
        Assert.NotEqual(result.tag,HttpJa4H.Compute("GET","HTTP/1.1",new[]{"Accept","Host"},"curl/8.0").tag);
    }

    [Fact]
    public void TcpFingerprintRetainsOptionOrderAndStopsAtEol()
    {
        byte[] options={2,4,5,180,1,3,3,7,4,2,0,99};
        Assert.Equal("t:64240:mss=1460;ws=7;sack=1;opt=2-1-3-4-0",
            TcpJa4T.Compute(options,64240,1460,7,true));
        Assert.Equal("t:0:mss=0;ws=0;sack=0;opt=",TcpJa4T.Compute(null,0,null,null,false));
    }

    [Fact]
    public void SshFingerprintRetainsPartialInputAndHasshFormat()
    {
        const string core="b:SSH-2.0-fixture;k:-;e:-;m:-";
        Assert.Equal("ssh:"+core+"|"+Sha8(core),SshJa4SSH.From("SSH-2.0-fixture",null,null,null));
        Assert.Equal(Md5("kex;enc;mac;none"),SshJa4SSH.Hassh("kex","enc","mac","none"));
    }

    [Fact]
    public void HasshClientAndServerUseExistingDirectionalLists()
    {
        var wire=new List<byte>{0x14};
        wire.AddRange(new byte[16]);
        foreach(string name in new[]{"kex","host","enc-c","enc-s","mac-c","mac-s","comp-c","comp-s","",""})
        {
            byte[] bytes=Encoding.ASCII.GetBytes(name);
            byte[] length=new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length,(uint)bytes.Length);
            wire.AddRange(length);wire.AddRange(bytes);
        }
        wire.AddRange(new byte[5]);
        Assert.True(Hassh.TryComputeClient(wire.ToArray(),out var client,out var clientAlgs));
        Assert.True(Hassh.TryComputeServer(wire.ToArray(),out var server,out var serverAlgs));
        Assert.Equal("kex;host;enc-c;mac-c;comp-c",clientAlgs);
        Assert.Equal("kex;host;enc-s;mac-s;comp-s",serverAlgs);
        Assert.Equal(Md5(clientAlgs),client);Assert.Equal(Md5(serverAlgs),server);
        Assert.False(Hassh.TryComputeClient(new byte[]{0x14},out _,out _));
    }

    [Fact]
    public void TlsClientFingerprintRetainsExistingFormat()
    {
        var hello=new List<byte>{3,3};hello.AddRange(new byte[32]);
        hello.AddRange(new byte[]{0,0,2,0x13,1,1,0,0,0});
        var hs=new byte[]{1,0,0,(byte)hello.Count}.Concat(hello).ToArray();
        var record=new byte[]{0x16,3,3,0,(byte)hs.Length}.Concat(hs).ToArray();
        const string core="v:771;cs:4865;ex:-;grp:-;sig:-;alpn:-";
        Assert.Equal("t:"+core+"|"+Sha8(core),TlsJa4.FromClientHello(record));
        Assert.Equal("",TlsJa4.FromClientHello(new byte[]{0x17,3,3,0,0}));
    }

    [Fact]
    public void RedisConfigShapeRequiresAttestedBoundaryAndRetainsNoArguments()
    {
        var wire="*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\nkey\r\n$7\r\nprivate\r\n"u8.ToArray();
        Assert.False(Resp2CommandInspector.TryInspect(wire,false,out _));
        Assert.True(Resp2CommandInspector.TryInspect(wire,true,out var result));
        Assert.Equal(Resp2CommandKind.Config,result.Command);
        Assert.Equal(3,result.ArgumentCount);Assert.Equal(wire.Length,result.BytesConsumed);
        Assert.True(result.IsConfigSetRequest);
        Assert.DoesNotContain("private",JsonSerializer.Serialize(result));
        for(int n=0;n<wire.Length;n++)Assert.False(Resp2CommandInspector.TryInspect(wire.AsSpan(0,n),true,out _));
    }

    [Theory]
    [InlineData("+OK\r\n",true,Resp2SimpleReplyKind.Ok)]
    [InlineData("-ERR private\r\n",true,Resp2SimpleReplyKind.Error)]
    [InlineData("+OK\r\n+OK\r\n",false,Resp2SimpleReplyKind.Unknown)]
    [InlineData("-ERR x\n",false,Resp2SimpleReplyKind.Unknown)]
    public void RedisReplyClassifiesOnlyBoundedSingleFrame(string wire,bool expected,Resp2SimpleReplyKind kind)
    {
        Assert.Equal(expected,Resp2SimpleReplyInspector.TryInspect(Encoding.ASCII.GetBytes(wire),out var result));
        Assert.Equal(kind,result);
    }

    private static byte[] SmbWrite()
    {
        var p=new byte[117];p[3]=113;p[4]=0xfe;p[5]=0x53;p[6]=0x4d;p[7]=0x42;
        var h=p.AsSpan(4);
        BinaryPrimitives.WriteUInt16LittleEndian(h[4..],64);
        BinaryPrimitives.WriteUInt16LittleEndian(h[12..],9);
        BinaryPrimitives.WriteUInt32LittleEndian(h[36..],1);
        BinaryPrimitives.WriteUInt64LittleEndian(h[40..],1);
        BinaryPrimitives.WriteUInt16LittleEndian(h[64..],49);
        BinaryPrimitives.WriteUInt16LittleEndian(h[66..],112);
        BinaryPrimitives.WriteUInt32LittleEndian(h[68..],1);
        BinaryPrimitives.WriteUInt64LittleEndian(h[80..],1);
        p[^1]=0x41;
        return p;
    }

    [Fact]
    public void SmbWriteRequiresCompleteStandaloneFrameAndCorrectDirection()
    {
        var wire=SmbWrite();
        Assert.True(Smb2CompleteWriteInspector.TryInspect(wire,51000,445,out uint length));
        Assert.Equal(1u,length);
        Assert.False(Smb2CompleteWriteInspector.TryInspect(wire,445,51000,out _));
        for(int n=0;n<wire.Length;n++)Assert.False(Smb2CompleteWriteInspector.TryInspect(wire.AsSpan(0,n),51000,445,out _));
        wire[20]=1; // SMB2 response flag.
        Assert.False(Smb2CompleteWriteInspector.TryInspect(wire,51000,445,out _));
    }
}
