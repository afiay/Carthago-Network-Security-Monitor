// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableExchangeInspectorTests
{
    private static readonly DateTime Epoch = new(2026,1,1,0,0,0,DateTimeKind.Utc);

    [Fact]
    public void ExchangeInspectorsHaveOnePortableOwner()
    {
        var core=typeof(Iec104ApduInspector).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        foreach(var type in new[]{typeof(Iec104ApduInspector),typeof(Iec104StartupOffSequence),typeof(OpcUaConnectionInspector),typeof(OpcUaHelloAckInspector),typeof(ModbusOversizedReadExchangeInspector),typeof(ModbusBulkFileReadInspector),typeof(LdapMessageInspector),typeof(TftpRequestInspector),typeof(TftpHandshakeTracker),typeof(Smb2WriteExchange),typeof(Smb2WriteTargetContext)})
            Assert.Same(core,type.Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a=>a.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    private static byte[] Start(byte control)=>new byte[]{0x68,4,control,0,0,0};
    private static byte[] Off()=>new byte[]{0x68,14,0,0,0,0,46,1,6,0,1,0,1,0,0,1};

    [Fact]
    public void IecApduRequiresAttestedCompleteBoundary()
    {
        Assert.True(Iec104ApduInspector.TryInspect(Start(7),true,out var observation));
        Assert.Equal(Iec104FrameKind.Unnumbered,observation.Kind);
        Assert.False(Iec104ApduInspector.TryInspect(Start(7),false,out _));
        Assert.False(Iec104ApduInspector.TryInspect(Start(7)[..^1],true,out _));
        Assert.True(Iec104ApduInspector.TryInspect(Off(),true,out var info));
        Assert.Equal((byte)46,info.AsduType);
    }

    [Theory]
    [InlineData(30,true)]
    [InlineData(31,false)]
    [InlineData(-1,false)]
    public void IecStartupOffSequenceRequiresOrderedBoundedExchange(int seconds,bool expected)
    {
        var state=new Iec104StartupOffSequence();
        Assert.False(state.Observe(Start(7),true,true,true,Epoch));
        Assert.False(state.Observe(Start(11),false,true,true,Epoch));
        Assert.Equal(expected,state.Observe(Off(),true,false,true,Epoch.AddSeconds(seconds)));
        Assert.False(state.Observe(Off(),true,false,true,Epoch.AddSeconds(30)));
    }

    [Fact]
    public void IecIncompleteFrameResetsSequence()
    {
        var state=new Iec104StartupOffSequence();
        state.Observe(Start(7),true,true,true,Epoch);
        state.Observe(Start(11),false,true,false,Epoch);
        Assert.False(state.Observe(Off(),true,false,true,Epoch));
    }

    private static void U32(byte[] p,int at,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(at),value);
    private static byte[] Ua(bool hello,uint receive=8192,uint send=16384)
    {
        var url="opc.tcp://fixture.test"u8.ToArray();
        var p=new byte[hello?32+url.Length:28];
        Encoding.ASCII.GetBytes(hello?"HELF":"ACKF").CopyTo(p,0);
        U32(p,4,(uint)p.Length); U32(p,12,receive); U32(p,16,send);
        if(hello){U32(p,28,(uint)url.Length);url.CopyTo(p,32);}
        return p;
    }

    [Fact]
    public void OpcUaHelloEnvelopeAndMatchingAckRetainOnlyBufferSizes()
    {
        var wire=Ua(true);
        Assert.True(OpcUaConnectionInspector.TryInspect(wire,true,out var observation));
        Assert.Equal(OpcUaConnectionKind.Hello,observation.Kind);
        Assert.False(OpcUaConnectionInspector.TryInspect(wire,false,out _));
        Assert.True(OpcUaHelloAckInspector.TryHello(wire,Epoch,out var hello));
        Assert.Equal(8192u,hello.Receive);Assert.Equal(16384u,hello.Send);
        Assert.True(OpcUaHelloAckInspector.IsMatchingAck(Ua(false,16384,8192),hello,Epoch.AddSeconds(30)));
        Assert.False(OpcUaHelloAckInspector.IsMatchingAck(Ua(false,32768,8192),hello,Epoch));
        Assert.False(OpcUaHelloAckInspector.IsMatchingAck(Ua(false,16384,8192),hello,Epoch.AddSeconds(31)));
        Assert.False(OpcUaHelloAckInspector.TryHello(wire[..^1],Epoch,out _));
    }

    [Theory]
    [InlineData(125,false)]
    [InlineData(126,true)]
    public void ModbusOversizedReadMatchesOnlyItsException(int quantity,bool expected)
    {
        byte[] request={0,7,0,0,0,6,1,3,0,1,0,(byte)quantity};
        Assert.Equal(expected,ModbusOversizedReadExchangeInspector.TryRequest(request,Epoch,out var pending));
        if(!expected)return;
        byte[] response={0,7,0,0,0,3,1,0x83,3};
        Assert.True(ModbusOversizedReadExchangeInspector.IsMatchingException(response,pending,Epoch.AddSeconds(30)));
        Assert.False(ModbusOversizedReadExchangeInspector.IsMatchingException(response,pending,Epoch.AddSeconds(31)));
        response[1]=8;
        Assert.False(ModbusOversizedReadExchangeInspector.IsMatchingException(response,pending,Epoch));
    }

    [Fact]
    public void ModbusBulkFileResponseRequiresMatchingTransactionUnitAndQuantity()
    {
        byte[] request={0,7,0,0,0,10,1,0x14,7,6,0,1,0,1,0,100};
        Assert.True(ModbusBulkFileReadInspector.TryRequest(request,Epoch,out var pending));
        var response=new byte[211];
        response[1]=7;response[5]=205;response[6]=1;response[7]=0x14;response[8]=202;response[9]=201;response[10]=6;
        Assert.True(ModbusBulkFileReadInspector.IsMatchingResponse(response,pending,Epoch));
        Assert.False(ModbusBulkFileReadInspector.IsMatchingResponse(response[..^1],pending,Epoch));
        Assert.False(ModbusBulkFileReadInspector.IsMatchingResponse(response,pending,Epoch.AddSeconds(31)));
        response[6]=2;
        Assert.False(ModbusBulkFileReadInspector.IsMatchingResponse(response,pending,Epoch));
    }

    [Fact]
    public void LdapSimpleBindRequiresAttestationAndDoesNotRetainSecrets()
    {
        byte[] wire={0x30,0x0e,2,1,1,0x60,9,2,1,3,4,1,0x61,0x80,1,0x62};
        Assert.True(LdapMessageInspector.TryInspectSimpleBind(wire,true,out var result));
        Assert.False(LdapMessageInspector.TryInspectSimpleBind(wire,false,out _));
        Assert.False(LdapMessageInspector.TryInspectSimpleBind(wire[..^1],true,out _));
        Assert.Equal(1,result.MessageId);
        Assert.True(result.HasNonEmptyCredential);
        using var json=JsonDocument.Parse(JsonSerializer.Serialize(result));
        Assert.Equal(new[]{"BytesConsumed","HasNonEmptyCredential","MessageId"},
            json.RootElement.EnumerateObject().Select(x=>x.Name).OrderBy(x=>x,StringComparer.Ordinal).ToArray());
    }

    private static TrafficRecord Udp(bool reverse=false)=>new()
    {
        Source=reverse?"192.0.2.2":"192.0.2.1",Destination=reverse?"192.0.2.1":"192.0.2.2",
        SourcePort=reverse?52000:51000,DestinationPort=reverse?51000:69,IsUdp=true,IpVersion=4
    };

    [Fact]
    public void TftpFirstResponseRequiresPendingRequestAndIsOneShot()
    {
        var tracker=new TftpHandshakeTracker();
        byte[] reply={0,3,0,1,0x41};
        var unsolicited=Udp(true);tracker.Observe(unsolicited,reply,true,Epoch);
        Assert.Null(unsolicited.TftpInitialReplyOpcode);
        var request=Udp();byte[] bytes={0,1,0x66,0,0x6f,0x63,0x74,0x65,0x74,0};
        tracker.Observe(request,bytes,true,Epoch);
        Assert.Equal((byte)1,request.TftpInitialRequestOpcode);
        var response=Udp(true);tracker.Observe(response,reply,true,Epoch.AddSeconds(1));
        Assert.Equal((byte)3,response.TftpInitialReplyOpcode);
        Assert.Equal(request.Id,response.TftpRequestCorrelationId);
        var duplicate=Udp(true);tracker.Observe(duplicate,reply,true,Epoch.AddSeconds(2));
        Assert.Null(duplicate.TftpInitialReplyOpcode);
    }

    [Fact]
    public void TftpExpiredOrUnattestedRequestCannotQualifyReply()
    {
        var tracker=new TftpHandshakeTracker();
        byte[] bytes={0,1,0x66,0,0x6f,0x63,0x74,0x65,0x74,0};
        var request=Udp();tracker.Observe(request,bytes,false,Epoch);
        Assert.Null(request.TftpInitialRequestOpcode);
        tracker.Observe(request,bytes,true,Epoch);
        var response=Udp(true);tracker.Observe(response,new byte[]{0,3,0,1},true,Epoch.AddSeconds(46));
        Assert.Null(response.TftpInitialReplyOpcode);
    }

    [Fact]
    public void SmbWriteReplyRequiresMatchingIdentifiersAckAndTime()
    {
        var request=new Smb2WriteExchange.Pending(Guid.NewGuid(),7,8,9,10,100,Epoch);
        var reply=new byte[84];reply[3]=80;reply[4]=0xfe;reply[5]=0x53;reply[6]=0x4d;reply[7]=0x42;
        reply[8]=64;reply[16]=9;reply[20]=1;reply[28]=7;reply[40]=9;reply[44]=8;reply[68]=17;reply[72]=10;
        Assert.True(Smb2WriteExchange.TryMatchReply(reply,request,100,Epoch,out uint status,out uint? count));
        Assert.Equal(0u,status);Assert.Equal(10u,count);
        Assert.False(Smb2WriteExchange.TryMatchReply(reply,request,99,Epoch,out _,out _));
        Assert.False(Smb2WriteExchange.TryMatchReply(reply,request,100,Epoch.AddSeconds(31),out _,out _));
        reply[28]=8;Assert.False(Smb2WriteExchange.TryMatchReply(reply,request,100,Epoch,out _,out _));
    }
}
