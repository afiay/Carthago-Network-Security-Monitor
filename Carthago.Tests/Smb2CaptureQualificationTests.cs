// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
using System.Text;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;
public sealed class Smb2CaptureQualificationTests
{
    private static readonly DateTime Epoch = new(2026,11,12,0,0,0,DateTimeKind.Utc);
    private static byte[] WritePayload()
    {
        var p = new byte[120]; p[3]=116; p[4]=0xfe; p[5]=0x53; p[6]=0x4d; p[7]=0x42;
        p[8]=64; p[16]=9; p[28]=1; p[40]=1; p[44]=1; // message, tree, session
        p[68]=49; p[70]=112; p[72]=4; p[84]=1; p[92]=2; // file ID
        p[116]=1; p[117]=2; p[118]=3; p[119]=4;
        return p;
    }
    private static TrafficRecord Parse(PacketHandler h,string src,string dst,byte[] payload,byte flags=0x18,uint seq=101,ushort sourcePort=51000,ushort destinationPort=445,uint ack=0)
    {
        var frame=new byte[40+payload.Length];
        frame[0]=0x45; frame[8]=64; frame[9]=6;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2,2),(ushort)frame.Length);
        IPAddress.Parse(src).GetAddressBytes().CopyTo(frame,12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(frame,16);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2),sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2),destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(24,4),seq);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(28,4),ack);
        frame[32]=0x50; frame[33]=flags; payload.CopyTo(frame,40);
        return Assert.IsType<TrafficRecord>(h.ParseFrame(frame,(LinkLayers)12));
    }
    private static TrafficRecord Capture(string src,string dst,byte[] payload)
    {
        var h=new PacketHandler(); Parse(h,src,dst,Array.Empty<byte>(),0x02,100);
        return Parse(h,src,dst,payload);
    }
    internal static TrafficRecord WritePacket(string src,string dst,string? process=null,int pid=0)
    {
        var r=Capture(src,dst,WritePayload()); r.ProcessName=process; r.ProcessId=pid;
        r.Info="SECRET-RAW-INFO-MARKER"; return r;
    }
    [Fact]
    public void InspectorReadsStructureSizeAfterProtocolSignature()
    {
        var p = WritePayload();
        Assert.Equal((ushort)64, BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(8,2)));
        Assert.NotEqual((ushort)64, BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(4,2)));
        Assert.True(Smb2CompleteWriteInspector.TryInspect(p, 51000, 445, out var length));
        Assert.Equal(4u, length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    [InlineData(65)]
    public void InvalidHeaderStructureSizeFailsClosed(int size)
    {
        var p = WritePayload();
        BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(8,2), (ushort)size);
        Assert.False(Smb2CompleteWriteInspector.TryInspect(p, 51000, 445, out var length));
        Assert.Equal(0u, length);
    }

    [Fact]
    public async Task CompleteCaptureActivatesR908AndDoesNotRetainFileData()
    {
        var h=new PacketHandler();
        var syn=Parse(h,"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x02,100);
        var write=Parse(h,"8.8.8.8","10.1.2.45",WritePayload());
        Assert.True(write.Smb2CompleteWriteRequestObserved);
        Assert.Equal(4u,write.Smb2ValidatedWriteLength);
        var rule=new R908_PublicSmbSynThenParsedWriteRule();
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(syn,Sensitivity.Balanced,Epoch))).Matched);
        Assert.True((await rule.EvaluateAsync(new RuleEvaluationContext(write,Sensitivity.Balanced,Epoch.AddSeconds(1)))).Matched);
    }
    [Theory]
    [InlineData("truncated")]
    [InlineData("compound")]
    [InlineData("response")]
    [InlineData("async")]
    [InlineData("related")]
    [InlineData("no-session")]
    [InlineData("no-tree")]
    [InlineData("no-file")]
    [InlineData("channel")]
    [InlineData("offset")]
    [InlineData("encrypted")]
    public async Task IncompleteOrUnsupportedWireCannotTrigger(string variant)
    {
        var p=WritePayload();
        switch(variant)
        {
            case "truncated": Array.Resize(ref p,p.Length-1); break;
            case "compound": p[24]=112; break;
            case "response": p[20]=1; break;
            case "async": p[20]=2; break;
            case "related": p[20]=4; break;
            case "no-session": p[44]=0; break;
            case "no-tree": p[40]=0; break;
            case "no-file": p[84]=0; p[92]=0; break;
            case "channel": p[100]=1; break;
            case "offset": p[70]=111; break;
            case "encrypted": p[4]=0xfd; break;
        }
        var h=new PacketHandler();
        var syn=Parse(h,"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x02,100);
        var write=Parse(h,"8.8.8.8","10.1.2.45",p);
        Assert.False(write.Smb2CompleteWriteRequestObserved);
        Assert.Null(write.Smb2ValidatedWriteLength);
        var rule=new R908_PublicSmbSynThenParsedWriteRule();
        await rule.EvaluateAsync(new RuleEvaluationContext(syn,Sensitivity.Balanced,Epoch));
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(write,Sensitivity.Balanced,Epoch.AddSeconds(1)))).Matched);
    }
    [Fact]
    public async Task LegacyLabelAndJsonCannotForgeQualifiedEvidence()
    {
        var r=JsonSerializer.Deserialize<TrafficRecord>("{\"Smb2CompleteWriteRequestObserved\":true,\"Smb2ValidatedWriteLength\":4,\"ApplicationProtocol\":\"smb2.write.request\"}")!;
        Assert.False(r.Smb2CompleteWriteRequestObserved);
        Assert.Null(r.Smb2ValidatedWriteLength);
        var syn=Parse(new PacketHandler(),"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x02,100);
        var rule=new R908_PublicSmbSynThenParsedWriteRule();
        await rule.EvaluateAsync(new RuleEvaluationContext(syn,Sensitivity.Balanced,Epoch));
        var forged=new TrafficRecord { Source="8.8.8.8", Destination="10.1.2.45", SourcePort=51000, DestinationPort=445,
            IsTcp=true, IpVersion=4, Protocol="TCP", TcpFlags=0x18, Length=160, L4Len=120,
            ApplicationProtocol="smb2.write.request", Info="smb2.write.request" };
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(forged,Sensitivity.Balanced,Epoch.AddSeconds(1)))).Matched);
    }

    private static byte[] WriteReply(uint status=0,uint count=4)
    {
        var p=new byte[status==0?84:77];
        p[3]=(byte)(p.Length-4); p[4]=0xfe; p[5]=0x53; p[6]=0x4d; p[7]=0x42;
        p[8]=64; p[16]=9; p[20]=1; p[28]=1; p[40]=1; p[44]=1;
        BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(12,4),status);
        p[68]=(byte)(status==0?17:9);
        if(status==0) BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(72,4),count);
        return p;
    }
    private static TrafficRecord BeginWrite(PacketHandler h)
    {
        Parse(h,"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x02,100);
        Parse(h,"10.1.2.45","8.8.8.8",Array.Empty<byte>(),0x12,500,445,51000,101);
        return Parse(h,"8.8.8.8","10.1.2.45",WritePayload(),0x18,101,51000,445,501);
    }
    private static TrafficRecord Reply(PacketHandler h,byte[] payload,uint ack=221,uint seq=501)
        => Parse(h,"10.1.2.45","8.8.8.8",payload,0x18,seq,445,51000,ack);

    [Theory]
    [InlineData(4u)]
    [InlineData(2u)]
    public void MatchingWriteResponseReportsFullOrPartialCount(uint count)
    {
        var h=new PacketHandler(); var request=BeginWrite(h);
        Assert.True(request.Smb2CompleteWriteRequestObserved);
        var reply=Reply(h,WriteReply(count:count));
        Assert.Equal(request.Id,reply.Smb2WriteResponseCorrelationId);
        Assert.Equal(0u,reply.Smb2WriteResponseStatus);
        Assert.Equal(count,reply.Smb2WriteAcknowledgedLength);
        Assert.False(reply.Smb2CompleteWriteRequestObserved);
        Assert.Null(Reply(h,WriteReply(count:count),seq:585).Smb2WriteResponseCorrelationId);
    }
    [Fact]
    public void MatchingErrorResponseDoesNotClaimBytesWritten()
    {
        var h=new PacketHandler(); var request=BeginWrite(h);
        var reply=Reply(h,WriteReply(0xc0000022u));
        Assert.Equal(request.Id,reply.Smb2WriteResponseCorrelationId);
        Assert.Equal(0xc0000022u,reply.Smb2WriteResponseStatus);
        Assert.Null(reply.Smb2WriteAcknowledgedLength);
    }
    [Theory]
    [InlineData("message")]
    [InlineData("session")]
    [InlineData("tree")]
    [InlineData("over-count")]
    [InlineData("zero-count")]
    [InlineData("async")]
    [InlineData("truncated")]
    [InlineData("pending")]
    [InlineData("ack")]
    public void InvalidOrUnmatchedResponseDoesNotCorroborate(string variant)
    {
        var h=new PacketHandler(); BeginWrite(h);
        var p=WriteReply(); uint ack=221;
        switch(variant)
        {
            case "message": p[28]=2; break;
            case "session": p[44]=2; break;
            case "tree": p[40]=2; break;
            case "over-count": p[72]=5; break;
            case "zero-count": p[72]=0; break;
            case "async": p[20]=3; break;
            case "truncated": Array.Resize(ref p,p.Length-1); break;
            case "pending": p=WriteReply(0x103u); break;
            case "ack": ack=220; break;
        }
        var r=Reply(h,p,ack);
        Assert.Null(r.Smb2WriteResponseCorrelationId);
        Assert.Null(r.Smb2WriteResponseStatus);
        Assert.Null(r.Smb2WriteAcknowledgedLength);
    }
    [Fact]
    public void MissingHandshakeDifferentCaptureAndReusedTupleFailClosed()
    {
        var h=new PacketHandler();
        Parse(h,"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x02,100);
        Parse(h,"8.8.8.8","10.1.2.45",WritePayload());
        Assert.Null(Reply(h,WriteReply()).Smb2WriteResponseCorrelationId);
        h=new PacketHandler(); BeginWrite(h);
        Assert.Null(Reply(new PacketHandler(),WriteReply()).Smb2WriteResponseCorrelationId);
        Parse(h,"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x02,100);
        Parse(h,"10.1.2.45","8.8.8.8",Array.Empty<byte>(),0x12,500,445,51000,101);
        Assert.Null(Reply(h,WriteReply()).Smb2WriteResponseCorrelationId);
    }
    [Fact]
    public void PipeliningAndFinInvalidatePendingExchange()
    {
        var h=new PacketHandler(); BeginWrite(h);
        var second=WritePayload(); second[28]=2;
        Parse(h,"8.8.8.8","10.1.2.45",second,0x18,221,51000,445,501);
        Assert.Null(Reply(h,WriteReply()).Smb2WriteResponseCorrelationId);
        h=new PacketHandler(); BeginWrite(h);
        Parse(h,"8.8.8.8","10.1.2.45",Array.Empty<byte>(),0x11,221,51000,445,501);
        Assert.Null(Reply(h,WriteReply()).Smb2WriteResponseCorrelationId);
    }
    [Fact]
    public void ExchangeExpiryReverseTimeAndJsonForgeryFailClosed()
    {
        var pending=Smb2WriteExchange.FromValidatedRequest(WritePayload(),4,Guid.NewGuid(),221,Epoch);
        Assert.False(Smb2WriteExchange.TryMatchReply(WriteReply(),pending,221,Epoch.AddSeconds(31),out _,out _));
        Assert.False(Smb2WriteExchange.TryMatchReply(WriteReply(),pending,221,Epoch.AddSeconds(-1),out _,out _));
        Assert.True(Smb2WriteExchange.TryMatchReply(WriteReply(),pending,221,Epoch.AddSeconds(30),out _,out _));
        var forged=JsonSerializer.Deserialize<TrafficRecord>("{\"Smb2WriteResponseCorrelationId\":\"11111111-1111-1111-1111-111111111111\",\"Smb2WriteResponseStatus\":0,\"Smb2WriteAcknowledgedLength\":4}")!;
        Assert.Null(forged.Smb2WriteResponseCorrelationId);
        Assert.Null(forged.Smb2WriteResponseStatus);
        Assert.Null(forged.Smb2WriteAcknowledgedLength);
    }

    private static byte[] SmbFrame(int size, ushort cmd, bool reply, byte msg, byte tree)
    {
        var p=new byte[size]; int length=size-4;
        p[1]=(byte)(length>>16); p[2]=(byte)(length>>8); p[3]=(byte)length;
        p[4]=0xfe; p[5]=0x53; p[6]=0x4d; p[7]=0x42; p[8]=64;
        BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(16,2),cmd);
        p[20]=(byte)(reply?1:0); p[28]=msg; p[40]=tree; p[44]=1;
        return p;
    }
    private static byte[] TreeRequest(string share)
    {
        var name=Encoding.Unicode.GetBytes("\\\\server\\"+share);
        var p=SmbFrame(76+name.Length,3,false,1,0); p[68]=9; p[72]=72;
        BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(74,2),(ushort)name.Length); name.CopyTo(p,76);
        return p;
    }
    private static byte[] TreeReply()
    {
        var p=SmbFrame(84,3,true,1,1); p[68]=16; p[70]=1; return p;
    }
    private static byte[] CreateRequest(string name)
    {
        var bytes=Encoding.Unicode.GetBytes(name); var p=SmbFrame(124+bytes.Length,5,false,2,1);
        p[68]=57; p[104]=1; p[112]=120;
        BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(114,2),(ushort)bytes.Length); bytes.CopyTo(p,124);
        return p;
    }
    private static byte[] CreateReply()
    {
        var p=SmbFrame(156,5,true,2,1); p[68]=89; p[132]=1; p[140]=2; return p;
    }
    internal static (TrafficRecord Syn, TrafficRecord Create, TrafficRecord Write) TargetChain(
        string share, string file, string variant="", string source="8.8.8.8", string destination="10.1.2.45")
    {
        var h=new PacketHandler(); uint c=101,s=501;
        var syn=Parse(h,source,destination,Array.Empty<byte>(),0x02,100);
        Parse(h,destination,source,Array.Empty<byte>(),0x12,500,445,51000,101);
        TrafficRecord Client(byte[] b)
        {
            var result=Parse(h,source,destination,b,0x18,c,51000,445,s); c+=(uint)b.Length; return result;
        }
        void Server(byte[] b)
        {
            Parse(h,destination,source,b,0x18,s,445,51000,c); s+=(uint)b.Length;
        }
        Client(TreeRequest(share));
        var tr=TreeReply();
        if(variant=="tree-error") tr[12]=0x22;
        if(variant=="tree-id") tr[40]=2;
        if(variant=="tree-message") tr[28]=9;
        if(variant=="non-disk") tr[70]=2;
        Server(tr);
        var create=Client(CreateRequest(file));
        var cr=CreateReply();
        if(variant=="create-error") cr[12]=0x22;
        if(variant=="create-session") cr[44]=2;
        if(variant=="create-message") cr[28]=9;
        if(variant=="create-handle") cr[132]=9;
        Server(cr);
        if(variant=="intervening") Client(SmbFrame(72,6,false,3,1));
        var w=WritePayload(); w[28]=4;
        if(variant=="write-tree") w[40]=2;
        if(variant=="write-session") w[44]=2;
        if(variant=="write-handle") w[84]=9;
        return(syn,create,Client(w));
    }
    [Theory]
    [InlineData("ADMIN$","private-tool.exe","administrative-disk","executable")]
    [InlineData("c$","private-script.ps1","administrative-disk","script")]
    [InlineData("TeamDocs","private-report.txt","other-disk","other")]
    public async Task ValidatedTreeAndOpenContextEnrichesWriteAndR908(string share,string name,string expectedShare,string expectedFile)
    {
        var chain=TargetChain(share,name);
        Assert.True(chain.Write.Smb2CompleteWriteRequestObserved);
        Assert.Equal(expectedShare,chain.Write.Smb2WriteShareKind);
        Assert.Equal(expectedFile,chain.Write.Smb2WriteFileKind);
        Assert.Equal(chain.Create.Id,chain.Write.Smb2WriteCreateCorrelationId);
        Assert.DoesNotContain(name,JsonSerializer.Serialize(chain.Write));
        var rule=new R908_PublicSmbSynThenParsedWriteRule();
        await rule.EvaluateAsync(new RuleEvaluationContext(chain.Syn,Sensitivity.Balanced,Epoch));
        var result=await rule.EvaluateAsync(new RuleEvaluationContext(chain.Write,Sensitivity.Balanced,Epoch.AddSeconds(1)));
        Assert.True(result.Matched);
        var json=JsonSerializer.Serialize(result.Events);
        Assert.Contains(expectedShare,json); Assert.Contains(expectedFile,json);
        Assert.DoesNotContain(name,json);
    }
    [Theory]
    [InlineData("tree-error")]
    [InlineData("tree-id")]
    [InlineData("tree-message")]
    [InlineData("non-disk")]
    [InlineData("create-error")]
    [InlineData("create-session")]
    [InlineData("create-message")]
    [InlineData("create-handle")]
    [InlineData("intervening")]
    [InlineData("write-tree")]
    [InlineData("write-session")]
    [InlineData("write-handle")]
    public void MismatchedOrUnsupportedTargetLeavesWriteAttemptIntact(string variant)
    {
        var chain=TargetChain("ADMIN$","private-tool.exe",variant);
        Assert.True(chain.Write.Smb2CompleteWriteRequestObserved);
        Assert.Null(chain.Write.Smb2WriteShareKind);
        Assert.Null(chain.Write.Smb2WriteFileKind);
        Assert.Null(chain.Write.Smb2WriteCreateCorrelationId);
    }
    [Fact]
    public void TargetMetadataCannotBeForgedByJson()
    {
        var forged=JsonSerializer.Deserialize<TrafficRecord>("{\"Smb2WriteShareKind\":\"administrative-disk\",\"Smb2WriteFileKind\":\"executable\",\"Smb2WriteCreateCorrelationId\":\"11111111-1111-1111-1111-111111111111\"}")!;
        Assert.Null(forged.Smb2WriteShareKind); Assert.Null(forged.Smb2WriteFileKind); Assert.Null(forged.Smb2WriteCreateCorrelationId);
    }
}
