// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
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
    private static TrafficRecord Parse(PacketHandler h,string src,string dst,byte[] payload,byte flags=0x18,uint seq=101)
    {
        var frame=new byte[40+payload.Length];
        frame[0]=0x45; frame[8]=64; frame[9]=6;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2,2),(ushort)frame.Length);
        IPAddress.Parse(src).GetAddressBytes().CopyTo(frame,12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(frame,16);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2),51000);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2),445);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(24,4),seq);
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
}
