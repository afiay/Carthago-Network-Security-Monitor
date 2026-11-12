// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
public sealed class DnsCaptureQualificationTests
{
    private static readonly DateTime Epoch = new(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
    private const string Client="10.1.1.10", Resolver="8.8.8.8", Name="update.example.net";
    internal static byte[] Message(ushort tx, bool response, string? address=null, bool nx=false,
        ushort ttl=15, string name=Name, bool differentOwner=false)
    {
        var bytes = new List<byte> { (byte)(tx >> 8), (byte)tx,
            response ? (byte)0x81 : (byte)0x01, nx ? (byte)0x83 : (byte)(response ? 0x80 : 0),
            0,1,0,(byte)(address == null ? 0 : 1),0,0,0,0 };
        foreach (var label in name.Split('.'))
        { bytes.Add((byte)label.Length); bytes.AddRange(Encoding.ASCII.GetBytes(label)); }
        bytes.AddRange(new byte[] { 0,0,1,0,1 });
        if (address != null)
        {
            if (differentOwner) bytes.AddRange(new byte[] { 1,(byte)'x',0 });
            else bytes.AddRange(new byte[] { 0xc0,0x0c });
            bytes.AddRange(new byte[] { 0,1,0,1,0,0,(byte)(ttl >> 8),(byte)ttl,0,4 });
            bytes.AddRange(IPAddress.Parse(address).GetAddressBytes());
        }
        return bytes.ToArray();
    }
    internal static TrafficRecord Parse(PacketHandler handler, byte[] dns, bool response, int pid=310, string process="python",
        bool inconsistentLength=false, int clientPort=51000)
    {
        var raw = new byte[28 + dns.Length]; raw[0]=0x45; raw[8]=64; raw[9]=17;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2,2),(ushort)raw.Length);
        IPAddress.Parse(response?Resolver:Client).GetAddressBytes().CopyTo(raw,12);
        IPAddress.Parse(response?Client:Resolver).GetAddressBytes().CopyTo(raw,16);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(20,2),(ushort)(response?53:clientPort));
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(22,2),(ushort)(response?clientPort:53));
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(24,2),(ushort)(8+dns.Length-(inconsistentLength?1:0)));
        dns.CopyTo(raw,28);
        var r=Assert.IsType<TrafficRecord>(handler.ParseFrame(raw,(LinkLayers)12));
        if (!response) { r.ProcessId=pid; r.ProcessName=process; }
        return r;
    }
    internal static TrafficRecord[] NxdomainPair()
    {
        var h=new PacketHandler();
        return new[] { Parse(h,Message(0x31,false),false,310,"hostd"),
            Parse(h,Message(0x31,true,nx:true),true) };
    }
    internal static TrafficRecord[] Churn()
    {
        var h=new PacketHandler(); var result=new List<TrafficRecord>();
        string[] answers={"1.1.1.1","9.9.9.9","208.67.222.222"};
        for(int i=0;i<answers.Length;i++)
        {
            ushort tx=(ushort)(0x40+i);
            result.Add(Parse(h,Message(tx,false),false));
            result.Add(Parse(h,Message(tx,true,answers[i]),true));
        }
        return result.ToArray();
    }
    private static RuleEvaluationContext At(TrafficRecord r,int seconds)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(seconds));
    [Fact]
    public void ProducerExtractsTransactionDirectAnswerAndTtl()
    {
        var pair=Churn();
        Assert.Equal((ushort)0x40,pair[0].DnsValidatedTransactionId);
        Assert.True(pair[0].DnsValidatedAQuestion);
        Assert.Equal((ushort)0x40,pair[1].DnsValidatedTransactionId);
        Assert.Equal("DNS",pair[1].ApplicationProtocol);
        Assert.True(pair[1].DnsValidatedSingleAAnswer);
        Assert.Equal("1.1.1.1",pair[1].DnsAnswers);
        Assert.Equal(15,pair[1].DnsTtl);
    }
    [Fact]
    public void TruncatedWrongOwnerWrongQuestionAndMultipleAnswersFailClosed()
    {
        var valid=Message(3,true,"1.1.1.1");
        var truncated=valid.Take(valid.Length-1).ToArray();
        var tc=(byte[])valid.Clone();tc[2]|=2;
        var multiple=(byte[])valid.Clone();multiple[7]=2;
        var badType=(byte[])valid.Clone();badType[12+1+"update".Length+1+"example".Length+1+"net".Length+2]=28;
        foreach(var wire in new[] {truncated,tc,multiple,badType,Message(3,true,"1.1.1.1",differentOwner:true)})
        {
            Assert.False(DnsAObservationInspector.TryInspect(wire,out _));
            Assert.False(Parse(new PacketHandler(),wire,true).DnsValidatedSingleAAnswer);
        }
        Assert.False(Parse(new PacketHandler(),valid,true,inconsistentLength:true).DnsValidatedSingleAAnswer);
    }
    [Fact]
    public async Task NxdomainMustMatchWireTransaction()
    {
        var pair=NxdomainPair();var rule=new R916_HostdPublicDnsQueryNxdomainReplyRule();
        await rule.EvaluateAsync(At(pair[0],0));
        var wrong=Parse(new PacketHandler(),Message(0x32,true,nx:true),true);
        Assert.False((await rule.EvaluateAsync(At(wrong,1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(pair[1],2))).Matched);
    }
    [Fact]
    public async Task ChurnRequiresSamePidAndMatchingTransactions()
    {
        var h=new PacketHandler();
        foreach(var variant in new[]{"tx","pid","port"})
        {
            var rule=new R962_CliDnsQueryLowTtlReplyChurnRule();
            string[] answers={"1.1.1.1","9.9.9.9","208.67.222.222"};
            for(int i=0;i<3;i++)
            {
                ushort tx=(ushort)(i+10);
                var query=Parse(h,Message(tx,false),false,variant=="pid"?310+i:310);
                var reply=Parse(h,Message((ushort)(variant=="tx"?tx+100:tx),true,answers[i]),true,
                    clientPort:variant=="port"?51001:51000);
                Assert.False((await rule.EvaluateAsync(At(query,i*3))).Matched);
                Assert.False((await rule.EvaluateAsync(At(reply,i*3+1))).Matched);
            }
        }
        var good=new R962_CliDnsQueryLowTtlReplyChurnRule();
        var records=Churn();
        for(int i=0;i<records.Length;i++)
            Assert.Equal(i==records.Length-1,(await good.EvaluateAsync(At(records[i],i*3))).Matched);
    }
    [Fact]
    public async Task SyntheticClaimWithoutCaptureValidationCannotTrigger()
    {
        var q=new TrafficRecord { Source=Client,Destination=Resolver,SourcePort=51000,DestinationPort=53,
            IpVersion=4,IsUdp=true,Protocol="UDP",Length=100,L4Len=72,ApplicationProtocol="DNS",
            DnsQname=Name,DnsQtype="A",DnsRcode="NOERROR",ProcessId=310,ProcessName="hostd" };
        var r=new TrafficRecord { Source=Resolver,Destination=Client,SourcePort=53,DestinationPort=51000,
            IpVersion=4,IsUdp=true,Protocol="UDP",Length=100,L4Len=72,ApplicationProtocol="DNS",
            DnsQname=Name,DnsQtype="A",DnsRcode="NXDOMAIN",DnsIsResponse=true };
        var rule=new R916_HostdPublicDnsQueryNxdomainReplyRule();
        Assert.False((await rule.EvaluateAsync(At(q,0))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
}
