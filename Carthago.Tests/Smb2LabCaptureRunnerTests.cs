// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

// Synthetic PCAP contract tests only; never count these as independent lab captures.
public sealed class Smb2LabCaptureRunnerTests
{
    private static readonly DateTime Epoch=new(2026,11,13,12,0,0,DateTimeKind.Utc);
    private static byte[] Tcp(string src,string dst,int sport,int dport,byte flags,uint seq,byte[] payload,uint ack=0)
    {
        var p=new byte[40+payload.Length];p[0]=0x45;p[8]=64;p[9]=6;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p,12);IPAddress.Parse(dst).GetAddressBytes().CopyTo(p,16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20,2),(ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22,2),(ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24,4),seq);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(28,4),ack);p[32]=0x50;p[33]=flags;
        payload.CopyTo(p,40);return p;
    }
    private static byte[] Write()
    {
        var p=new byte[120];p[3]=116;p[4]=0xfe;p[5]=0x53;p[6]=0x4d;p[7]=0x42;
        p[8]=64;p[16]=9;p[28]=1;p[40]=1;p[44]=1;p[68]=49;p[70]=112;p[72]=4;p[84]=1;p[92]=2;
        return p;
    }
    private static byte[] Pcap(int gap=1,bool truncated=false,bool big=false,bool nano=false)
    {
        using var ms=new MemoryStream();
        void U32(uint n){var b=new byte[4];if(big)BinaryPrimitives.WriteUInt32BigEndian(b,n);else BinaryPrimitives.WriteUInt32LittleEndian(b,n);ms.Write(b);}
        void U16(ushort n){var b=new byte[2];if(big)BinaryPrimitives.WriteUInt16BigEndian(b,n);else BinaryPrimitives.WriteUInt16LittleEndian(b,n);ms.Write(b);}
        U32(nano?0xa1b23c4du:0xa1b2c3d4u);U16(2);U16(4);U32(0);U32(0);U32(65535);U32(101);
        uint sec=(uint)new DateTimeOffset(Epoch).ToUnixTimeSeconds();
        void Frame(byte[] p,uint at,uint fraction,bool shortFrame)
        {U32(at);U32(fraction);U32((uint)p.Length);U32((uint)p.Length+(shortFrame?1u:0u));ms.Write(p);}
        Frame(Tcp("10.77.1.20","10.77.2.40",53000,445,2,100,Array.Empty<byte>()),sec,0,false);
        Frame(Tcp("10.77.1.20","10.77.2.40",53000,445,0x18,101,Write()),sec+1,nano?500000000u:500000u,truncated);
        Frame(Tcp("10.77.2.40","10.77.3.60",53001,502,2,200,Array.Empty<byte>()),sec+(uint)gap+1,0,false);
        return ms.ToArray();
    }
    private static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
    private static async Task<Smb2LabCaptureRunner.LabReport> Run(byte[] pcap,string rule="R942",
        string variant="")
    {
        string dir=Path.Combine(Path.GetTempPath(),"carthago-q9-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var truth=System.Text.Encoding.UTF8.GetBytes("Synthetic contract fixture; not independent ground truth.");
            File.WriteAllBytes(Path.Combine(dir,"case.pcap"),pcap);
            File.WriteAllBytes(Path.Combine(dir,"truth.txt"),truth);
            var manifest=new {
                version=1,caseId="Q9-CONTRACT",label="malicious-simulation",targetRule=rule,
                captureFile=variant=="traversal"?"../case.pcap":"case.pcap",
                captureSha256=variant=="bad-hash"?new string('0',64):Hash(pcap),
                groundTruthFile="truth.txt",groundTruthSha256=Hash(truth),
                sourceIp="10.77.1.20",destinationIp="10.77.2.40",
                followupDestinationIp=rule=="R942"?"10.77.3.60":null,
                startsUtc=Epoch,endsUtc=Epoch.AddSeconds(variant=="outside-window"?1:120),
                expectedWrite=true
            };
            string path=Path.Combine(dir,"manifest.json");
            File.WriteAllText(path,JsonSerializer.Serialize(manifest));
            return await Smb2LabCaptureRunner.RunAsync(path);
        }
        finally{Directory.Delete(dir,true);}
    }
    [Theory]
    [InlineData(false,false)]
    [InlineData(true,false)]
    [InlineData(false,true)]
    [InlineData(true,true)]
    public async Task OriginalFrameReplayPreservesTimestampAndShadowBoundary(bool big,bool nano)
    {
        var result=await Run(Pcap(big:big,nano:nano));
        Assert.Equal(3,result.FrameCount);Assert.Equal(1,result.QualifiedWrites);
        Assert.Equal(64,result.ManifestSha256.Length);
        Assert.Equal("packet-rule-evaluated",result.CoverageStatus);
        Assert.True(result.RawMatch);Assert.False(result.PrecisionGateAllowsAlert);
        Assert.False(result.ProductionPromotionEligible);
    }
    [Fact]
    public async Task CaptureTimeNotExecutionTimeControlsRuleWindow()
    {
        var result=await Run(Pcap(gap:60));
        Assert.Equal(1,result.QualifiedWrites);Assert.False(result.RawMatch);
    }
    [Fact]
    public async Task TruncatedCaptureAndMissingProcessRemainSeparate()
    {
        var shortCapture=await Run(Pcap(truncated:true));
        Assert.Equal("capture-truncated",shortCapture.CoverageStatus);
        Assert.Equal(0,shortCapture.QualifiedWrites);
        var process=await Run(Pcap(),"R910");
        Assert.Equal("process-attribution-unavailable",process.CoverageStatus);
        Assert.Null(process.RawMatch);Assert.Null(process.PrecisionGateAllowsAlert);
    }
    [Theory]
    [InlineData("bad-hash")]
    [InlineData("traversal")]
    [InlineData("outside-window")]
    public async Task ProvenanceAndScopeViolationsReject(string variant)
        => await Assert.ThrowsAsync<InvalidDataException>(()=>Run(Pcap(),variant:variant));
    [Theory]
    [InlineData("magic")]
    [InlineData("link")]
    [InlineData("record")]
    [InlineData("time")]
    public void MalformedPcapRejected(string variant)
    {
        var p=Pcap();
        switch(variant)
        {
            case "magic": p[0]=0;break;
            case "link": p[20]=113;break;
            case "record": Array.Resize(ref p,p.Length-1);break;
            case "time": BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(28,4),1000000);break;
        }
        Assert.Throws<InvalidDataException>(()=>Smb2LabCaptureRunner.ParseClassicPcap(p));
    }

    [Theory]
    [InlineData(30,true)]
    [InlineData(31,false)]
    public void CaptureClockControlsProducerResponseExpiry(int seconds,bool expected)
    {
        DateTime now=Epoch;
        var handler=new PacketHandler(()=>now);
        var link=(LinkLayers)101;
        handler.ParseFrame(Tcp("10.77.1.20","10.77.2.40",53000,445,0x02,100,Array.Empty<byte>()),link);
        handler.ParseFrame(Tcp("10.77.2.40","10.77.1.20",445,53000,0x12,500,Array.Empty<byte>(),101),link);
        var request=handler.ParseFrame(Tcp("10.77.1.20","10.77.2.40",53000,445,0x18,101,Write(),501),link);
        Assert.NotNull(request);Assert.True(request!.Smb2CompleteWriteRequestObserved);
        var reply=new byte[84];reply[3]=80;reply[4]=0xfe;reply[5]=0x53;reply[6]=0x4d;reply[7]=0x42;
        reply[8]=64;reply[16]=9;reply[20]=1;reply[28]=1;reply[40]=1;reply[44]=1;
        reply[68]=17;reply[72]=4;
        now=Epoch.AddSeconds(seconds);
        var response=handler.ParseFrame(Tcp("10.77.2.40","10.77.1.20",445,53000,0x18,501,reply,221),link);
        Assert.NotNull(response);
        Assert.Equal(expected,response!.Smb2WriteResponseCorrelationId.HasValue);
        if(expected)Assert.Equal(request.Id,response.Smb2WriteResponseCorrelationId);
    }
}
