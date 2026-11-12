// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Benchmarking;
using PacketDotNet;
using Xunit;
using Xunit.Abstractions;

namespace Carthago.Tests;

// Separately authored, synthetic accuracy matrix. Labels are scenario ground
// truth, not inferred from the detector. A passing test documents a known gap,
// not a passing production precision gate. Do not tune on this matrix and
// then call it an independent holdout.
public sealed class Smb2PairedAccuracyQualificationTests
{
    private readonly ITestOutputHelper _output;
    public Smb2PairedAccuracyQualificationTests(ITestOutputHelper output) => _output=output;
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static readonly string[] Ids={"R903","R908","R910","R919","R942","R950"};
    private static readonly string[] Classes={"malicious","benign-lookalike","benign-control","unsupported-malicious"};
    public static IEnumerable<object[]> Cases =>
        from id in Ids from label in Classes select new object[]{id,label};

    private static EvidenceDrivenPrecisionRuleBase Rule(string id) => id switch
    {
        "R903"=>new R903_PowershellSmbWriteThenWinRmSynRule(),
        "R908"=>new R908_PublicSmbSynThenParsedWriteRule(),
        "R910"=>new R910_PowershellLdapSynThenSmbWriteRule(),
        "R919"=>new R919_PsexecSmbWriteThenRpcSynRule(),
        "R942"=>new R942_PrivateSmbWriteThenModbusSynRule(),
        "R950"=>new R950_PowershellPrivateScriptGetThenSmbWriteRule(),
        _=>throw new ArgumentOutOfRangeException(nameof(id))
    };

    // Build independent byte fixtures rather than reuse the Q4–Q6 helpers.
    // No production capture, credentials, real filenames or live endpoints.
    private static byte[] WriteBytes(bool truncated)
    {
        var p=new byte[140];
        p[3]=136; p[4]=0xfe; p[5]=0x53; p[6]=0x4d; p[7]=0x42;
        p[8]=64; p[16]=9; p[28]=17; p[40]=7; p[44]=19;
        p[68]=49; p[70]=112; p[72]=24; p[84]=11; p[92]=13;
        for(int i=116;i<p.Length;i++) p[i]=(byte)(i-115);
        if(truncated) Array.Resize(ref p,p.Length-1);
        return p;
    }
    private static TrafficRecord Frame(PacketHandler h,string src,string dst,
        ushort sport,ushort dport,byte flags,uint seq,byte[] payload,string? process,int pid)
    {
        var frame=new byte[40+payload.Length]; frame[0]=0x45; frame[8]=64; frame[9]=6;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2,2),(ushort)frame.Length);
        IPAddress.Parse(src).GetAddressBytes().CopyTo(frame,12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(frame,16);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2),sport);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2),dport);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(24,4),seq);
        frame[32]=0x50; frame[33]=flags; payload.CopyTo(frame,40);
        var rec=Assert.IsType<TrafficRecord>(h.ParseFrame(frame,(LinkLayers)12));
        // Synthetic ETW/process attribution, explicitly not capture-derived.
        rec.ProcessName=process; rec.ProcessId=pid;
        return rec;
    }
    private static TrafficRecord[] Scenario(string id,string label)
    {
        bool control=label=="benign-control", unsupported=label=="unsupported-malicious";
        string src=id=="R908"?"8.8.4.4":"10.77.1.20", dst="10.77.2.40";
        string? process=id=="R919"?"psexec.exe":id is "R903" or "R910" or "R950"?"powershell.exe":null;
        int pid=process==null?0:817;
        var smb=new PacketHandler();
        var syn=Frame(smb,src,dst,53077,445,0x02,1000,Array.Empty<byte>(),process,pid);
        var write=Frame(smb,src,dst,53077,445,0x18,1001,WriteBytes(unsupported),process,pid);
        Assert.Equal(!unsupported,write.Smb2CompleteWriteRequestObserved);
        TrafficRecord OtherSyn(string from,string to,ushort port,ushort sport=53078)
            =>Frame(new PacketHandler(),from,to,sport,port,0x02,2000,Array.Empty<byte>(),process,pid);
        if(id=="R908")
            return new[]{control?OtherSyn(src,dst,445):syn,write};
        if(id=="R903")
            return new[]{write,OtherSyn(src,dst,control?(ushort)5986:(ushort)5985)};
        if(id=="R910")
            return new[]{OtherSyn(src,control?"10.77.2.41":dst,389),write};
        if(id=="R919")
            return new[]{write,OtherSyn(src,dst,control?(ushort)136:(ushort)135)};
        if(id=="R942")
            return new[]{write,OtherSyn(control?"10.77.2.41":dst,"10.77.3.60",502)};
        // The HTTP request is a separately constructed typed observation,
        // not a claim of captured HTTP or independently measured process identity.
        var http=new TrafficRecord{Id=Guid.NewGuid(),Source=src,Destination=dst,
            SourcePort=53078,DestinationPort=80,IpVersion=4,IsTcp=true,Protocol="TCP",
            TcpFlags=0x18,Length=240,L4Len=200,ProcessName=process,ProcessId=pid,
            ApplicationProtocol="HTTP",HttpMethod="GET",
            HttpHost="deployment.example.test",HttpUri=control?"/packages/readme.txt":"/packages/setup.ps1"};
        return new[]{http,write};
    }

    private sealed record Observation(string RuleId,string Label,bool RawMatch,bool Alert,
        double? Confidence,string? EffectiveMode,bool ProducerAvailable);

    private static async Task<Observation> Evaluate(string id,string label)
    {
        var rule=Rule(id); var packets=Scenario(id,label);
        bool raw=false,alert=false; double? confidence=null; string? mode=null;
        for(int i=0;i<packets.Length;i++)
        {
            var record=packets[i];
            var result=await rule.EvaluateAsync(new RuleEvaluationContext(record,Sensitivity.Balanced,Epoch.AddSeconds(i*3)));
            Assert.False(result.Failed,result.FailureMessage);
            raw|=result.Matched;
            foreach(var evt in result.Events)
            {
                confidence=confidence.HasValue?Math.Max(confidence.Value,evt.ConfidenceScore):evt.ConfidenceScore;
                var decision=RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor,evt,record,RuleMode.Alert,"Research");
                alert|=decision.AllowsAlert; mode=decision.EffectiveMode.ToString();
            }
        }
        return new(id,label,raw,alert,confidence,mode,packets.Any(p=>p.Smb2CompleteWriteRequestObserved));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task FrozenScenarioDocumentsRawMatchAndDeploymentBoundary(string id,string label)
    {
        var observation=await Evaluate(id,label);
        _output.WriteLine(JsonSerializer.Serialize(observation));
        Assert.Equal(label is "malicious" or "benign-lookalike",observation.RawMatch);
        Assert.Equal(label!="unsupported-malicious",observation.ProducerAvailable);
        Assert.False(observation.Alert);
        if(observation.RawMatch)
        {
            Assert.True(observation.Confidence.HasValue);
            Assert.Equal("Shadow",observation.EffectiveMode);
        }
    }

    [Fact]
    public async Task ReportSeparatesRawQualityAlertQualityAndProducerGaps()
    {
        var rows=new List<Observation>();
        foreach(var id in Ids)
        foreach(var label in Classes)
            rows.Add(await Evaluate(id,label));
        var supported=rows.Where(r=>r.ProducerAvailable).ToArray();
        DetectionQualityMetrics Metrics(Func<Observation,bool> positive) => new()
        {
            TruePositives=supported.Count(r=>r.Label=="malicious"&&positive(r)),
            FalseNegatives=supported.Count(r=>r.Label=="malicious"&&!positive(r)),
            FalsePositives=supported.Count(r=>r.Label!="malicious"&&positive(r)),
            TrueNegatives=supported.Count(r=>r.Label!="malicious"&&!positive(r))
        };
        var raw=Metrics(r=>r.RawMatch); var alerts=Metrics(r=>r.Alert);
        var gaps=rows.Count(r=>!r.ProducerAvailable);
        _output.WriteLine(JsonSerializer.Serialize(new {
            corpus="Q7-v1-synthetic-not-independent",rows,raw,alerts,producerGaps=gaps,
            productionPromotionEligible=false
        },new JsonSerializerOptions{WriteIndented=true}));
        Assert.Equal(24,rows.Count); Assert.Equal(6,gaps);
        Assert.Equal(6,raw.TruePositives); Assert.Equal(6,raw.FalsePositives);
        Assert.Equal(0,raw.FalseNegatives); Assert.Equal(6,raw.TrueNegatives);
        Assert.Equal(0.5,raw.Precision); Assert.Equal(1.0,raw.Recall);
        Assert.Equal(0,alerts.TruePositives); Assert.Equal(0,alerts.FalsePositives);
        Assert.Equal(6,alerts.FalseNegatives); Assert.Equal(12,alerts.TrueNegatives);
        Assert.Null(alerts.Precision);
    }
}
