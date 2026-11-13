// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using PacketDotNet;

namespace Carthago.Services.Benchmarking
{
    /// <summary>Offline diagnostic replay of original classic-PCAP frames. No process
    /// identity is invented, no live traffic is generated, and no label is inferred
    /// from a detection. Hashes bind input bytes, not the truth of operator labels.</summary>
    public static class Smb2LabCaptureRunner
    {
        private const int MaxCaptureBytes=32*1024*1024, MaxFrames=20000;
        private static readonly JsonSerializerOptions JsonOptions=new()
        {
            PropertyNamingPolicy=JsonNamingPolicy.CamelCase,
            UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow
        };
        private sealed class Manifest
        {
            public Manifest() { }
            public int Version {get;set;}
            public string CaseId {get;set;}="";
            public string Label {get;set;}="";
            public string TargetRule {get;set;}="";
            public string CaptureFile {get;set;}="";
            public string CaptureSha256 {get;set;}="";
            public string GroundTruthFile {get;set;}="";
            public string GroundTruthSha256 {get;set;}="";
            public string SourceIp {get;set;}="";
            public string DestinationIp {get;set;}="";
            public string? FollowupDestinationIp {get;set;}
            public DateTime StartsUtc {get;set;}
            public DateTime EndsUtc {get;set;}
            public bool? ExpectedWrite {get;set;}
        }
        internal sealed record Frame(DateTime Utc, byte[] Bytes, bool Truncated);
        internal sealed record Capture(LinkLayers LinkLayer, IReadOnlyList<Frame> Frames);

        public sealed record LabReport(string CaseId,string Label,string TargetRule,
            string ManifestSha256,string CaptureSha256,string GroundTruthSha256,string GroundTruthStatus,
            int FrameCount,int TruncatedFrames,int ScopedTcpFrames,
            int QualifiedWrites,int CorrelatedTargets,int CorrelatedReplies,
            bool ExpectedWrite,string CoverageStatus,bool? RawMatch,bool? PrecisionGateAllowsAlert,
            double? MaximumConfidence,string? EffectiveMode,
            bool ProductionPromotionEligible);

        public static async Task<LabReport> RunAsync(string manifestPath)
        {
            var full=Path.GetFullPath(manifestPath);
            var manifestBytes=ReadBounded(full,64*1024);
            using(var document=JsonDocument.Parse(manifestBytes))
            {
                if(document.RootElement.ValueKind!=JsonValueKind.Object
                    || document.RootElement.EnumerateObject().GroupBy(p=>p.Name,StringComparer.OrdinalIgnoreCase)
                        .Any(g=>g.Count()!=1))
                    throw new InvalidDataException("Manifest must have unique properties.");
            }
            var m=JsonSerializer.Deserialize<Manifest>(manifestBytes,JsonOptions)
                ??throw new InvalidDataException("Missing manifest.");
            Validate(m);
            string root=Path.GetDirectoryName(full)!;
            var bytes=ReadBounded(Path.Combine(root,m.CaptureFile),MaxCaptureBytes);
            var truth=ReadBounded(Path.Combine(root,m.GroundTruthFile),1024*1024);
            string captureHash=Hash(bytes), truthHash=Hash(truth);
            if(!captureHash.Equals(m.CaptureSha256,StringComparison.OrdinalIgnoreCase)
                || !truthHash.Equals(m.GroundTruthSha256,StringComparison.OrdinalIgnoreCase)
                || truth.Length==0) throw new InvalidDataException("Provenance hash mismatch or empty ground truth.");
            var capture=ParseClassicPcap(bytes);
            if(capture.Frames.Count==0 || capture.Frames[0].Utc<m.StartsUtc
                || capture.Frames[^1].Utc>m.EndsUtc)
                throw new InvalidDataException("Capture outside manifest UTC window.");

            DateTime now=capture.Frames[0].Utc;
            var handler=new PacketHandler(()=>now);
            // Four rules require process attribution, which PCAP does not supply.
            EvidenceDrivenPrecisionRuleBase? rule=m.TargetRule switch
            {
                "R908"=>new R908_PublicSmbSynThenParsedWriteRule(),
                "R942"=>new R942_PrivateSmbWriteThenModbusSynRule(),
                _=>null
            };
            var environment=new Carthago.Services.EnvironmentTuning.ApprovedAssetRegistry(
                new Carthago.Services.EnvironmentTuning.EnvironmentTuningOptions());
            bool raw=false,alert=false;
            double? confidence=null; string? mode=null;
            int truncated=0,scoped=0,writes=0,targets=0,replies=0;
            foreach(var frame in capture.Frames)
            {
                now=frame.Utc;
                if(frame.Truncated){truncated++;continue;}
                var rec=handler.ParseFrame(frame.Bytes,capture.LinkLayer);
                if(rec==null || !rec.IsTcp || rec.IpVersion!=4) continue;
                bool forward=rec.Source==m.SourceIp && rec.Destination==m.DestinationIp;
                bool reverse=rec.Source==m.DestinationIp && rec.Destination==m.SourceIp;
                bool smb=forward&&rec.DestinationPort==445 || reverse&&rec.SourcePort==445;
                bool followup=m.TargetRule=="R942" && rec.Source==m.DestinationIp
                    && rec.Destination==m.FollowupDestinationIp && rec.DestinationPort==502;
                if(!smb&&!followup)continue;
                scoped++;
                if(forward && Smb2QualifiedEvidence.Write(rec))
                {
                    writes++;
                    if(rec.Smb2WriteCreateCorrelationId.HasValue) targets++;
                }
                if(reverse && rec.Smb2WriteResponseCorrelationId.HasValue)replies++;
                if(rule==null)continue;
                var result=await rule.EvaluateAsync(new RuleEvaluationContext(rec,Sensitivity.Balanced,now));
                if(result.Failed)throw new InvalidOperationException("Rule evaluation failed.");
                raw|=result.Matched;
                foreach(var evt in result.Events)
                {
                    confidence=confidence.HasValue?Math.Max(confidence.Value,evt.ConfidenceScore):evt.ConfidenceScore;
                    var decision=RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor,evt,rec,RuleMode.Alert,"Research",environment);
                    alert|=decision.AllowsAlert; mode=decision.EffectiveMode.ToString();
                }
            }
            // Truncation anywhere in this isolated capture disqualifies coverage.
            // An expected WRITE with no qualified observation is a producer gap,
            // not automatically a false negative of the detector.
            string coverage=truncated>0?"capture-truncated":
                scoped==0?"no-scoped-traffic":
                m.ExpectedWrite==true&&writes==0?"expected-write-not-qualified":
                m.ExpectedWrite==false&&writes>0?"ground-truth-conflict":
                rule==null?"process-attribution-unavailable":"packet-rule-evaluated";
            return new(m.CaseId,m.Label,m.TargetRule,Hash(manifestBytes),captureHash,truthHash,
                "operator-supplied-hash-verified-not-independently-validated",
                capture.Frames.Count,truncated,scoped,writes,targets,replies,m.ExpectedWrite!.Value,
                coverage,rule==null?null:raw,rule==null?null:alert,confidence,mode,false);
        }

        private static void Validate(Manifest m)
        {
            if(m.Version!=1 || !Token(m.CaseId,64) || m.Label is not ("benign" or "malicious-simulation")
                || m.TargetRule is not ("R903" or "R908" or "R910" or "R919" or "R942" or "R950")
                || !SafeName(m.CaptureFile) || !m.CaptureFile.EndsWith(".pcap",StringComparison.OrdinalIgnoreCase)
                || !SafeName(m.GroundTruthFile) || string.Equals(m.CaptureFile,m.GroundTruthFile,StringComparison.OrdinalIgnoreCase)
                || !Sha(m.CaptureSha256) || !Sha(m.GroundTruthSha256)
                || !Ipv4(m.SourceIp) || !Ipv4(m.DestinationIp) || m.SourceIp==m.DestinationIp
                || (m.TargetRule=="R942" && (!Ipv4(m.FollowupDestinationIp)
                    || m.FollowupDestinationIp==m.DestinationIp || m.FollowupDestinationIp==m.SourceIp))
                || (m.TargetRule!="R942" && m.FollowupDestinationIp!=null)
                || m.StartsUtc.Kind!=DateTimeKind.Utc || m.EndsUtc.Kind!=DateTimeKind.Utc
                || m.EndsUtc<=m.StartsUtc || m.EndsUtc-m.StartsUtc>TimeSpan.FromMinutes(10)
                || !m.ExpectedWrite.HasValue)
                throw new InvalidDataException("Invalid manifest contract.");
        }
        private static bool Token(string? s,int max)=>!string.IsNullOrEmpty(s)&&s.Length<=max
            && s.All(c=>char.IsAsciiLetterOrDigit(c)||c=='-'||c=='_');
        private static bool SafeName(string? s)=>!string.IsNullOrEmpty(s)&&s.Length<=128
            && s!="."&&s!=".."&&!s.StartsWith(".",StringComparison.Ordinal)
            && s.All(c=>char.IsAsciiLetterOrDigit(c)||c=='-'||c=='_'||c=='.');
        private static bool Sha(string? s)=>s?.Length==64 && s.All(Uri.IsHexDigit);
        private static bool Ipv4(string? s)=>IPAddress.TryParse(s,out var ip)
            && ip.AddressFamily==AddressFamily.InterNetwork&&ip.ToString()==s;
        private static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        private static byte[] ReadBounded(string path,int max)
        {
            using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(stream.Length<1||stream.Length>max)throw new InvalidDataException("Input size outside limits.");
            var bytes=new byte[(int)stream.Length];stream.ReadExactly(bytes);
            if(stream.ReadByte()!=-1)throw new InvalidDataException("Input changed while reading.");
            return bytes;
        }

        internal static Capture ParseClassicPcap(byte[] bytes)
        {
            if(bytes.Length<24||bytes.Length>MaxCaptureBytes)throw new InvalidDataException("PCAP header/size.");
            uint magic=BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(0,4));
            bool little=magic is 0xd4c3b2a1 or 0x4d3cb2a1;
            bool nano=magic is 0xa1b23c4d or 0x4d3cb2a1;
            if(magic is not (0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1))
                throw new InvalidDataException("Classic PCAP only.");
            uint U32(int offset)=>little?BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset,4))
                :BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset,4));
            ushort U16(int offset)=>little?BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset,2))
                :BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset,2));
            uint snap=U32(16),link=U32(20);
            if(U16(4)!=2||U16(6)!=4||snap<1||snap>262144||link is not (1 or 101 or 228))
                throw new InvalidDataException("Unsupported PCAP format/link type.");
            var frames=new List<Frame>();int pos=24;DateTime? last=null;
            while(pos<bytes.Length)
            {
                if(frames.Count>=MaxFrames||bytes.Length-pos<16)throw new InvalidDataException("PCAP record limit/header.");
                uint sec=U32(pos),fraction=U32(pos+4),incl=U32(pos+8),orig=U32(pos+12);
                pos+=16;
                if(fraction>=(nano?1000000000u:1000000u)||incl==0||incl>snap||incl>orig
                    || incl>(uint)(bytes.Length-pos))
                    throw new InvalidDataException("Invalid PCAP record.");
                var at=DateTime.UnixEpoch.AddSeconds(sec).AddTicks(nano?fraction/100L:fraction*10L);
                if(last.HasValue&&at<last.Value)throw new InvalidDataException("Nonmonotonic PCAP timestamps.");
                if(frames.Count>0&&at-frames[0].Utc>TimeSpan.FromMinutes(10))throw new InvalidDataException("PCAP duration limit.");
                frames.Add(new(at,bytes.AsSpan(pos,(int)incl).ToArray(),incl<orig));
                last=at;pos+=(int)incl;
            }
            return new((LinkLayers)link,frames);
        }
    }
}
