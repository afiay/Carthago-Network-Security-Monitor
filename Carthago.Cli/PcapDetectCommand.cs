// SPDX-License-Identifier: MIT
using System.Globalization;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Cli;

internal static class PcapDetectCommand
{
    internal sealed record Finding(string RuleId,int PacketNumber,DateTime TimestampUtc,uint Nanoseconds,
        int Section,int InterfaceId,string Method);
    internal sealed record RuleResult(string RuleId,string Status,int Evaluated,int Matches,int Suppressed);
    internal sealed record Result(string Format,int PacketsRead,int Parsed,int Rejected,int CaptureTruncated,
        int ClockResets,int MatchCount,int SuppressedCount,int FindingLimit,bool FindingsTruncated,
        IReadOnlyList<RuleResult> Rules,IReadOnlyList<Finding> Findings);

    internal static bool TryParse(string[] command,out string path,out string[] rules,out int limit)
    {
        path="";rules=Array.Empty<string>();limit=50;
        if(command.Length is not (5 or 7) || command[0]!="pcap" || command[1]!="detect" ||
            command[3]!="--rules" || string.IsNullOrWhiteSpace(command[2]) ||
            command[2].StartsWith("--",StringComparison.Ordinal) ||
            Path.GetExtension(command[2]).ToLowerInvariant() is not (".pcap" or ".pcapng") ||
            command[4].Length>1024) return false;
        var ids=command[4].Split(',');
        if(ids.Length is <1 or >64 || ids.Any(id=>id!=id.Trim() || !RuleIdValidator.IsCoreRuleId(id)) ||
            ids.Distinct(StringComparer.Ordinal).Count()!=ids.Length) return false;
        if(command.Length==7 && (command[5]!="--limit" ||
            !int.TryParse(command[6],NumberStyles.None,CultureInfo.InvariantCulture,out limit) ||
            limit is <1 or >100)) return false;
        path=command[2];rules=ids;return true;
    }

    internal static async Task<Result> RunAsync(string path,string[] rules,int limit,CancellationToken token)
    {
        if(limit is <1 or >100) throw new ArgumentOutOfRangeException(nameof(limit));
        var supported=rules.Where(PortableReplayDispatcher.Supports).ToArray();
        var findings=new List<Finding>(limit);
        // Retain only the current processor epoch per interface (maximum eight).
        // A replaced parser marks the same reset boundary for detector state.
        var sessions=new Dictionary<int,(PortablePacketProcessor Processor,PortableReplayDispatcher Dispatcher)>();
        int section=-1,evaluated=0,matches=0,suppressed=0;
        var capture=await PcapInspectCommand.InspectAsync(path,1,token,(row,record,processor)=>
        {
            token.ThrowIfCancellationRequested();
            if(supported.Length==0) return;
            if(section!=row.Section){sessions.Clear();section=row.Section;}
            if(!sessions.TryGetValue(row.InterfaceId,out var session) || !ReferenceEquals(session.Processor,processor))
            {
                session=(processor,new PortableReplayDispatcher());
                sessions[row.InterfaceId]=session;
            }
            var context=new PacketEvaluationContext(record,Sensitivity.Balanced,row.TimestampUtc);
            foreach(var id in supported)
            {
                evaluated++;
                var observation=session.Dispatcher.Evaluate(id,context,out var method);
                if(observation==WebSignatureObservation.Suppressed) suppressed++;
                if(observation!=WebSignatureObservation.Match) continue;
                matches++;
                if(findings.Count<limit) findings.Add(new(id,row.PacketNumber,row.TimestampUtc,row.Nanoseconds,
                    row.Section,row.InterfaceId,method));
            }
        });
        token.ThrowIfCancellationRequested();
        var results=rules.Select(id=>PortableReplayDispatcher.Supports(id)
            ?new RuleResult(id,"evaluated",evaluated,matches,suppressed)
            :new RuleResult(id,"unsupported_detector",0,0,0)).ToArray();
        return new(capture.Format,capture.PacketsRead,capture.Parsed,capture.Rejected,capture.CaptureTruncated,
            capture.ClockResets,matches,suppressed,limit,matches>findings.Count,results,findings);
    }
}
