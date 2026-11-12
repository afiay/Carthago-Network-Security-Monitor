// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;

namespace Carthago.Services.EnvironmentTuning
{
    // Operator-supplied change scope, not proof of user identity or authorization.
    // Exact source/destination and observed filename category, not a broad allowlist.
    public sealed record Smb2MaintenanceScope
    {
        public string ChangeId { get; init; } = "";
        public string RuleId { get; init; } = "";
        public string SourceIp { get; init; } = "";
        public string DestinationIp { get; init; } = "";
        public string ProcessName { get; init; } = "";
        public string ShareKind { get; init; } = "";
        public string FileKind { get; init; } = "";
        public DateTime StartsUtc { get; init; }
        public DateTime EndsUtc { get; init; }

        internal static Smb2MaintenanceScope[] Snapshot(IEnumerable<Smb2MaintenanceScope>? entries)
        {
            var input=entries?.Take(257).ToArray() ?? Array.Empty<Smb2MaintenanceScope>();
            if(input.Length>256) return Array.Empty<Smb2MaintenanceScope>();
            // Reject all duplicate IDs rather than arbitrarily prefer one entry.
            return input.Where(s=>s!=null && s.Valid())
                .GroupBy(s=>s.ChangeId,StringComparer.OrdinalIgnoreCase)
                .Where(g=>g.Count()==1).Select(g=>g.Single()).ToArray();
        }

        private bool Valid()
            => !string.IsNullOrEmpty(ChangeId) && ChangeId.Length<=64
                && ChangeId.All(c=>char.IsAsciiLetterOrDigit(c)||c=='-'||c=='_')
                && RuleId is "R910" or "R950"
                && PrivateIpv4(SourceIp) && PrivateIpv4(DestinationIp) && SourceIp!=DestinationIp
                && ProcessName is "powershell.exe" or "pwsh.exe"
                && ShareKind is "administrative-disk" or "other-disk"
                && FileKind is "executable" or "script" or "other"
                && StartsUtc.Kind==DateTimeKind.Utc && EndsUtc.Kind==DateTimeKind.Utc
                && EndsUtc>StartsUtc && EndsUtc-StartsUtc<=TimeSpan.FromHours(8)
                && EndsUtc-StartsUtc>TimeSpan.FromSeconds(45);

        private static bool PrivateIpv4(string? value)
        {
            if(!IPAddress.TryParse(value,out var ip) || ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork
                || ip.ToString()!=value) return false;
            var b=ip.GetAddressBytes();
            return b[0]==10 || (b[0]==172&&b[1]>=16&&b[1]<=31) || (b[0]==192&&b[1]==168);
        }

        internal static Smb2MaintenanceScope? Match(IEnumerable<Smb2MaintenanceScope> scopes,
            string ruleId, DetectionEvent evt, TrafficRecord r)
        {
            // Require the actual terminal WRITE and its capture-correlated context.
            // Local TCP socket attribution is an observation, not a signed process identity.
            if(ruleId is not ("R910" or "R950") || evt.RuleId!=ruleId
                || !Smb2QualifiedEvidence.Write(r) || !PrivateIpv4(r.Source) || !PrivateIpv4(r.Destination)
                || r.SrcIsLocalHost!=true || r.DstIsLocalHost!=false
                || r.ProcessId<=0 || r.ProcessAttribution!="TcpSocketTable"
                || r.Smb2WriteCreateCorrelationId is not Guid createId || createId==Guid.Empty
                || !Guid.TryParse(evt.PacketId,out var packetId) || packetId!=r.Id
                || evt.SourceIp!=r.Source || evt.DestinationIp!=r.Destination
                || evt.SourcePort!=r.SourcePort || evt.DestinationPort!=r.DestinationPort
                || !string.Equals(evt.ProcessName,r.ProcessName,StringComparison.OrdinalIgnoreCase)
                || evt.TimestampUtc.Kind!=DateTimeKind.Utc || evt.WindowSeconds!=45 || evt.Count!=2)
                return null;

            // The entire possible 45s rule window must fit the configured interval.
            // No grace period after expiration; ambiguous overlapping matches fail closed.
            Smb2MaintenanceScope? match=null;
            foreach(var s in scopes)
            {
                if(s.RuleId!=ruleId || s.SourceIp!=r.Source || s.DestinationIp!=r.Destination
                    || !string.Equals(s.ProcessName,r.ProcessName,StringComparison.OrdinalIgnoreCase)
                    || s.ShareKind!=r.Smb2WriteShareKind || s.FileKind!=r.Smb2WriteFileKind
                    || evt.TimestampUtc<s.StartsUtc || evt.TimestampUtc>=s.EndsUtc
                    || evt.TimestampUtc-s.StartsUtc<TimeSpan.FromSeconds(45)) continue;
                if(match!=null) return null;
                match=s;
            }
            return match;
        }
    }
}
