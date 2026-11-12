// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Smb2QualifiedEvidence
    {
        internal static DetectionEvidenceItem[] WithTarget(DetectionEvidenceItem[] evidence, TrafficRecord r)
        {
            if (!Write(r) || r.Smb2WriteCreateCorrelationId is not Guid id || id==Guid.Empty
                || r.Smb2WriteShareKind is not ("administrative-disk" or "other-disk")
                || r.Smb2WriteFileKind is not ("executable" or "script" or "other")) return evidence;
            var result=new List<DetectionEvidenceItem>(evidence)
            {
                new("smb2.share.kind",r.Smb2WriteShareKind,"capture-correlated"),
                new("smb2.file.kind",r.Smb2WriteFileKind,"capture-correlated")
            };
            return result.ToArray();
        }

        internal static bool Write(TrafficRecord r)
            => Research786NetworkEvidence.TcpData(r)
                && r.DestinationPort == 445 && r.SourcePort != 445
                && r.Smb2CompleteWriteRequestObserved
                && r.Smb2ValidatedWriteLength is uint bytes && bytes > 0
                && r.L4Len is int len && (long)bytes + 116 <= len
                && r.ApplicationProtocol == "smb2.write.request"
                && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null
                && r.TlsVersion == null && r.Sni == null && !r.DnsIsResponse;
    }
}
