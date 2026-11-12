// SPDX-License-Identifier: MIT
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Smb2QualifiedEvidence
    {
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
