// SPDX-License-Identifier: MIT
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Capture-attested fields are internal-set and never inferred from ports or Info.
    internal static class TftpQualifiedEvidence
    {
        internal static bool Request(TrafficRecord r)
            => Research786NetworkEvidence.UdpData(r) && r.DestinationPort == 69
                && r.SourcePort > 1024 && r.TftpRequestCorrelationId == r.Id
                && ((r.TftpInitialRequestOpcode == 1 && r.ApplicationProtocol == "tftp.rrq")
                    || (r.TftpInitialRequestOpcode == 2 && r.ApplicationProtocol == "tftp.wrq"))
                && r.TftpInitialReplyOpcode == null && Clear(r);
        internal static bool FirstReply(TrafficRecord r)
            => Research786NetworkEvidence.UdpData(r) && r.SourcePort > 1024 && r.DestinationPort > 1024
                && r.TftpRequestCorrelationId is Guid id && id != Guid.Empty && id != r.Id
                && r.TftpInitialRequestOpcode == null && Clear(r)
                && ((r.TftpInitialReplyOpcode == 3 && r.ApplicationProtocol == "tftp.data.first" && r.L4Len is >= 4 and <= 516)
                    || (r.TftpInitialReplyOpcode == 4 && r.ApplicationProtocol == "tftp.ack.initial" && r.L4Len == 4));
        private static bool Clear(TrafficRecord r)
            => r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null
                && r.TlsVersion == null && r.Sni == null && !r.DnsIsResponse;
    }
}
