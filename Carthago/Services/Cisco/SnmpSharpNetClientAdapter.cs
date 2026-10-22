// SPDX-License-Identifier: MIT
// File: Services/Cisco/SnmpSharpNetClientAdapter.cs
using System;
using System.Collections.Generic;
using System.Net;
using SnmpSharpNet;

namespace Carthago.Services.Cisco
{
    public sealed class SnmpSharpNetClientAdapter : ISnmpClientAdapter
    {
        public IReadOnlyList<SnmpWalkVariable> Walk(
            string host,
            int port,
            string community,
            string rootOid,
            int timeoutMilliseconds = 3000,
            int retries = 1,
            int maxRepetitions = 25)
        {
            if (!IPAddress.TryParse(host, out var agentAddress))
                throw new ArgumentException("SNMP host must be an IPv4 or IPv6 address for this adapter.", nameof(host));
            if (string.IsNullOrWhiteSpace(community))
                throw new ArgumentException("SNMP community is required.", nameof(community));
            if (string.IsNullOrWhiteSpace(rootOid))
                throw new ArgumentException("SNMP root OID is required.", nameof(rootOid));

            var results = new List<SnmpWalkVariable>();
            var parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));
            var root = new Oid(rootOid);

            using var target = new UdpTarget(agentAddress, port, timeoutMilliseconds, retries);
            var pdu = new Pdu(PduType.GetBulk)
            {
                NonRepeaters = 0,
                MaxRepetitions = maxRepetitions
            };
            pdu.VbList.Add(root);

            var lastOid = (Oid)root.Clone();
            var done = false;
            while (!done)
            {
                pdu.VbList[0].Oid = lastOid;
                var response = target.Request(pdu, parameters) as SnmpV2Packet;
                if (response == null || response.Pdu.ErrorStatus != 0 || response.Pdu.VbList.Count == 0)
                    break;

                foreach (Vb vb in response.Pdu.VbList)
                {
                    lastOid = vb.Oid;
                    var oidText = vb.Oid.ToString();
                    if (!oidText.StartsWith(rootOid, StringComparison.Ordinal))
                    {
                        done = true;
                        break;
                    }

                    var octets = vb.Value as OctetString;
                    results.Add(new SnmpWalkVariable(
                        oidText,
                        vb.Value?.ToString(),
                        octets?.ToArray()));
                }
            }

            return results;
        }
    }
}
