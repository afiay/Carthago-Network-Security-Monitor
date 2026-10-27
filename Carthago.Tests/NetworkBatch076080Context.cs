// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
namespace Carthago.Tests;
internal static class NetworkBatch076080Context
{
    internal static readonly DateTime Origin = DateTime.UtcNow.AddMinutes(-20);
    internal static RuleEvaluationContext Event(int second, string? app = "SMB",
        string? service = "ADMIN_SHARE", int port = 445,
        string source = "10.76.0.10", string target = "10.76.1.10",
        string protocol = "TCP", string? info = null, Guid? id = null)
    {
        var r = new TrafficRecord {
            Id = id ?? Guid.NewGuid(), IpVersion = 4, Source = source, Destination = target,
            Protocol = protocol, IsTcp = protocol == "TCP", IsUdp = protocol == "UDP",
            SourcePort = 52000, DestinationPort = port,
            TcpFlags = protocol == "TCP" ? (ushort)0x18 : null,
            ApplicationProtocol = app, ApplicationService = service, Info = info
        };
        return new RuleEvaluationContext(r, Sensitivity.Balanced, Origin.AddSeconds(second));
    }
}
