// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch226230Context
{
    private static int _source = 20;
    internal static readonly DateTime Origin = new(2026, 10, 28, 6, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int rule)
    {
        var n = Interlocked.Increment(ref _source);
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = "10.226.0." + n,
            Destination = rule == 226 ? "10.227.0.20" : rule == 228 ? "198.51.100.228" : "10.230.0.10",
            Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 51000, DestinationPort = rule == 226 ? 44818 : rule == 228 ? 4840 : 1883,
            ApplicationProtocol = rule == 226 ? "ethernetip.listidentity" : rule == 228 ? "opcua"
                : rule == 229 ? "mqtt.publish" : "mqtt.connect",
            ApplicationService = rule == 226 ? "EtherNetIP" : rule == 228 ? "OPC UA" : "MQTT",
            Length = 160, L4Len = 90, Info = ""
        };
        if (rule == 227)
        {
            r.Source = "02:00:00:00:00:01"; r.Destination = "01:0e:cf:00:00:00";
            r.MacSource = r.Source; r.MacDestination = r.Destination;
            r.Protocol = "PROFINET-DCP"; r.IsTcp = false;
            r.SourcePort = null; r.DestinationPort = null;
            r.ApplicationProtocol = "profinet.dcp.identify";
        }
        if (rule == 229) { r.MqttRetain = true; r.MqttTopic = "devices/cmd"; }
        if (rule == 230) r.MqttWillTopic = "devices/control";
        return r;
    }
}
