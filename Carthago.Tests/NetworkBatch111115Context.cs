// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch111115Context
{
    private static readonly DateTime Origin = DateTime.UtcNow.AddMinutes(-30);

    internal static string Source()
    {
        var bytes = Guid.NewGuid().ToByteArray();
        return "10.113." + bytes[0] + "." + Math.Max(1, (int)bytes[1]);
    }

    internal static RuleEvaluationContext Web(int seconds, string source,
        string host = "file.io", string method = "POST",
        string uri = "/upload", int bytes = 450_000,
        string process = "powershell.exe", string? headers = null,
        string? info = null)
        => NetworkBatch101105Context.Cloud(seconds, source, host,
            method, bytes, uri, process, headers, info);

    internal static RuleEvaluationContext Mqtt(int milliseconds, string source,
        string destination = "198.51.100.40", string host = "broker.hivemq.com",
        string info = "publish topic=device/temp", string process = "gatewayd.exe")
    {
        var record = new TrafficRecord
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "MQTT", ApplicationProtocol = "MQTT",
            ApplicationService = "MQTT", IsTcp = true, IsUdp = false,
            SourcePort = 51000, DestinationPort = 1883, Length = 2048,
            L4Len = 2048, HttpHost = host, ProcessName = process,
            Info = info
        };
        return new RuleEvaluationContext(record, Sensitivity.Balanced,
            Origin.AddMilliseconds(milliseconds));
    }
}
