// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch236240Context
{
    private static int _source = 10;
    internal static readonly DateTime Origin = new(2026, 10, 28, 7, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int rule)
    {
        var n = Interlocked.Increment(ref _source);
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = "10.236.0." + n,
            Destination = "198.51.100." + (rule - 1),
            SourcePort = 51000, DestinationPort = 80,
            Protocol = "TCP", IsTcp = true, IsUdp = false,
            ApplicationProtocol = "HTTP", HttpMethod = "GET",
            HttpUri = "/firmware/router-v3.bin", HttpHost = "updates.example",
            ProcessName = "camera-updater.exe", Length = 320, L4Len = 220,
            Info = ""
        };
        switch (rule)
        {
            case 237: r.HttpUri = "/login.cgi"; r.ProcessName = "router-updater.exe"; break;
            case 238:
                r.ApplicationProtocol = "TLS"; r.HttpMethod = null; r.HttpUri = null;
                r.HttpHost = null; r.DestinationPort = 443; r.TlsVersion = "TLS1.3";
                r.Sni = "api.smartthings.com"; r.ProcessName = "homeassistant"; break;
            case 239:
                r.ApplicationProtocol = "mqtt.publish"; r.HttpMethod = null; r.HttpUri = null;
                r.HttpHost = null; r.DestinationPort = 1883; r.ProcessName = "zigbee2mqtt";
                r.MqttPublishTopicObserved = true; r.MqttControlTopicObserved = true; break;
            case 240:
                r.ApplicationProtocol = "modbus.write"; r.HttpMethod = null; r.HttpUri = null;
                r.HttpHost = null; r.DestinationPort = 502; r.ProcessName = "engineering-tool.exe"; break;
        }
        return r;
    }
}
