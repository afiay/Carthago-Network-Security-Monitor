// SPDX-License-Identifier: MIT
// File: Interop/Zeek/ZeekFieldMapping.cs
using System.Collections.Generic;

namespace Carthago.Interop.Zeek
{
    public sealed class ZeekLogSchema
    {
        public string LogName { get; set; } = string.Empty;
        public Dictionary<string, string> Fields { get; set; } = new();
    }

    public static class ZeekFieldMapping
    {
        public static IReadOnlyList<ZeekLogSchema> KnownSchemas { get; } = new[]
        {
            new ZeekLogSchema { LogName = "conn", Fields = { ["id.orig_h"] = "TrafficRecord.Source", ["id.resp_h"] = "TrafficRecord.Destination", ["proto"] = "TrafficRecord.Protocol" } },
            new ZeekLogSchema { LogName = "dns", Fields = { ["query"] = "TrafficRecord.DnsQname", ["qtype_name"] = "TrafficRecord.DnsQtype", ["rcode_name"] = "TrafficRecord.DnsRcode" } },
            new ZeekLogSchema { LogName = "http", Fields = { ["method"] = "TrafficRecord.HttpMethod", ["host"] = "TrafficRecord.HttpHost", ["uri"] = "TrafficRecord.HttpUri", ["user_agent"] = "TrafficRecord.HttpUserAgent" } },
            new ZeekLogSchema { LogName = "ssl", Fields = { ["server_name"] = "TrafficRecord.Sni", ["ja3"] = "TrafficRecord.Ja3", ["ja4"] = "TrafficRecord.Ja4" } }
        };
    }
}
