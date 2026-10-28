// SPDX-License-Identifier: MIT
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Parsed operation contracts only. Info, guessed ApplicationService and
    // unverified payload descriptions never establish a request or write.
    internal static class NetworkBatch236240Evidence
    {
        internal static bool Tcp(TrafficRecord r)
            => r.Id != Guid.Empty && r.IsTcp && !r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && IPAddress.TryParse(r.Source, out var src)
                && IPAddress.TryParse(r.Destination, out var dst)
                && src.AddressFamily == dst.AddressFamily && !src.Equals(dst)
                && r.DnsQname == null;

        private static bool PlainHttp(TrafficRecord r)
            => Tcp(r) && r.TlsVersion == null && r.DestinationPort is 80 or 8080 or 8000 or 8008 or 8888
                && string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                && r.HttpMethod is "GET" or "POST" && r.HttpUri != null;

        private static string Path(TrafficRecord r) => (r.HttpUri ?? "").Split('?', 2)[0];
        private static bool DeviceProcess(string? process)
            => process != null && (process.Equals("camera-updater.exe", StringComparison.OrdinalIgnoreCase)
                || process.Equals("router-updater.exe", StringComparison.OrdinalIgnoreCase)
                || process.Equals("device-agent.exe", StringComparison.OrdinalIgnoreCase));

        internal static bool FirmwareRequest(TrafficRecord r)
        {
            if (!PlainHttp(r) || r.HttpMethod != "GET" || !DeviceProcess(r.ProcessName)) return false;
            var path = Path(r);
            var update = path.Contains("/firmware/", StringComparison.OrdinalIgnoreCase)
                || path.Contains("/updates/", StringComparison.OrdinalIgnoreCase)
                || path.Contains("/ota/", StringComparison.OrdinalIgnoreCase);
            return update && (path.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".img", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".fw", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".trx", StringComparison.OrdinalIgnoreCase));
        }

        internal static bool AdminRequest(TrafficRecord r)
        {
            if (!PlainHttp(r) || !DeviceProcess(r.ProcessName)) return false;
            var path = Path(r);
            return path.Equals("/login.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/setup.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/webcm", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/cgi-bin/luci/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/goform/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/boaform/", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool HubCloud(TrafficRecord r, out string host)
        {
            host = "";
            if (!Tcp(r) || !NetworkBatch226230Evidence.Public(r.Destination)
                || !NetworkBatch226230Evidence.Public(r.Destination)
                || !HubProcess(r.ProcessName)) return false;
            if (r.TlsVersion != null && string.Equals(r.ApplicationProtocol, "TLS", StringComparison.OrdinalIgnoreCase)
                && r.HttpMethod == null)
                host = r.Sni ?? "";
            else if (PlainHttp(r))
                host = r.HttpHost ?? "";
            else return false;
            return HostRoot(host, "smartthings.com") || HostRoot(host, "tuya.com")
                || HostRoot(host, "nabucasa.com") || HostRoot(host, "meethue.com");
        }

        private static bool HostRoot(string host, string root)
            => host.Equals(root, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + root, StringComparison.OrdinalIgnoreCase);

        private static bool HubProcess(string? name)
            => name != null && (name.Equals("homeassistant", StringComparison.OrdinalIgnoreCase)
                || name.Equals("homeassistant.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("hass", StringComparison.OrdinalIgnoreCase)
                || name.Equals("zigbee2mqtt", StringComparison.OrdinalIgnoreCase));

        internal static bool BridgeMqtt(TrafficRecord r, out bool controlTopic)
        {
            controlTopic = false;
            if (!Tcp(r) || r.TlsVersion != null || r.HttpMethod != null
                || r.DestinationPort != 1883
                || !NetworkBatch226230Evidence.Public(r.Destination)
                || !string.Equals(r.ProcessName, "zigbee2mqtt", StringComparison.OrdinalIgnoreCase)
                   && !string.Equals(r.ProcessName, "zigbee2mqtt.exe", StringComparison.OrdinalIgnoreCase))
                return false;
            if (string.Equals(r.ApplicationProtocol, "mqtt.publish", StringComparison.OrdinalIgnoreCase))
            {
                if (!r.MqttPublishTopicObserved) return false;
                controlTopic = r.MqttControlTopicObserved;
                return true;
            }
            return string.Equals(r.ApplicationProtocol, "mqtt.connect", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool ModbusWrite(TrafficRecord r)
            => Tcp(r) && r.DestinationPort == 502 && r.TlsVersion == null
                && r.HttpMethod == null
                && string.Equals(r.ApplicationProtocol, "modbus.write", StringComparison.OrdinalIgnoreCase);
    }
}
