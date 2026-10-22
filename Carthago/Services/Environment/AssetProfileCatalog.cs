// SPDX-License-Identifier: MIT
// File: Services/Environment/AssetProfileCatalog.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services.EnvironmentTuning
{
    public enum AssetRole
    {
        Unknown,
        Workstation,
        Server,
        DomainController,
        DatabaseServer,
        DnsResolver,
        AdminHost,
        KubernetesApiServer,
        CiCdServer,
        CameraNvr,
        OtController,
        BackupServer,
        ProxyServer,
        VpnGateway,
        CloudStorageProvider,
        IoTDevice,
        NetworkDevice,
        SecuritySensor
    }

    public sealed record AssetProfile(
        string Identifier,
        AssetRole Role,
        bool IsTrusted,
        bool IsApprovedScanner,
        bool IsApprovedService,
        IReadOnlyList<string> Tags)
    {
        public static AssetProfile Unknown(string? identifier)
            => new(string.IsNullOrWhiteSpace(identifier) ? "unknown" : identifier.Trim(), AssetRole.Unknown, false, false, false, Array.Empty<string>());
    }

    public sealed class AssetProfileCatalog
    {
        private readonly ApprovedAssetRegistry _approved;

        public AssetProfileCatalog(ApprovedAssetRegistry? approved = null)
            => _approved = approved ?? ApprovedAssetRegistry.Current;

        public AssetProfile ResolveSource(TrafficRecord record)
            => Resolve(FirstNonEmpty(record.Source, record.MacSource, record.ProcessName), record, isSource: true);

        public AssetProfile ResolveDestination(TrafficRecord record)
            => Resolve(FirstNonEmpty(record.Destination, record.HttpHost, record.Sni, record.DnsQname, record.MacDestination), record, isSource: false);

        private AssetProfile Resolve(string? identifier, TrafficRecord record, bool isSource)
        {
            var id = string.IsNullOrWhiteSpace(identifier) ? "unknown" : identifier.Trim();
            var tags = new List<string>();
            var role = AssetRole.Unknown;
            var trusted = false;
            var approvedService = false;

            if (_approved.IsAdminHost(id))
            {
                role = AssetRole.AdminHost;
                trusted = true;
                tags.Add("approved-admin-host");
            }
            else if (_approved.IsDomainController(id))
            {
                role = AssetRole.DomainController;
                trusted = true;
                tags.Add("domain-controller");
            }
            else if (_approved.IsApprovedModbusController(id) || _approved.IsApprovedBacnetController(id))
            {
                role = AssetRole.OtController;
                trusted = true;
                approvedService = true;
                tags.Add("approved-ot-controller");
            }
            else if (LooksLikeDns(record, id))
            {
                role = AssetRole.DnsResolver;
                approvedService = true;
                tags.Add("dns-resolver");
            }
            else if (LooksLikeKubernetes(record, id))
            {
                role = AssetRole.KubernetesApiServer;
                tags.Add("kubernetes");
            }
            else if (LooksLikeCiCd(record, id))
            {
                role = AssetRole.CiCdServer;
                tags.Add("ci-cd");
            }
            else if (LooksLikeCamera(record, id))
            {
                role = AssetRole.CameraNvr;
                tags.Add("camera-nvr");
            }
            else if (LooksLikeProxyOrVpn(record, id, out var proxyRole))
            {
                role = proxyRole;
                approvedService = true;
                tags.Add(proxyRole == AssetRole.VpnGateway ? "vpn-gateway" : "proxy-server");
            }
            else if (LooksLikeIoT(record))
            {
                role = AssetRole.IoTDevice;
                tags.Add("iot-or-ot");
            }
            else if (LooksLikeServer(record, isSource))
            {
                role = AssetRole.Server;
                tags.Add("server-like");
            }
            else if (!string.Equals(id, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                role = AssetRole.Workstation;
                tags.Add("default-workstation");
            }

            var isScanner = ContainsAny(record.ProcessName, "nmap", "nessus", "qualys", "rapid7", "openvas")
                || ContainsAny(record.HttpUserAgent, "nmap", "nessus", "qualys", "rapid7", "openvas");

            return new AssetProfile(id, role, trusted, isScanner, approvedService, tags.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        private static bool LooksLikeDns(TrafficRecord record, string id)
            => record.DestinationPort == 53
                || string.Equals(record.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                || ContainsAny(id, "dns", "resolver");

        private static bool LooksLikeKubernetes(TrafficRecord record, string id)
            => record.DestinationPort is 6443 or 10250 or 10255 or 2379 or 2380
                || ContainsAny(id, "kube", "kubernetes", "k8s")
                || ContainsAny(record.HttpUri, "/api/v1", "/apis/apps", "serviceaccounts", "pods");

        private static bool LooksLikeCiCd(TrafficRecord record, string id)
            => ContainsAny(id, "jenkins", "gitlab", "github", "runner", "build", "ci", "nexus", "artifactory")
                || ContainsAny(record.HttpHost, "github", "gitlab", "dev.azure", "jenkins", "artifactory", "nexus");

        private static bool LooksLikeCamera(TrafficRecord record, string id)
            => record.DestinationPort is 554 or 8554
                || ContainsAny(id, "camera", "nvr", "rtsp", "onvif")
                || ContainsAny(record.ApplicationProtocol, "rtsp", "onvif");

        private static bool LooksLikeProxyOrVpn(TrafficRecord record, string id, out AssetRole role)
        {
            if (record.IsVpn == true || ContainsAny(id, "vpn", "wireguard", "openvpn", "tailscale", "zerotier"))
            {
                role = AssetRole.VpnGateway;
                return true;
            }

            if (record.IsProxy == true || ContainsAny(id, "proxy", "squid", "zscaler", "cloudflare"))
            {
                role = AssetRole.ProxyServer;
                return true;
            }

            role = AssetRole.Unknown;
            return false;
        }

        private static bool LooksLikeIoT(TrafficRecord record)
            => record.DestinationPort is 23 or 102 or 502 or 1883 or 1900 or 20000 or 2404 or 47808 or 44818 or 4840 or 5683 or 5684 or 8883
                || ContainsAny(record.ApplicationProtocol, "mqtt", "modbus", "bacnet", "rtsp", "onvif", "coap", "zigbee")
                || ContainsAny(record.Info, "mqtt", "modbus", "bacnet", "rtsp", "onvif", "coap", "zigbee");

        private static bool LooksLikeServer(TrafficRecord record, bool isSource)
        {
            var port = isSource ? record.SourcePort : record.DestinationPort;
            return port is 22 or 25 or 53 or 80 or 443 or 445 or 3389 or 5432 or 3306 or 6379 or 8080 or 8443 or 9200 or 27017;
        }

        private static string? FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }

            return null;
        }

        private static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }
    }
}
