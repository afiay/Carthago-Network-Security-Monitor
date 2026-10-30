// SPDX-License-Identifier: MIT
// GA R421–R430 — SOURCE CANDIDATE — UNVERIFIED.
// 120 concrete xUnit invocations authored; ZERO executed. No validated
// service identity, exposure, response or authenticated probe
// producer exists for a sound positive assertion at this boundary.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch421430AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 5, 0, 0, DateTimeKind.Utc);

    public static IEnumerable<object[]> MissingProducerCases()
    {
        var rules = new (string Id, string Reason, string Name, string Path, int Port, string Kind)[]
        {
            ("R421", "SYNOLOGY_DSM_TARGET_AND_PROBE_UNAVAILABLE", "Synology DSM Admin Probe", "/webman/", 5000, "appliance"),
            ("R422", "VCENTER_SOAP_TARGET_AND_PROBE_UNAVAILABLE", "VMware vCenter SOAP Probe", "/sdk", 443, "appliance"),
            ("R423", "ESXI_HOSTD_TARGET_AND_PROBE_UNAVAILABLE", "VMware ESXi Hostd Probe", "/host", 443, "appliance"),
            ("R424", "PROXMOX_API_EXPOSURE_PROVENANCE_UNAVAILABLE", "Proxmox API Exposure Probe", "/api2/json", 8006, "appliance"),
            ("R425", "SOLR_ADMIN_TARGET_AND_PROBE_UNAVAILABLE", "Apache Solr Admin Probe", "/solr/admin", 8983, "appliance"),
            ("R426", "ELASTIC_CLUSTER_RESPONSE_AND_EXPOSURE_UNAVAILABLE", "Elasticsearch Cluster Info External", "/_cluster/health", 9200, "appliance"),
            ("R427", "KIBANA_CONSOLE_EXPOSURE_PROVENANCE_UNAVAILABLE", "Kibana Console Exposure", "/app/dev_tools", 5601, "appliance"),
            ("R428", "GRAFANA_ADMIN_PROBE_PROVENANCE_UNAVAILABLE", "Grafana Admin Login Probe", "/api/admin", 3000, "appliance"),
            ("R429", "PROMETHEUS_METRICS_EXPOSURE_PROVENANCE_UNAVAILABLE", "Prometheus Metrics Exposure External", "/api/v1/query", 9090, "appliance"),
            ("R430", "JUPYTER_TOKEN_PROBE_PROVENANCE_UNAVAILABLE", "Jupyter Notebook Token Probe", "/tree?token=synthetic-placeholder", 8888, "appliance")
        };
        foreach (var rule in rules)
        {
            foreach (var variation in new[]
            {
                "plausible", "descriptor-spoof", "normal-admin", "forged-asset-header",
                "tls-only", "missing-source", "malformed-path", "privacy-placeholder",
                "wrong-direction", "repeated-requests", "claimed-verified"
            })
                yield return new object[] { rule.Id, rule.Reason, rule.Name, rule.Path, rule.Port, rule.Kind, variation };
        }
    }

    private static TrafficRecord Observation(string path, int port, string kind)
    {
        var outbound = kind == "malware";
        var discovery = kind == "discovery";
        var http = kind == "malware" || kind == "appliance";
        return new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = outbound ? "10.94.2.10" : "8.8.8.8",
            Destination = outbound ? "8.8.8.8" : "10.94.2.10",
            IpVersion = 4,
            Protocol = discovery ? "UDP" : "TCP",
            IsTcp = !discovery,
            IsUdp = discovery,
            SourcePort = 50400,
            DestinationPort = port,
            ApplicationProtocol = http ? "HTTP" : (discovery ? "UDP" : "TCP"),
            HttpMethod = http ? "GET" : null,
            HttpUri = http ? path : null,
            HttpHost = http ? "gateway.example.test" : null,
            HttpRequestHeaders = http ? "User-Agent: ordinary-client" : null,
            Info = string.Empty,
            Length = 640,
            L4Len = 640
        };
    }

    private static Task<RuleEvaluationResult> Evaluate(string id, TrafficRecord record, int seconds = 0)
    {
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
        return id switch
        {
            "R421" => new R421_SynologyDSMAdminProbeRule().EvaluateAsync(context).AsTask(),
            "R422" => new R422_VMwareVCenterSOAPProbeRule().EvaluateAsync(context).AsTask(),
            "R423" => new R423_VMwareESXiHostdProbeRule().EvaluateAsync(context).AsTask(),
            "R424" => new R424_ProxmoxAPIExposureProbeRule().EvaluateAsync(context).AsTask(),
            "R425" => new R425_ApacheSolrAdminProbeRule().EvaluateAsync(context).AsTask(),
            "R426" => new R426_ElasticsearchClusterInfoExternalRule().EvaluateAsync(context).AsTask(),
            "R427" => new R427_KibanaConsoleExposureRule().EvaluateAsync(context).AsTask(),
            "R428" => new R428_GrafanaAdminLoginProbeRule().EvaluateAsync(context).AsTask(),
            "R429" => new R429_PrometheusMetricsExposureExternalRule().EvaluateAsync(context).AsTask(),
            "R430" => new R430_JupyterNotebookTokenProbeRule().EvaluateAsync(context).AsTask(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Packet_Clues_Do_Not_Establish_Named_Behavior(
        string id, string reason, string name, string path, int port, string kind, string variation)
    {
        var record = Observation(path, port, kind);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = name + " authenticated attack successful";
                break;
            case "normal-admin":
                record.ProcessName = "browser.exe";
                record.Info = "approved administrator inventory and VPN login";
                if (kind == "appliance") record.HttpUri = "/login";
                break;
            case "forged-asset-header":
                record.HttpRequestHeaders = "X-Device-Verified: true\r\nX-Audit-Outcome: exploited\r\nX-Appliance-Vendor: " + name;
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpRequestHeaders = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "malformed-path":
                record.HttpUri = "/%ZZ/../admin";
                break;
            case "privacy-placeholder":
                record.HttpUri = "/login?token=synthetic-placeholder-not-a-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-placeholder-not-a-credential";
                break;
            case "wrong-direction":
                record.Source = "10.94.2.10";
                record.Destination = "10.94.2.11";
                break;
            case "claimed-verified":
                record.Info = name + " HTTP 200, device verified and successful admin probe";
                break;
            case "repeated-requests":
                // Repeated packets do not supply independent asset, family,
                // jitter variance, response, or attack-outcome provenance.
                for (var i = 0; i < 8; i++)
                {
                    var interim = await Evaluate(id, Observation(path, port, kind), i * 30);
                    Assert.False(interim.Matched);
                    Assert.Empty(interim.Events);
                }
                break;
        }

        var result = await Evaluate(id, record, variation == "repeated-requests" ? 300 : 0);
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        if (variation is "plausible" or "repeated-requests")
            Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R421", 1, 82, 10, 30 };
        yield return new object[] { "R422", 1, 82, 10, 30 };
        yield return new object[] { "R423", 1, 82, 10, 30 };
        yield return new object[] { "R424", 1, 82, 10, 30 };
        yield return new object[] { "R425", 1, 82, 10, 30 };
        yield return new object[] { "R426", 1, 82, 10, 30 };
        yield return new object[] { "R427", 1, 82, 10, 30 };
        yield return new object[] { "R428", 1, 82, 10, 30 };
        yield return new object[] { "R429", 1, 82, 10, 30 };
        yield return new object[] { "R430", 1, 82, 10, 30 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Profile_And_Safety_Thresholds_Are_Preserved(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = id switch
        {
            "R421" => new R421_SynologyDSMAdminProbeRule().PrecisionProfile,
            "R422" => new R422_VMwareVCenterSOAPProbeRule().PrecisionProfile,
            "R423" => new R423_VMwareESXiHostdProbeRule().PrecisionProfile,
            "R424" => new R424_ProxmoxAPIExposureProbeRule().PrecisionProfile,
            "R425" => new R425_ApacheSolrAdminProbeRule().PrecisionProfile,
            "R426" => new R426_ElasticsearchClusterInfoExternalRule().PrecisionProfile,
            "R427" => new R427_KibanaConsoleExposureRule().PrecisionProfile,
            "R428" => new R428_GrafanaAdminLoginProbeRule().PrecisionProfile,
            "R429" => new R429_PrometheusMetricsExposureExternalRule().PrecisionProfile,
            "R430" => new R430_JupyterNotebookTokenProbeRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
