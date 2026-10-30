// SPDX-License-Identifier: MIT
// GA R411–R420 — SOURCE CANDIDATE — UNVERIFIED.
// 120 concrete xUnit invocations authored; ZERO executed. No validated
// family, appliance-identity, exploit, discovery-response or beacon-jitter
// producer exists for a sound positive assertion at this boundary.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch411420AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 5, 0, 0, DateTimeKind.Utc);

    public static IEnumerable<object[]> MissingProducerCases()
    {
        var rules = new (string Id, string Reason, string Name, string Path, int Port, string Kind)[]
        {
            ("R411", "LUMMA_FAMILY_SIGNATURE_UNAVAILABLE", "Lumma Stealer Gate Pattern", "/gate.php", 80, "malware"),
            ("R412", "BEACON_JITTER_INTERVAL_PROVENANCE_UNAVAILABLE", "Generic Beacon Jitter Low Variance", "/callback", 80, "malware"),
            ("R413", "CITRIX_APPLIANCE_SCAN_PROVENANCE_UNAVAILABLE", "Citrix Netscaler Gateway Scan Pattern", "/vpn/index.html", 443, "appliance"),
            ("R414", "IVANTI_EXPLOIT_PROVENANCE_UNAVAILABLE", "Ivanti Connect Secure Exploit Probe", "/api/v1/totp/user-backup-code", 443, "appliance"),
            ("R415", "F5_TMUI_TARGET_AND_PROBE_PROVENANCE_UNAVAILABLE", "F5 BIG-IP TMUI Probe", "/tmui/login.jsp", 443, "appliance"),
            ("R416", "SONICWALL_EXPLOIT_SIGNATURE_UNAVAILABLE", "SonicWall SSLVPN Exploit Probe", "/client.conf", 443, "appliance"),
            ("R417", "CISCO_ASA_WEBVPN_PROBE_PROVENANCE_UNAVAILABLE", "Cisco ASA WebVPN Probe", "/+CSCOE+/logon.html", 443, "appliance"),
            ("R418", "MIKROTIK_WINBOX_PROTOCOL_AND_ASSET_UNAVAILABLE", "MikroTik Winbox External Access", "", 8291, "winbox"),
            ("R419", "UBIQUITI_DISCOVERY_RESPONSE_AND_EXPOSURE_UNAVAILABLE", "Ubiquiti Discovery External Exposure", "", 10001, "discovery"),
            ("R420", "QNAP_ADMIN_TARGET_AND_PROBE_PROVENANCE_UNAVAILABLE", "QNAP QTS Admin Probe", "/cgi-bin/authLogin.cgi", 8080, "appliance")
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
            "R411" => new R411_LummaStealerGatePatternRule().EvaluateAsync(context).AsTask(),
            "R412" => new R412_GenericBeaconJitterLowVarianceRule().EvaluateAsync(context).AsTask(),
            "R413" => new R413_CitrixNetscalerGatewayScanPatternRule().EvaluateAsync(context).AsTask(),
            "R414" => new R414_IvantiConnectSecureExploitProbeRule().EvaluateAsync(context).AsTask(),
            "R415" => new R415_F5BIGIPTMUIProbeRule().EvaluateAsync(context).AsTask(),
            "R416" => new R416_SonicWallSSLVPNExploitProbeRule().EvaluateAsync(context).AsTask(),
            "R417" => new R417_CiscoASAWebVPNProbeRule().EvaluateAsync(context).AsTask(),
            "R418" => new R418_MikroTikWinboxExternalAccessRule().EvaluateAsync(context).AsTask(),
            "R419" => new R419_UbiquitiDiscoveryExternalExposureRule().EvaluateAsync(context).AsTask(),
            "R420" => new R420_QNAPQTSAdminProbeRule().EvaluateAsync(context).AsTask(),
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
                record.Info = id switch
                {
                    "R411" => "lumma family signature validated",
                    "R412" => "beacon intervals 60s 60s 60s 60s zero jitter",
                    "R418" => "MikroTik Winbox authenticated session successful",
                    "R419" => "Ubiquiti UDP discovery response externally exposed",
                    _ => name + " device identified and exploit probe confirmed"
                };
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
        yield return new object[] { "R411", 1, 86, 30, 45 };
        yield return new object[] { "R412", 4, 86, 60, 45 };
        yield return new object[] { "R413", 1, 82, 10, 30 };
        yield return new object[] { "R414", 1, 82, 10, 30 };
        yield return new object[] { "R415", 1, 82, 10, 30 };
        yield return new object[] { "R416", 1, 82, 10, 30 };
        yield return new object[] { "R417", 1, 82, 10, 30 };
        yield return new object[] { "R418", 1, 82, 10, 30 };
        yield return new object[] { "R419", 1, 82, 10, 30 };
        yield return new object[] { "R420", 1, 82, 10, 30 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Profile_And_Safety_Thresholds_Are_Preserved(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = id switch
        {
            "R411" => new R411_LummaStealerGatePatternRule().PrecisionProfile,
            "R412" => new R412_GenericBeaconJitterLowVarianceRule().PrecisionProfile,
            "R413" => new R413_CitrixNetscalerGatewayScanPatternRule().PrecisionProfile,
            "R414" => new R414_IvantiConnectSecureExploitProbeRule().PrecisionProfile,
            "R415" => new R415_F5BIGIPTMUIProbeRule().PrecisionProfile,
            "R416" => new R416_SonicWallSSLVPNExploitProbeRule().PrecisionProfile,
            "R417" => new R417_CiscoASAWebVPNProbeRule().PrecisionProfile,
            "R418" => new R418_MikroTikWinboxExternalAccessRule().PrecisionProfile,
            "R419" => new R419_UbiquitiDiscoveryExternalExposureRule().PrecisionProfile,
            "R420" => new R420_QNAPQTSAdminProbeRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
